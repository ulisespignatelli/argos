"""Correlacion, alertas y exportacion, probadas sin servidor."""
import re
from datetime import UTC, datetime

from app.domain.models import Entity, utcnow
from app.services import correlation, export
from app.services.alerts import AlertEngine
from app.storage.alerts import AlertRepository


def c2(i, ip, fam, asn="AS1", cc="NL"):
    return Entity(id=f"c:{i}", layer="c2", label=ip, observed_at=utcnow(), lat=1, lon=1,
                  attrs={"ip": ip, "malware": fam, "asn": asn, "country_code": cc, "country": cc,
                         "first_seen": "2026-11-17T10:00:00+00:00", "confidence": 100})


def test_pivot_ip_includes_neighbors_and_groups():
    ents = [c2(1, "1.1.1.1", "Sliver", "AS9"), c2(2, "1.1.1.1", "Havoc", "AS9"), c2(3, "2.2.2.2", "Sliver", "AS9"),
            c2(4, "3.3.3.3", "Remcos", "AS7")]
    p = correlation.pivot(ents, "ip", "1.1.1.1")
    assert p.total == 2
    groups = {g.label: [i.value for i in g.items] for g in p.groups}
    assert set(groups["Familias de malware"]) == {"Sliver", "Havoc"}
    assert groups["IPs vecinas en la misma red"] == ["2.2.2.2"]
    assert correlation.pivot(ents, "malware", "sliver").total == 2   # sin distinguir mayusculas


class Hub:
    def __init__(self):
        self.sent = []

    async def broadcast(self, m):
        self.sent.append(m)


async def test_alert_rules(tmp_path):
    repo, hub = AlertRepository(str(tmp_path / "a.db")), Hub()
    eng = AlertEngine(repo, hub, ("AR",))
    base = [c2(i, f"10.0.0.{i}", "Sliver") for i in range(6)]
    assert await eng.on_snapshot("c2", None, base) == []                    # linea de base, sin alertas
    grown = base + [c2(100 + i, f"10.1.0.{i}", "Sliver") for i in range(10)] + [c2(99, "9.9.9.9", "Pikabot", cc="AR")]
    fired = {a.rule for a in await eng.on_snapshot("c2", base, grown)}
    assert fired == {"familia_nueva", "pais_vigilado", "crecimiento"}
    assert await eng.on_snapshot("c2", base, grown) == []                   # deduplicadas
    assert len(hub.sent) == 3 and len(await repo.recent()) == 3

    kev = lambda i, rw: Entity(id=f"k:{i}", layer="kev", label="x", observed_at=utcnow(),  # noqa: E731
                               attrs={"cve": f"CVE-{i}", "ransomware": rw, "name": "n"})
    out = await eng.on_snapshot("kev", [kev(1, False)], [kev(1, False), kev(2, True)])
    assert [(a.rule, a.severity) for a in out] == [("kev_nueva", "alta")]


def test_exports():
    ents = [c2(1, "1.1.1.1", "Sliver"), c2(2, "1.1.1.1", "Sliver"), c2(3, "=cmd|' /C calc'!A0", "Havoc")]
    csv = export.to_csv(ents)
    assert "'=cmd" in csv   # neutraliza formulas de Excel
    assert export.to_blocklist(ents[:2]).strip().endswith("1.1.1.1")
    bundle = export.to_stix(ents[:2], datetime(2026, 11, 17, tzinfo=UTC))
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("indicator") == 1 and types.count("malware") == 1 and types.count("relationship") == 1
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[ipv4-addr:value = '1.1.1.1']"
    assert re.fullmatch(r"indicator--[0-9a-f-]{36}", ind["id"]) and ind["valid_from"].endswith("Z")
    assert export.to_stix(ents[:2])["objects"][1]["id"] == bundle["objects"][1]["id"]   # ids deterministas
