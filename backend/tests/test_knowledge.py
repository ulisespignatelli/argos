"""Base de conocimiento real (ATT&CK 20.x + MISP), enriquecimiento y ataques de ransomware."""
import httpx

from app.collectors.ransomware_live import RansomwareLiveVictims, parse
from app.domain.models import Entity, utcnow
from app.knowledge.kb import KnowledgeBase
from app.services.attack_enrichment import AttackEnricher
from app.services.intel import matrix

KB = KnowledgeBase()


def test_kb_matches_families_and_groups():
    assert KB.match_software("Cobalt Strike") == "S0154"
    assert KB.match_software("lumma-stealer") == "S1213"          # normaliza guiones y espacios
    assert KB.match_software("lockbit3") == KB.match_software("LockBit 3.0")   # alias de sitios de filtracion
    assert KB.match_group("Akira") == "G1024"
    assert KB.groups["G0032"]["country"] == "KP"                   # Lazarus segun MISP
    assert KB.country("ar")["name"] == "Argentina" and KB.country("KP")["name"] == "Corea del Norte"


async def test_enricher_links_c2_and_incidents():
    c2 = Entity(id="c:1", layer="c2", label="x", observed_at=utcnow(), attrs={"malware": "Cobalt Strike"})
    inc = Entity(id="i:1", layer="incidents", label="v", observed_at=utcnow(), attrs={"group": "akira"})
    other = Entity(id="o:1", layer="c2", label="x", observed_at=utcnow(), attrs={"malware": "FamiliaInventada"})
    a, b, c = await AttackEnricher(KB).enrich([c2, inc, other])
    assert a.attrs["software_id"] == "S0154" and len(a.attrs["actors"]) > 3 and "origin" not in a.attrs
    assert b.attrs["actors"][0] == "G1024"
    assert "actors" not in c.attrs


def test_ransomware_live_accepts_both_formats():
    items = [
        {"victim": "Empresa Uno", "group": "akira", "discovered": "2026-11-18T10:00:00+00:00", "country": "AR",
         "sector": "Salud", "url": "https://www.ransomware.live/id/abc"},
        {"post_title": "Empresa Dos", "group_name": "qilin", "discovered": "2026-11-18 09:00:00.123", "country": "BR",
         "activity": "Manufactura", "url": "javascript:alert(1)"},
        {"victim": "Sin grupo"},
    ]
    out = parse(items, KB.countries)
    assert [e.label for e in out] == ["Empresa Uno", "Empresa Dos"]
    assert out[0].attrs["country"] == "Argentina" and -40 < out[0].lat < -29
    assert out[0].attrs["source_url"].startswith("https://") and out[1].attrs["source_url"] is None
    assert out[1].attrs["sector"] == "Manufactura" and out[0].attrs["claim"] is True


async def test_ransomware_live_falls_back_to_v1():
    seen = []

    def handler(r):
        seen.append(r.url.path)
        if r.url.path.startswith("/v2/"):
            return httpx.Response(404)
        return httpx.Response(200, json=[{"victim": "Y", "group": "qilin", "discovered": "2026-11-18T10:00:00Z",
                                          "country": "AR"}])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        items = await RansomwareLiveVictims(KB.countries).fetch(c)
    assert seen == ["/v2/recentvictims", "/recentvictims"] and items[0].attrs["country"] == "Argentina"


async def test_ransomlook_is_last_fallback_and_has_no_location():
    def handler(r):
        if r.url.host == "www.ransomlook.io":
            return httpx.Response(200, json=[{"post_title": "Victima Z", "group_name": "inc ransom",
                                              "discovered": "2026-11-19 23:05:24", "description": "..."}])
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        items = await RansomwareLiveVictims(KB.countries).fetch(c)
    assert items[0].label == "Victima Z" and items[0].attrs["source"] == "RansomLook"
    assert items[0].lat is None and items[0].observed_at.tzinfo is not None


async def test_ransomware_live_reports_all_failures():
    import pytest

    from app.collectors.base import CollectorError
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as c:
        with pytest.raises(CollectorError, match="ransomware.live HTTP 404.*RansomLook HTTP 404"):
            await RansomwareLiveVictims(KB.countries).fetch(c)


async def test_ransomware_live_fetch():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[
            {"victim": "X", "group": "play", "discovered": "2026-11-18T10:00:00Z", "country": "CL"}]))) as c:
        items = await RansomwareLiveVictims(KB.countries).fetch(c)
    assert items[0].attrs["country_code"] == "CL"


async def test_matrix_active_weights_live_software():
    c2 = [Entity(id=f"c:{i}", layer="c2", label="x", observed_at=utcnow(), attrs={"malware": "Cobalt Strike"})
          for i in range(5)]
    m = matrix(KB, await AttackEnricher(KB).enrich(c2), "active")
    cells = {t["id"]: t["score"] for tac in m["tactics"] for t in tac["techniques"]}
    assert m["max"] == 5 and cells["T1059"] == 5     # Cobalt Strike ejecuta comandos (T1059)
    assert all(not t["id"].count(".") for tac in m["tactics"] for t in tac["techniques"])   # solo tecnicas padre


def test_shared_tools_do_not_inflate_ranking():
    """50 C2 de Cobalt Strike (lo usan decenas de grupos) pesan menos que 3 ataques atribuidos directamente."""
    from app.services.intel import active_actors
    cs = [Entity(id=f"c:{i}", layer="c2", label="x", observed_at=utcnow(), attrs={"malware": "Cobalt Strike"})
          for i in range(50)]
    inc = [Entity(id=f"i:{i}", layer="incidents", label="v", observed_at=utcnow(), attrs={"group": "akira"})
           for i in range(3)]
    import asyncio
    enriched = asyncio.run(AttackEnricher(KB).enrich(cs + inc))
    rows = active_actors(KB, enriched)
    assert rows[0]["id"] == "G1024" and rows[0]["direct"] == 3
    apt29 = next(r for r in rows if r["id"] == "G0016")   # usa Cobalt Strike
    assert apt29["via_software"] == 50 and apt29["relevance"] < 3
