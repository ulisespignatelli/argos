"""Servidores de comando y control (C2) activos, de ThreatFox (abuse.ch). Requiere clave gratuita."""
from datetime import datetime, timezone

import httpx

from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity

URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxC2(Collector):
    name, layer, keep_history = "threatfox", "c2", True

    def __init__(self, key: str, days: int = 3, interval: float = 900):
        self.key, self.days, self.interval = key, days, interval

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        if not self.key:
            raise CollectorError("falta ARGOS_THREATFOX_KEY (clave gratuita en auth.abuse.ch)")
        resp = await client.post(URL, json={"query": "get_iocs", "days": self.days}, headers={"Auth-Key": self.key})
        if resp.status_code in (401, 403):
            raise CollectorError("ThreatFox rechazo la clave (revisar ARGOS_THREATFOX_KEY)")
        if resp.status_code != 200:
            raise CollectorError(f"ThreatFox respondio HTTP {resp.status_code}")
        data = resp.json()
        status = data.get("query_status")
        if status == "no_result":
            return []
        if status != "ok":
            raise CollectorError(f"ThreatFox: {status}")
        return parse(data.get("data") or [])


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse(items: list[dict]) -> list[Entity]:
    """Se queda con los IOC del tipo ip:port (infraestructura ubicable en el mapa)."""
    out = []
    for it in items:
        if it.get("ioc_type") != "ip:port" or not it.get("ioc") or it.get("id") is None:
            continue
        ip, _, port = str(it["ioc"]).rpartition(":")
        if not ip:
            continue
        first = _ts(it.get("first_seen"))
        malware = it.get("malware_printable") or it.get("malware") or "desconocido"
        out.append(Entity(
            id=f"threatfox:{it['id']}", layer="c2", label=f"{malware} · {ip}",
            observed_at=_ts(it.get("last_seen")) or first or datetime.now(timezone.utc),
            attrs={"ip": ip, "port": int(port) if port.isdigit() else None, "malware": malware,
                   "malware_id": it.get("malware"), "threat_type": it.get("threat_type_desc") or it.get("threat_type"),
                   "confidence": it.get("confidence_level"), "first_seen": first.isoformat() if first else None,
                   "reporter": it.get("reporter"), "tags": it.get("tags") or [], "reference": it.get("reference"),
                   "source_url": f"https://threatfox.abuse.ch/ioc/{it['id']}/"},
        ))
    return out
