"""URLs que distribuyen malware, de URLhaus (abuse.ch). Usa la misma clave que ThreatFox."""
import ipaddress
from datetime import UTC, datetime

import httpx

from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity

URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"


class UrlhausUrls(Collector):
    name, layer, keep_history = "urlhaus", "urls", True

    def __init__(self, key: str, interval: float = 900):
        self.key, self.interval = key, interval

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        if not self.key:
            raise CollectorError("falta ARGOS_ABUSECH_KEY (clave gratuita en auth.abuse.ch)")
        resp = await client.get(URL, headers={"Auth-Key": self.key})
        if resp.status_code in (401, 403):
            raise CollectorError("URLhaus rechazo la clave (revisar ARGOS_ABUSECH_KEY)")
        if resp.status_code != 200:
            raise CollectorError(f"URLhaus respondio HTTP {resp.status_code}")
        data = resp.json()
        status = data.get("query_status")
        if status == "no_results":
            return []
        if status != "ok":
            raise CollectorError(f"URLhaus: {status}")
        return parse(data.get("urls") or [])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse(items: list[dict]) -> list[Entity]:
    out = []
    for it in items:
        url, host, uid = it.get("url"), it.get("host"), it.get("id")
        if not url or not host or uid is None:
            continue
        try:
            added = datetime.strptime(it.get("date_added", ""), "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=UTC)
        except ValueError:
            added = datetime.now(UTC)
        attrs = {"url": url, "host": host, "status": it.get("url_status"), "threat": it.get("threat"),
                 "tags": it.get("tags") or [], "reporter": it.get("reporter"),
                 "source_url": it.get("urlhaus_reference")}
        if is_ip(host):
            attrs["ip"] = host   # solo las URLs alojadas directamente en una IP se ubican en el mapa
        out.append(Entity(id=f"urlhaus:{uid}", layer="urls", label=host, observed_at=added, attrs=attrs))
    return out
