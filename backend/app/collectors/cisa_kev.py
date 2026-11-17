"""Vulnerabilidades que CISA confirma como explotadas en ataques reales (catalogo KEV, publico)."""
from datetime import datetime, timezone

import httpx

from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKev(Collector):
    name, layer, keep_history = "cisa", "kev", True

    def __init__(self, interval: float = 21600, latest: int = 60):
        self.interval, self.latest = interval, latest

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        resp = await client.get(URL)
        if resp.status_code != 200:
            raise CollectorError(f"CISA respondio HTTP {resp.status_code}")
        return parse(resp.json(), self.latest)


def parse(data: dict, latest: int = 60) -> list[Entity]:
    out = []
    for v in data.get("vulnerabilities", []):
        cve, added = v.get("cveID"), v.get("dateAdded")
        if not cve or not added:
            continue
        try:
            when = datetime.strptime(added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        out.append(Entity(
            id=f"kev:{cve}", layer="kev", label=f"{cve} · {v.get('vendorProject', '')} {v.get('product', '')}".strip(),
            observed_at=when,
            attrs={"cve": cve, "vendor": v.get("vendorProject"), "product": v.get("product"),
                   "name": v.get("vulnerabilityName"), "description": v.get("shortDescription"),
                   "action": v.get("requiredAction"), "due_date": v.get("dueDate"),
                   "ransomware": v.get("knownRansomwareCampaignUse") == "Known", "cwes": v.get("cwes") or [],
                   "source_url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
        ))
    out.sort(key=lambda e: e.observed_at, reverse=True)
    return out[:latest]
