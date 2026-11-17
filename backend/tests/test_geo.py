import json

import httpx

from app.domain.models import Entity, GeoInfo, utcnow
from app.geolocation.base import Geolocator
from app.geolocation.ipapi import IpApiGeolocator
from app.services.enrichment import GeoIpEnricher
from app.storage.geo_cache import GeoCache


class CountingGeo(Geolocator):
    name = "fake"

    def __init__(self):
        self.calls = []

    async def locate(self, ips):
        self.calls.append(list(ips))
        return {ip: GeoInfo(ip=ip, lat=10, lon=20, country="X", country_code="XX") for ip in ips if ip != "8.8.4.4"}


def ent(i, ip):
    return Entity(id=f"t:{i}", layer="c2", label=ip, observed_at=utcnow(), attrs={"ip": ip})


async def test_enricher_uses_cache_and_keeps_unlocated(tmp_path):
    geo, cache = CountingGeo(), GeoCache(str(tmp_path / "g.db"))
    enricher = GeoIpEnricher(geo, cache)
    out = await enricher.enrich([ent(1, "1.1.1.1"), ent(2, "8.8.4.4"), ent(3, "1.1.1.1")])
    assert [(e.lat, e.lon) for e in out] == [(10, 20), (None, None), (10, 20)]
    assert out[0].attrs["country_code"] == "XX"
    await enricher.enrich([ent(4, "1.1.1.1"), ent(5, "8.8.4.4")])
    assert geo.calls == [["1.1.1.1", "8.8.4.4"], ["8.8.4.4"]]   # 1.1.1.1 ya estaba en cache


async def test_ipapi_batches_and_skips_private():
    bodies = []

    def handler(req):
        ips = json.loads(req.content)
        bodies.append(ips)
        return httpx.Response(200, json=[{"status": "success", "query": ip, "lat": 1.5, "lon": 2.5, "country": "Y",
                                          "countryCode": "YY", "city": "Z", "as": "AS123 Ejemplo", "org": "Org"}
                                         for ip in ips])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        public = [f"45.9.{i // 250}.{i % 250 + 1}" for i in range(150)]
        res = await IpApiGeolocator(c).locate(public + ["10.0.0.1", "192.0.2.5", "no-ip"])
    assert [len(b) for b in bodies] == [100, 50]
    assert len(res) == 150 and res[public[0]].asn == "AS123"
