"""Geolocalizacion con ip-api.com (lote de hasta 100 IPs, gratis, sin clave, uso no comercial).

Solo se envian IPs publicas que ya son indicadores publicos de amenazas: nunca datos de usuarios.
"""
import ipaddress
import logging

import httpx

from app.domain.models import GeoInfo
from app.geolocation.base import Geolocator

log = logging.getLogger(__name__)
URL = "http://ip-api.com/batch"   # el plan gratuito no ofrece HTTPS
FIELDS = "status,message,country,countryCode,city,lat,lon,isp,org,as,query"
BATCH, MAX_BATCHES = 100, 10      # limite gratuito: 15 lotes por minuto


class IpApiGeolocator(Geolocator):
    name = "ip-api"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def locate(self, ips: list[str]) -> dict[str, GeoInfo]:
        public = [ip for ip in ips if _is_public(ip)]
        found: dict[str, GeoInfo] = {}
        for start in range(0, min(len(public), BATCH * MAX_BATCHES), BATCH):
            chunk = public[start:start + BATCH]
            resp = await self.client.post(URL, params={"fields": FIELDS}, json=chunk)
            if resp.status_code == 429:
                log.warning("ip-api: limite alcanzado; el resto se ubica en el proximo ciclo")
                break
            resp.raise_for_status()
            for row in resp.json():
                if row.get("status") == "success" and row.get("query"):
                    found[row["query"]] = GeoInfo(
                        ip=row["query"], lat=row["lat"], lon=row["lon"], country=row.get("country"),
                        country_code=row.get("countryCode"), city=row.get("city"),
                        asn=(row.get("as") or "").split(" ")[0] or None, org=row.get("org") or row.get("isp"))
            if resp.headers.get("X-Rl") == "0":
                break
        return found


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False
