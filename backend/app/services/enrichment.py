"""Enriquecedores: pasos que agregan informacion a las entidades entre el recolector y la cache."""
import logging
from typing import Protocol

from app.domain.models import Entity
from app.geolocation.base import Geolocator
from app.storage.geo_cache import GeoCache

log = logging.getLogger(__name__)


class Enricher(Protocol):
    async def enrich(self, entities: list[Entity]) -> list[Entity]: ...


class GeoIpEnricher:
    """Ubica en el mapa las entidades que traen una IP y todavia no tienen coordenadas."""

    def __init__(self, geolocator: Geolocator, cache: GeoCache):
        self.geolocator, self.cache = geolocator, cache

    async def enrich(self, entities: list[Entity]) -> list[Entity]:
        ips = {e.attrs["ip"] for e in entities if e.lat is None and e.attrs.get("ip")}
        if not ips:
            return entities
        known = await self.cache.get_many(ips)
        missing = sorted(ips - known.keys())
        if missing:
            try:
                found = await self.geolocator.locate(missing)
            except Exception as exc:   # sin geolocalizacion, los datos igual se muestran en el panel
                log.warning("geolocalizacion (%s) fallo: %s", self.geolocator.name, exc)
                found = {}
            if found:
                await self.cache.put_many(found)
                known.update(found)
        out = []
        for e in entities:
            g = known.get(e.attrs.get("ip", "")) if e.lat is None else None
            if g:
                e = e.model_copy(update={"lat": g.lat, "lon": g.lon, "attrs": {
                    **e.attrs, "country": g.country, "country_code": g.country_code, "city": g.city,
                    "asn": g.asn, "org": g.org}})
            out.append(e)
        return out
