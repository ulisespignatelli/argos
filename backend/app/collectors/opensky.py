"""Aviones en una zona (OpenSky Network, senales ADS-B publicas). Anonimo tiene limite diario."""
from datetime import datetime, timezone

import httpx

from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity

URL = "https://opensky-network.org/api/states/all"


class OpenSkyAircraft(Collector):
    name, layer = "opensky", "aircraft"

    def __init__(self, bbox: tuple[float, float, float, float], interval: float = 60):
        self.bbox, self.interval = bbox, interval

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        lamin, lomin, lamax, lomax = self.bbox
        resp = await client.get(URL, params={"lamin": lamin, "lomin": lomin, "lamax": lamax, "lomax": lomax})
        if resp.status_code == 429:
            raise CollectorError("limite de consultas de OpenSky alcanzado")
        if resp.status_code != 200:
            raise CollectorError(f"OpenSky respondio HTTP {resp.status_code}")
        return parse(resp.json())


def parse(data: dict) -> list[Entity]:
    # Vector de estado: 0 icao24, 1 callsign, 2 pais, 4 ultimo contacto, 5 lon, 6 lat,
    # 7 altitud baro (m), 8 en tierra, 9 velocidad (m/s), 10 rumbo, 14 squawk
    out = []
    for s in data.get("states") or []:
        if not isinstance(s, list) or len(s) < 11 or s[5] is None or s[6] is None:
            continue
        callsign = (s[1] or "").strip()
        out.append(Entity(
            id=f"opensky:{s[0]}", layer="aircraft", lat=s[6], lon=s[5],
            label=callsign or s[0].upper(),
            observed_at=datetime.fromtimestamp(s[4] or 0, timezone.utc),
            attrs={"icao24": s[0], "country": s[2], "altitude_m": s[7], "on_ground": bool(s[8]),
                   "speed_ms": s[9], "track_deg": s[10], "squawk": s[14] if len(s) > 14 else None},
        ))
    return out
