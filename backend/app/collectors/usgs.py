"""Terremotos de las ultimas 24 h (USGS, GeoJSON publico, sin clave)."""
from datetime import datetime, timezone

import httpx

from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity

URL = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson"


class UsgsEarthquakes(Collector):
    name, layer, keep_history = "usgs", "earthquakes", True

    def __init__(self, interval: float = 300):
        self.interval = interval

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        resp = await client.get(URL)
        if resp.status_code != 200:
            raise CollectorError(f"USGS respondio HTTP {resp.status_code}")
        return parse(resp.json())


def parse(data: dict) -> list[Entity]:
    out = []
    for f in data.get("features", []):
        props, geom = f.get("properties") or {}, f.get("geometry") or {}
        coords = geom.get("coordinates") or []
        mag = props.get("mag")
        if len(coords) < 2 or not isinstance(mag, (int, float)) or not f.get("id"):
            continue
        out.append(Entity(
            id=f"usgs:{f['id']}", layer="earthquakes", lat=coords[1], lon=coords[0],
            label=f"M {mag:.1f} · {props.get('place') or 'sin ubicacion'}",
            observed_at=datetime.fromtimestamp(props.get("time", 0) / 1000, timezone.utc),
            attrs={"mag": mag, "depth_km": coords[2] if len(coords) > 2 else None,
                   "place": props.get("place"), "url": props.get("url")},
        ))
    return out
