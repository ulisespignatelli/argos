"""Datos simulados para mostrar el sistema sin red. Deterministas: misma semilla, mismo mundo."""
import math
import random
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.collectors.base import Collector
from app.domain.models import Entity

AIRPORTS = [(-34.82, -58.54), (-23.43, -46.47), (-33.39, -70.79), (-31.31, -64.21), (-32.83, -68.79),
            (-41.15, -71.16), (-12.02, -77.11), (-22.81, -43.25), (-54.84, -68.30), (-24.39, -65.10),
            (-38.73, -62.17), (-27.45, -59.05), (-15.87, -47.92), (-30.00, -51.17), (-34.84, -56.03)]
PREFIXES = ["ARG", "LAN", "GLO", "AZU", "JAT", "FBZ"]
ZONES = [(-30.5, -71.5, "Coquimbo, Chile"), (-31.5, -68.5, "San Juan, Argentina"), (-15, -75, "costa de Peru"),
         (-23.5, -67, "Jujuy, Argentina"), (-36, -73, "Biobio, Chile"), (-5, -80, "norte de Peru")]


def _interp(a, b, f):
    return a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f


class DemoAircraft(Collector):
    name, layer = "demo", "aircraft"

    def __init__(self, interval: float = 3, count: int = 120, seed: int = 7):
        self.interval = interval
        r = random.Random(seed)
        self.flights = []
        while len(self.flights) < count:
            o, d = r.sample(AIRPORTS, 2)
            km = math.dist(o, d) * 111
            if km < 300:
                continue
            self.flights.append({"id": f"{r.randrange(0xa00000, 0xffffff):06x}",
                                 "cs": f"{r.choice(PREFIXES)}{r.randint(100, 1999)}",
                                 "o": o, "d": d, "dur": km / 830 * 3600, "off": r.random()})

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        now = time.time()
        out = []
        for f in self.flights:
            p = (now / f["dur"] + f["off"]) % 1
            lat, lon = _interp(f["o"], f["d"], p)
            track = (math.degrees(math.atan2(f["d"][1] - f["o"][1], f["d"][0] - f["o"][0])) + 360) % 360
            edge = min(p, 1 - p)
            out.append(Entity(
                id=f"demo:{f['id']}", layer="aircraft", lat=lat, lon=lon, label=f["cs"],
                observed_at=datetime.fromtimestamp(now, timezone.utc),
                attrs={"icao24": f["id"], "country": "Simulado", "altitude_m": round(min(1, edge / .08) * 10700),
                       "on_ground": False, "speed_ms": 230.0, "track_deg": round(track, 1), "squawk": None},
            ))
        return out


class DemoEarthquakes(Collector):
    name, layer, keep_history = "demo", "earthquakes", True

    def __init__(self, interval: float = 30, count: int = 25, seed: int = 11):
        self.interval = interval
        r = random.Random(seed)
        self.items = []
        for i in range(count):
            lat, lon, place = r.choice(ZONES)
            self.items.append((i, lat + r.uniform(-2, 2), lon + r.uniform(-2, 2), place,
                               round(2.5 + r.random() ** 2 * 4, 1), r.uniform(0, 86400), round(r.uniform(5, 180))))

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        now = datetime.now(timezone.utc)
        return [Entity(id=f"demo:q{i}", layer="earthquakes", lat=lat, lon=lon, label=f"M {mag:.1f} · {place}",
                       observed_at=now - timedelta(seconds=age),
                       attrs={"mag": mag, "depth_km": depth, "place": place, "url": None})
                for i, lat, lon, place, mag, age, depth in self.items]
