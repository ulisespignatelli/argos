"""Victimas de ransomware reivindicadas por los propios grupos en sus sitios de filtracion.

Fuentes, en orden: ransomware.live (v2 y v1) y, si no responde, RansomLook. ransomware.live trae el pais de la
victima; RansomLook no, asi que sus registros se listan pero no se ubican en el mapa (nunca se adivina un pais).

Importante: una reivindicacion no es una confirmacion. El grupo publica la victima para presionar el pago;
a veces exagera o miente. Por eso estas entradas se muestran como "reivindicadas", nunca como confirmadas.
"""
import hashlib
import random
from datetime import UTC, datetime

import httpx

from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity

# La v2 es la documentada; la v1 y RansomLook quedan como respaldo (ransomware.live no responde desde todas las redes).
URLS = (("ransomware.live", "https://api.ransomware.live/v2/recentvictims"),
        ("ransomware.live", "https://api.ransomware.live/recentvictims"),
        ("RansomLook", "https://www.ransomlook.io/api/recent"))
HEADERS = {"Accept": "application/json"}


class RansomwareLiveVictims(Collector):
    name, layer, keep_history = "ransomware.live · RansomLook", "incidents", True

    def __init__(self, countries: dict, interval: float = 1800):
        self.countries, self.interval = countries, interval

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        tried = []
        for source, url in URLS:
            try:
                resp = await client.get(url, headers=HEADERS, follow_redirects=True)
            except httpx.HTTPError as exc:
                tried.append(f"{source}: {exc.__class__.__name__}")
                continue
            if resp.status_code == 200:
                data = resp.json()
                items = data if isinstance(data, list) else data.get("victims") or data.get("data") or []
                return parse(items, self.countries, source)
            tried.append(f"{source} HTTP {resp.status_code}")
        raise CollectorError("ninguna fuente respondió (" + ", ".join(tried) + ")")


def _ts(v) -> datetime | None:
    if not v or not isinstance(v, str):
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T", 1))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _clean(v) -> str | None:
    """La API usa "Not Found" cuando no conoce el sector: eso es un dato faltante, no un sector."""
    v = str(v or "").strip()
    return None if not v or v.lower() in ("not found", "unknown", "n/a") else v


def place(cc: str, key: str, countries: dict) -> tuple[float | None, float | None]:
    """Ubica la victima en su pais, con un leve desplazamiento estable para que no se tapen entre si."""
    c = countries.get(cc)
    if not c:
        return None, None
    r = random.Random(key)  # noqa: S311 (dispersion visual, no criptografia)
    return round(max(-89.0, min(89.0, c["lat"] + r.uniform(-1.2, 1.2))), 4), round(c["lon"] + r.uniform(-1.5, 1.5), 4)


def parse(items: list[dict], countries: dict, source: str = "ransomware.live") -> list[Entity]:
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        # La API cambio nombres de campos entre versiones: se aceptan ambos.
        victim = (it.get("victim") or it.get("post_title") or "").strip()
        group = (it.get("group") or it.get("group_name") or "").strip()
        if not victim or not group:
            continue
        discovered = _ts(it.get("discovered")) or _ts(it.get("published")) or datetime.now(UTC)
        attacked = _ts(it.get("attackdate"))
        cc = str(it.get("country") or "").upper()[:2]
        key = hashlib.sha256(f"{group}|{victim}|{discovered.date()}".encode()).hexdigest()[:16]
        lat, lon = place(cc, key, countries)
        url = it.get("url") if str(it.get("url", "")).startswith("https://www.ransomware.live/") else None
        out.append(Entity(
            id=f"ransomwarelive:{key}", layer="incidents", lat=lat, lon=lon, label=victim, observed_at=discovered,
            attrs={"kind": "ransomware", "victim": victim, "group": group, "claim": True, "source": source,
                   "sector": _clean(it.get("activity") or it.get("sector")), "country_code": cc or None,
                   "country": countries.get(cc, {}).get("name"), "website": it.get("website") or it.get("domain"),
                   "attack_date": attacked.isoformat() if attacked else None, "source_url": url},
        ))
    return out
