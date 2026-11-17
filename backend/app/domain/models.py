"""Modelo comun. Todas las fuentes se normalizan a Entity; el resto del sistema solo conoce esto."""
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Entity(BaseModel):
    id: str                       # unico global: "<fuente>:<id de la fuente>"
    layer: str                    # "c2" (en el mapa), "kev" (solo panel), ...
    lat: float | None = Field(default=None, ge=-90, le=90)    # None: sin ubicacion (todavia)
    lon: float | None = Field(default=None, ge=-180, le=180)
    label: str
    observed_at: datetime
    attrs: dict[str, Any] = {}


class GeoInfo(BaseModel):
    ip: str
    lat: float
    lon: float
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    asn: str | None = None
    org: str | None = None


class LayerStatus(BaseModel):
    layer: str
    source: str
    updated_at: datetime | None = None
    count: int = 0
    error: str | None = None


class Snapshot(BaseModel):
    status: LayerStatus
    entities: list[Entity]
