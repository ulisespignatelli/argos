"""Modelo comun. Todas las fuentes se normalizan a Entity; el resto del sistema solo conoce esto."""
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Entity(BaseModel):
    id: str                       # unico global: "<fuente>:<id de la fuente>"
    layer: str                    # capa del mapa: "aircraft", "earthquakes", ...
    lat: float = Field(ge=-90, le=90)
    lon: float = Field(ge=-180, le=180)
    label: str
    observed_at: datetime
    attrs: dict[str, Any] = {}


class LayerStatus(BaseModel):
    layer: str
    source: str
    updated_at: datetime | None = None
    count: int = 0
    error: str | None = None


class Snapshot(BaseModel):
    status: LayerStatus
    entities: list[Entity]
