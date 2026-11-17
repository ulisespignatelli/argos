"""Modelo comun. Todas las fuentes se normalizan a Entity; el resto del sistema solo conoce esto."""
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


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


class Alert(BaseModel):
    id: str
    at: datetime
    severity: str                 # "alta", "media" o "baja"
    rule: str
    title: str
    detail: str
    pivot_kind: str | None = None  # para abrir la investigacion desde la alerta
    pivot_value: str | None = None


class PivotItem(BaseModel):
    value: str
    count: int


class PivotGroup(BaseModel):
    kind: str
    label: str
    items: list[PivotItem]


class Pivot(BaseModel):
    kind: str
    value: str
    total: int
    groups: list[PivotGroup]
    entities: list[Entity]
