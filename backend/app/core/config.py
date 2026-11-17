"""Configuracion leida de variables de entorno. Las claves nunca van en el codigo."""
import os
from dataclasses import dataclass, field


def _floats(raw: str) -> tuple[float, ...]:
    return tuple(float(x) for x in raw.split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    # "live" consulta las fuentes reales; "demo" usa datos simulados (sin red).
    mode: str = field(default_factory=lambda: os.getenv("ARGOS_MODE", "live"))
    db_path: str = field(default_factory=lambda: os.getenv("ARGOS_DB", "argos.db"))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: tuple(
        o for o in os.getenv("ARGOS_CORS", "http://localhost:5173").split(",") if o))
    # Zona de aviones: lat_min, lon_min, lat_max, lon_max (por defecto, Sudamerica sur).
    opensky_bbox: tuple[float, ...] = field(default_factory=lambda: _floats(
        os.getenv("ARGOS_OPENSKY_BBOX", "-56,-80,-15,-30")))
    opensky_interval: float = field(default_factory=lambda: float(os.getenv("ARGOS_OPENSKY_INTERVAL", "60")))
    usgs_interval: float = field(default_factory=lambda: float(os.getenv("ARGOS_USGS_INTERVAL", "300")))
    history_days: int = field(default_factory=lambda: int(os.getenv("ARGOS_HISTORY_DAYS", "7")))

    def __post_init__(self):
        if self.mode not in ("live", "demo"):
            raise ValueError("ARGOS_MODE debe ser 'live' o 'demo'")
        if len(self.opensky_bbox) != 4:
            raise ValueError("ARGOS_OPENSKY_BBOX necesita 4 valores")
