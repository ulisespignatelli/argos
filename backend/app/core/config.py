"""Configuracion desde variables de entorno o backend/.env. Las claves nunca van en el codigo."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def load_dotenv(path: Path = Path(__file__).resolve().parents[2] / ".env") -> None:
    """Lee KEY=VALOR de backend/.env sin pisar variables ya definidas en el entorno."""
    if not path.is_file():
        return
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        # Si una clave aparece dos veces, gana la última que tenga valor.
        if value or key.strip() not in values:
            values[key.strip()] = value
    for key, value in values.items():
        os.environ.setdefault(key, value)


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


@dataclass(frozen=True)
class Settings:
    # "live" consulta las fuentes reales; "demo" usa datos simulados (sin red).
    mode: str = field(default_factory=lambda: _env("ARGOS_MODE", "live"))
    # Una base por modo: las alertas y el historial simulados nunca se mezclan con los reales.
    db_path: str = field(default_factory=lambda: _env("ARGOS_DB", f"argos-{_env('ARGOS_MODE', 'live')}.db"))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: tuple(
        o for o in _env("ARGOS_CORS", "http://localhost:5173").split(",") if o))
    # abuse.ch (ThreatFox y URLhaus): una sola clave gratuita, en https://auth.abuse.ch
    abusech_key: str = field(default_factory=lambda: _env("ARGOS_ABUSECH_KEY", "") or _env("ARGOS_THREATFOX_KEY", ""))
    threatfox_days: int = field(default_factory=lambda: int(_env("ARGOS_THREATFOX_DAYS", "3")))
    threatfox_interval: float = field(default_factory=lambda: float(_env("ARGOS_THREATFOX_INTERVAL", "900")))
    urlhaus_interval: float = field(default_factory=lambda: float(_env("ARGOS_URLHAUS_INTERVAL", "900")))
    ransomware_interval: float = field(default_factory=lambda: float(_env("ARGOS_RANSOMWARE_INTERVAL", "1800")))
    kev_interval: float = field(default_factory=lambda: float(_env("ARGOS_KEV_INTERVAL", "21600")))
    # Noticias y avisos (RSS): cada cuanto se leen (0 = desactivado), cuantos dias se miran y feeds propios.
    news_interval: float = field(default_factory=lambda: float(_env("ARGOS_NEWS_INTERVAL", "1800")))
    news_days: int = field(default_factory=lambda: int(_env("ARGOS_NEWS_DAYS", "14")))
    news_feeds: str = field(default_factory=lambda: _env("ARGOS_NEWS_FEEDS", ""))
    # Geolocalizacion de IPs: "ip-api" (gratis, sin clave, uso no comercial) o "none".
    geoip: str = field(default_factory=lambda: _env("ARGOS_GEOIP", "ip-api"))
    # Paises a vigilar (ISO-3166 alfa-2): alerta cuando aparece un C2 nuevo alli.
    watch_countries: tuple[str, ...] = field(default_factory=lambda: tuple(
        c.strip().upper() for c in _env("ARGOS_WATCH_COUNTRIES", "AR").split(",") if c.strip()))
    rate_limit_per_minute: int = field(default_factory=lambda: int(_env("ARGOS_RATE_LIMIT", "240")))
    history_days: int = field(default_factory=lambda: int(_env("ARGOS_HISTORY_DAYS", "365")))

    def __post_init__(self):
        if self.mode not in ("live", "demo"):
            raise ValueError("ARGOS_MODE debe ser 'live' o 'demo'")
        if self.geoip not in ("ip-api", "none"):
            raise ValueError("ARGOS_GEOIP debe ser 'ip-api' o 'none'")
        if not 1 <= self.threatfox_days <= 7:
            raise ValueError("ARGOS_THREATFOX_DAYS debe estar entre 1 y 7")
