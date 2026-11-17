"""Configuracion desde variables de entorno o backend/.env. Las claves nunca van en el codigo."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def load_dotenv(path: Path = Path(__file__).resolve().parents[2] / ".env") -> None:
    """Lee KEY=VALOR de backend/.env sin pisar variables ya definidas en el entorno."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


@dataclass(frozen=True)
class Settings:
    # "live" consulta las fuentes reales; "demo" usa datos simulados (sin red).
    mode: str = field(default_factory=lambda: _env("ARGOS_MODE", "live"))
    db_path: str = field(default_factory=lambda: _env("ARGOS_DB", "argos.db"))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: tuple(
        o for o in _env("ARGOS_CORS", "http://localhost:5173").split(",") if o))
    # ThreatFox (abuse.ch): clave gratuita en https://auth.abuse.ch
    threatfox_key: str = field(default_factory=lambda: _env("ARGOS_THREATFOX_KEY", ""))
    threatfox_days: int = field(default_factory=lambda: int(_env("ARGOS_THREATFOX_DAYS", "3")))
    threatfox_interval: float = field(default_factory=lambda: float(_env("ARGOS_THREATFOX_INTERVAL", "900")))
    kev_interval: float = field(default_factory=lambda: float(_env("ARGOS_KEV_INTERVAL", "21600")))
    # Geolocalizacion de IPs: "ip-api" (gratis, sin clave, uso no comercial) o "none".
    geoip: str = field(default_factory=lambda: _env("ARGOS_GEOIP", "ip-api"))
    history_days: int = field(default_factory=lambda: int(_env("ARGOS_HISTORY_DAYS", "30")))

    def __post_init__(self):
        if self.mode not in ("live", "demo"):
            raise ValueError("ARGOS_MODE debe ser 'live' o 'demo'")
        if self.geoip not in ("ip-api", "none"):
            raise ValueError("ARGOS_GEOIP debe ser 'ip-api' o 'none'")
        if not 1 <= self.threatfox_days <= 7:
            raise ValueError("ARGOS_THREATFOX_DAYS debe estar entre 1 y 7")
