"""Arma la lista de recolectores segun la configuracion."""
from app.collectors.base import Collector
from app.collectors.cisa_kev import CisaKev
from app.collectors.demo import DemoC2, DemoKev
from app.collectors.threatfox import ThreatFoxC2
from app.core.config import Settings


def build_collectors(s: Settings) -> list[Collector]:
    if s.mode == "demo":
        return [DemoC2(), DemoKev()]
    return [ThreatFoxC2(s.threatfox_key, s.threatfox_days, s.threatfox_interval), CisaKev(s.kev_interval)]
