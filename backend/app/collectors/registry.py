"""Arma la lista de recolectores segun la configuracion."""
from app.collectors.base import Collector
from app.collectors.cisa_kev import CisaKev
from app.collectors.demo import DemoC2, DemoKev, DemoUrls
from app.collectors.threatfox import ThreatFoxC2
from app.collectors.urlhaus import UrlhausUrls
from app.core.config import Settings


def build_collectors(s: Settings) -> list[Collector]:
    if s.mode == "demo":
        c2 = DemoC2()
        return [c2, DemoUrls(shared_from=c2), DemoKev()]
    return [ThreatFoxC2(s.abusech_key, s.threatfox_days, s.threatfox_interval),
            UrlhausUrls(s.abusech_key, s.urlhaus_interval),
            CisaKev(s.kev_interval)]
