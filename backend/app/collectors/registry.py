"""Arma la lista de recolectores segun la configuracion."""
from app.collectors.base import Collector
from app.collectors.cisa_kev import CisaKev
from app.collectors.demo import DemoC2, DemoIncidents, DemoKev, DemoNews, DemoUrls
from app.collectors.news import DEFAULT_FEEDS, KevIndex, NewsEvents, parse_feed_list
from app.collectors.ransomware_live import RansomwareLiveVictims
from app.collectors.threatfox import ThreatFoxC2
from app.collectors.urlhaus import UrlhausUrls
from app.core.config import Settings
from app.knowledge.kb import KnowledgeBase


def build_collectors(s: Settings, kb: KnowledgeBase) -> list[Collector]:
    if s.mode == "demo":
        c2 = DemoC2()
        return [c2, DemoUrls(shared_from=c2), DemoKev(), DemoIncidents(kb.countries), DemoNews(kb)]
    kev = KevIndex()
    feeds = parse_feed_list(s.news_feeds) if s.news_feeds else DEFAULT_FEEDS
    collectors: list[Collector] = [
        ThreatFoxC2(s.abusech_key, s.threatfox_days, s.threatfox_interval),
        UrlhausUrls(s.abusech_key, s.urlhaus_interval),
        CisaKev(s.kev_interval, index=kev),
        RansomwareLiveVictims(kb.countries, s.ransomware_interval)]
    if s.news_interval > 0:
        collectors.append(NewsEvents(kb, kev, feeds, s.news_interval, s.news_days))
    return collectors
