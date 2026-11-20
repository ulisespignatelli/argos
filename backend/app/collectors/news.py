"""Eventos a partir de avisos oficiales y prensa especializada (RSS/Atom), sin IA.

Lee varios feeds en paralelo, extrae datos con reglas (ver services/news_extract.py), agrupa notas del
mismo hecho y verifica: fuente oficial, 2+ medios o CVE en el catalogo KEV de CISA. Ademas consulta
el registro publico de CVE (cveawg.mitre.org) para marcar CVE que no tienen registro publicado.
Un feed caido no frena a los demas.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity
from app.knowledge.kb import KnowledgeBase
from app.services.news_extract import TYPE_LABELS, Extracted, Extractor, cluster, event_id, parse_feed, status

log = logging.getLogger("argos.news")
CVE_API = "https://cveawg.mitre.org/api/cve/"


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    official: bool = False
    default_type: str | None = None


DEFAULT_FEEDS = (
    Feed("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", official=True),
    Feed("CERT-EU", "https://cert.europa.eu/publications/security-advisories-rss", official=True),
    Feed("INCIBE-CERT", "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed", official=True),
    Feed("INCIBE-CERT SCI", "https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/feed", official=True,
         default_type="ot"),
    Feed("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    Feed("The Record", "https://therecord.media/feed"),
    Feed("SecurityWeek", "https://www.securityweek.com/feed/"),
    Feed("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    Feed("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    Feed("Krebs on Security", "https://krebsonsecurity.com/feed/"),
)


def parse_feed_list(raw: str) -> tuple[Feed, ...]:
    """ARGOS_NEWS_FEEDS="Nombre|https://url|oficial;Otro|https://url" (reemplaza la lista por defecto)."""
    feeds = []
    for part in raw.split(";"):
        bits = [b.strip() for b in part.split("|")]
        if len(bits) >= 2 and bits[1].startswith("https://"):
            feeds.append(Feed(bits[0] or bits[1], bits[1], official=len(bits) > 2 and bits[2].lower() == "oficial"))
    return tuple(feeds)


class KevIndex:
    """CVE del catalogo KEV completo. Lo llena el recolector de CISA y lo lee el de noticias."""

    def __init__(self):
        self.ids: frozenset[str] = frozenset()


class CveRegistry:
    """Consulta (con cache de 24 h) si un CVE tiene registro publicado en el programa CVE."""

    def __init__(self, per_cycle: int = 20, ttl: float = 86400):
        self.per_cycle, self.ttl = per_cycle, ttl
        self._cache: dict[str, tuple[float, str]] = {}

    def get(self, cve: str) -> str | None:
        hit = self._cache.get(cve)
        return hit[1] if hit and time.monotonic() - hit[0] < self.ttl else None

    async def check(self, client: httpx.AsyncClient, cves: list[str]) -> None:
        pending = [c for c in dict.fromkeys(cves) if self.get(c) is None][: self.per_cycle]
        for cve in pending:
            try:
                r = await client.get(CVE_API + cve, timeout=10)
            except httpx.HTTPError:
                continue
            if r.status_code == 200:
                state = str((r.json().get("cveMetadata") or {}).get("state", "PUBLISHED")).upper()
                self._cache[cve] = (time.monotonic(), "rechazado" if state == "REJECTED" else "publicado")
            elif r.status_code == 404:
                self._cache[cve] = (time.monotonic(), "sin_registro")


class NewsEvents(Collector):
    name, layer, keep_history = "news", "events", True

    def __init__(self, kb: KnowledgeBase, kev: KevIndex | None = None, feeds: tuple[Feed, ...] = DEFAULT_FEEDS,
                 interval: float = 1800, days: int = 14, registry: CveRegistry | None = None):
        self.kb, self.kev, self.feeds, self.interval, self.days = kb, kev or KevIndex(), feeds, interval, days
        self.extractor = Extractor(kb)
        self.registry = registry or CveRegistry()
        self.last_failed: list[str] = []

    async def _one(self, client: httpx.AsyncClient, feed: Feed):
        r = await client.get(feed.url, timeout=20, follow_redirects=True,
                             headers={"Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"})
        if r.status_code != 200:
            raise CollectorError(f"HTTP {r.status_code}")
        return parse_feed(r.content, feed.name, feed.official, feed.default_type)

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        results = await asyncio.gather(*(self._one(client, f) for f in self.feeds), return_exceptions=True)
        items, failed = [], []
        for feed, res in zip(self.feeds, results, strict=True):
            if isinstance(res, BaseException):
                failed.append(feed.name)
                log.warning("feed %s: %s", feed.name, res)
            else:
                items += res
        self.last_failed = failed
        if not items and failed:
            raise CollectorError(f"ningún feed respondió ({', '.join(failed[:4])}…)")
        events = build_events(self.extractor, self.kb, items, self.kev.ids, self.days)
        await self.registry.check(client, [c["id"] for e in events for c in e.attrs["cves"]])
        return [annotate_cves(e, self.registry) for e in events]


def build_events(extractor: Extractor, kb: KnowledgeBase, items, kev_ids: frozenset[str], days: int = 14,
                 now: datetime | None = None) -> list[Entity]:
    now = now or datetime.now(UTC)
    cut = now - timedelta(days=days)
    seen: set[str] = set()
    extracted: list[Extracted] = []
    for it in sorted(items, key=lambda i: i.published):
        if it.published < cut or it.url in seen:
            continue
        seen.add(it.url)
        ex = extractor.extract(it, kev_ids)
        if ex.primary:          # sin ningun tipo reconocible no es un evento (reseñas, webinars, etc.)
            extracted.append(ex)
    return [to_entity(g, kb, kev_ids) for g in cluster(extracted)]


def _pick(group: list[Extracted]) -> Extracted:
    """Titulo del evento: el de la fuente oficial si hay, si no el de la nota mas antigua."""
    return min(group, key=lambda x: (not x.item.official, x.item.published))


def to_entity(group: list[Extracted], kb: KnowledgeBase, kev_ids: frozenset[str]) -> Entity:
    head = _pick(group)
    votes: dict[str, int] = {}
    for x in group:
        for i, t in enumerate(x.types):
            votes[t] = votes.get(t, 0) + (3 if i == 0 else 1)
    types = sorted(votes, key=lambda t: -votes[t])
    kind = types[0]
    def merge(attr: str) -> list[str]:
        return list(dict.fromkeys(v for x in group for v in getattr(x, attr)))

    cves, actors, software = merge("cves"), merge("actors"), merge("software")
    victims, origins = merge("victims"), merge("origins")
    victims = [v for v in victims if v not in origins]
    verdict, why = status(group, kev_ids)
    first = min(x.item.published for x in group)
    lat = lon = None
    if victims and (c := kb.country(victims[0])):
        r = random.Random(event_id(group))  # noqa: S311 (dispersion visual)
        lat, lon = round(c["lat"] + r.uniform(-1.5, 1.5), 4), round(c["lon"] + r.uniform(-1.8, 1.8), 4)
    origin = None
    if origins and (c := kb.country(origins[0])):
        origin = {"country": origins[0], "name": c["name"], "lat": c["lat"], "lon": c["lon"],
                  "actor": actors[0] if actors else None}
    sources = sorted(({"name": x.item.source, "url": x.item.url, "title": x.item.title,
                       "published": x.item.published.isoformat(), "official": x.item.official} for x in group),
                     key=lambda s: s["published"])
    attrs = {
        "kind": kind, "kind_label": TYPE_LABELS[kind], "types": types, "title": head.item.title,
        "sources": sources[:12], "n_sources": len({s["name"] for s in sources}),
        "status": verdict, "status_reason": why,
        "cves": [{"id": c, "kev": c.upper() in kev_ids, "registry": None} for c in cves],
        "exploited": any(x.exploited for x in group),
        "actors": [{"id": g, "name": kb.groups[g]["name"]} for g in actors],
        "malware": [{"id": s, "name": kb.software[s]["name"]} for s in software],
        "countries": [{"code": cc, "name": kb.country(cc)["name"]} for cc in victims if kb.country(cc)],
        "country_code": victims[0] if victims else None,
        "origin": origin,
        "reasons": list(dict.fromkeys(r for x in group for r in x.reasons))[:10],
        "global": lat is None,
        "source_url": head.item.url,
    }
    return Entity(id=event_id(group), layer="events", lat=lat, lon=lon, label=head.item.title,
                  observed_at=first, attrs=attrs)


def annotate_cves(e: Entity, registry: CveRegistry) -> Entity:
    cves = [{**c, "registry": registry.get(c["id"])} for c in e.attrs["cves"]]
    reasons = list(e.attrs["reasons"])
    if any(c["registry"] == "sin_registro" and not c["kev"] for c in cves):
        reasons.append("atención: hay un CVE sin registro público en cve.org (reservado o inexistente)")
    return e.model_copy(update={"attrs": {**e.attrs, "cves": cves, "reasons": reasons}})
