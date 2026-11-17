"""Corre cada recolector en su propio ciclo: consulta, enriquece, guarda y difunde."""
import asyncio
import logging

import httpx

from app.collectors.base import Collector
from app.services.cache import LayerCache
from app.services.enrichment import Enricher
from app.services.hub import Hub
from app.storage.history import HistoryRepository

log = logging.getLogger(__name__)
MAX_BACKOFF = 1800


class Scheduler:
    def __init__(self, collectors: list[Collector], cache: LayerCache, hub: Hub, history: HistoryRepository,
                 client: httpx.AsyncClient | None, enrichers: list[Enricher] | None = None):
        self.collectors, self.cache, self.hub, self.history, self.client = collectors, cache, hub, history, client
        self.enrichers = enrichers or []
        self._tasks: list[asyncio.Task] = []
        for c in collectors:
            cache.register(c.layer, c.name)

    async def run_once(self, c: Collector) -> bool:
        try:
            entities = await c.fetch(self.client)
        except Exception as exc:  # una fuente caida no debe tumbar a las demas
            msg = str(exc) or exc.__class__.__name__
            log.warning("%s: %s", c.name, msg)
            status = await self.cache.set_error(c.layer, msg)
            await self.hub.broadcast({"type": "status", "status": status.model_dump(mode="json")})
            return False
        for enricher in self.enrichers:
            entities = await enricher.enrich(entities)
        snap = await self.cache.replace(c.layer, entities)
        if c.keep_history:
            await self.history.save(entities)
        await self.hub.broadcast({"type": "snapshot", "snapshot": snap.model_dump(mode="json")})
        return True

    async def _loop(self, c: Collector) -> None:
        delay = c.interval
        while True:
            ok = await self.run_once(c)
            delay = c.interval if ok else min(MAX_BACKOFF, max(delay, 30) * 2)
            await asyncio.sleep(delay)

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._loop(c), name=f"collector:{c.name}:{c.layer}")
                       for c in self.collectors]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
