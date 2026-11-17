"""Punto de entrada: arma las piezas y las conecta. Ninguna pieza conoce a las demas por su cuenta."""
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import rest, ws
from app.collectors.base import Collector
from app.collectors.registry import build_collectors
from app.core.config import Settings
from app.core.logging import setup_logging
from app.services.cache import LayerCache
from app.services.hub import Hub
from app.services.scheduler import Scheduler
from app.storage.history import HistoryRepository


def create_app(settings: Settings | None = None, collectors: list[Collector] | None = None,
               start_scheduler: bool = True) -> FastAPI:
    settings = settings or Settings()
    setup_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.cache = LayerCache()
        app.state.hub = Hub()
        app.state.history = HistoryRepository(settings.db_path)
        await app.state.history.prune(settings.history_days)
        async with httpx.AsyncClient(timeout=20, headers={"User-Agent": "argos-osint/0.1"}) as client:
            app.state.scheduler = Scheduler(collectors if collectors is not None else build_collectors(settings),
                                            app.state.cache, app.state.hub, app.state.history, client)
            if start_scheduler:
                app.state.scheduler.start()
            yield
            await app.state.scheduler.stop()
        app.state.history.close()

    app = FastAPI(title="ARGOS API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET"],
                       allow_headers=["*"])
    app.include_router(rest.router)
    app.include_router(ws.router)
    return app


app = create_app()
