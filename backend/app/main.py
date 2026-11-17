"""Punto de entrada: arma las piezas y las conecta. Ninguna pieza conoce a las demas por su cuenta."""
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import rest, ws
from app.collectors.base import Collector
from app.collectors.registry import build_collectors
from app.core.config import Settings, load_dotenv
from app.core.logging import setup_logging
from app.geolocation.base import Geolocator
from app.geolocation.demo import DemoGeolocator
from app.geolocation.ipapi import IpApiGeolocator
from app.services.cache import LayerCache
from app.services.enrichment import GeoIpEnricher
from app.services.hub import Hub
from app.services.scheduler import Scheduler
from app.storage.geo_cache import GeoCache
from app.storage.history import HistoryRepository


def build_geolocator(settings: Settings, client: httpx.AsyncClient) -> Geolocator | None:
    if settings.mode == "demo":
        return DemoGeolocator()
    return IpApiGeolocator(client) if settings.geoip == "ip-api" else None


def create_app(settings: Settings | None = None, collectors: list[Collector] | None = None,
               start_scheduler: bool = True) -> FastAPI:
    if settings is None:
        load_dotenv()
        settings = Settings()
    setup_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.cache = LayerCache()
        app.state.hub = Hub()
        app.state.history = HistoryRepository(settings.db_path)
        geo_cache = GeoCache(settings.db_path)
        await app.state.history.prune(settings.history_days)
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "argos-osint/0.2"}) as client:
            geolocator = build_geolocator(settings, client)
            enrichers = [GeoIpEnricher(geolocator, geo_cache)] if geolocator else []
            app.state.scheduler = Scheduler(collectors if collectors is not None else build_collectors(settings),
                                            app.state.cache, app.state.hub, app.state.history, client, enrichers)
            if start_scheduler:
                app.state.scheduler.start()
            yield
            await app.state.scheduler.stop()
        geo_cache.close()
        app.state.history.close()

    app = FastAPI(title="ARGOS API", version="0.2.0", lifespan=lifespan,
                  description="Inteligencia de amenazas con fuentes abiertas: infraestructura C2 y vulnerabilidades explotadas.")
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET"],
                       allow_headers=["*"])
    app.include_router(rest.router)
    app.include_router(ws.router)
    return app


app = create_app()
