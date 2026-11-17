from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.api.deps import get_alerts, get_cache, get_history
from app.domain.models import Alert, Entity, LayerStatus, Pivot, Snapshot
from app.services import correlation, export
from app.services.cache import LayerCache
from app.storage.alerts import AlertRepository
from app.storage.history import HistoryRepository

router = APIRouter(prefix="/api")
MAP_LAYERS = ("c2", "urls")   # capas con indicadores de red, que participan de la correlacion


@router.get("/health")
def health(request: Request) -> dict:
    return {"status": "ok", "mode": request.app.state.settings.mode, "clients": request.app.state.hub.size}


@router.get("/layers", response_model=list[LayerStatus])
def layers(cache: LayerCache = Depends(get_cache)):
    return cache.statuses()


@router.get("/layers/{layer}", response_model=Snapshot)
def layer(layer: str, cache: LayerCache = Depends(get_cache)):
    snap = cache.get(layer)
    if not snap:
        raise HTTPException(404, f"capa desconocida: {layer}")
    return snap


@router.get("/history/{layer}", response_model=list[Entity])
async def history(layer: str, hours: float = Query(24, gt=0, le=24 * 90),
                  repo: HistoryRepository = Depends(get_history)):
    return await repo.query(layer, datetime.now(UTC) - timedelta(hours=hours))


@router.get("/pivot", response_model=Pivot)
def pivot(kind: Literal["ip", "asn", "country", "malware", "host"],
          value: str = Query(min_length=1, max_length=255), cache: LayerCache = Depends(get_cache)):
    """Investiga un dato y devuelve todo lo conectado con el en las capas de red."""
    entities = [e for name in MAP_LAYERS if (snap := cache.get(name)) for e in snap.entities]
    return correlation.pivot(entities, kind, value)


@router.get("/alerts", response_model=list[Alert])
async def alerts(limit: int = Query(50, ge=1, le=500), repo: AlertRepository = Depends(get_alerts)):
    return await repo.recent(limit)


def _c2(cache: LayerCache, malware: str | None, country: str | None) -> list[Entity]:
    snap = cache.get("c2")
    return export.filter_c2(snap.entities if snap else [], malware, country)


def _attachment(name: str) -> dict:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return {"Content-Disposition": f'attachment; filename="argos-{name}-{stamp}"'}


@router.get("/export/c2.csv", response_class=PlainTextResponse)
def export_csv(malware: str | None = None, country: str | None = None, cache: LayerCache = Depends(get_cache)):
    return PlainTextResponse(export.to_csv(_c2(cache, malware, country)), media_type="text/csv; charset=utf-8",
                             headers=_attachment("c2.csv"))


@router.get("/export/blocklist.txt", response_class=PlainTextResponse)
def export_blocklist(malware: str | None = None, country: str | None = None, cache: LayerCache = Depends(get_cache)):
    return PlainTextResponse(export.to_blocklist(_c2(cache, malware, country)), headers=_attachment("blocklist.txt"))


@router.get("/export/stix.json")
def export_stix(malware: str | None = None, country: str | None = None, cache: LayerCache = Depends(get_cache)):
    return JSONResponse(export.to_stix(_c2(cache, malware, country)), media_type="application/stix+json;version=2.1",
                        headers=_attachment("stix.json"))
