from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.deps import get_cache, get_history
from app.domain.models import Entity, LayerStatus, Snapshot
from app.services.cache import LayerCache
from app.storage.history import HistoryRepository

router = APIRouter(prefix="/api")


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
async def history(layer: str, hours: float = Query(24, gt=0, le=24 * 30),
                  repo: HistoryRepository = Depends(get_history)):
    return await repo.query(layer, datetime.now(timezone.utc) - timedelta(hours=hours))
