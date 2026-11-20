from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.api.deps import get_alerts, get_cache, get_history
from app.domain.models import Alert, Entity, LayerStatus, Pivot, Snapshot
from app.services import correlation, export, intel, report
from app.services.cache import LayerCache
from app.storage.alerts import AlertRepository
from app.storage.history import HistoryRepository

router = APIRouter(prefix="/api")
MAP_LAYERS = ("c2", "urls", "incidents")   # capas que participan de la correlacion


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
async def history(layer: str, hours: float = Query(24, gt=0, le=24 * 3660),
                  limit: int = Query(5000, ge=1, le=20000), repo: HistoryRepository = Depends(get_history)):
    """Observaciones guardadas de una capa, de la mas nueva a la mas vieja (para las ventanas de tiempo)."""
    return await repo.query(layer, datetime.now(UTC) - timedelta(hours=hours), limit)


@router.get("/pivot", response_model=Pivot)
def pivot(request: Request, kind: Literal["ip", "asn", "country", "malware", "host", "actor"],
          value: str = Query(min_length=1, max_length=255), cache: LayerCache = Depends(get_cache)):
    """Investiga un dato y devuelve todo lo conectado con el."""
    kb = request.app.state.kb

    def label(k: str, v: str) -> str | None:
        if k == "actor" and v in kb.groups:
            return kb.groups[v]["name"]
        if k == "country" and kb.country(v):
            return kb.country(v)["name"]
        return None

    return correlation.pivot(_entities(cache), kind, value, label)


def _entities(cache: LayerCache) -> list[Entity]:
    return [e for name in MAP_LAYERS if (snap := cache.get(name)) for e in snap.entities]


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


# ---- Inteligencia: actores, matriz ATT&CK e informe ----

@router.get("/actors")
def actors(request: Request, active_only: bool = False, cache: LayerCache = Depends(get_cache)) -> list[dict]:
    rows = intel.active_actors(request.app.state.kb, _entities(cache))
    return [r for r in rows if r["activity"] > 0] if active_only else rows


@router.get("/actors/{gid}")
def actor(request: Request, gid: str, cache: LayerCache = Depends(get_cache)) -> dict:
    profile = intel.actor_profile(request.app.state.kb, gid.upper(), _entities(cache))
    if not profile:
        raise HTTPException(404, f"actor desconocido: {gid}")
    return profile


@router.get("/attack/matrix")
def attack_matrix(request: Request, scope: str = Query("active", max_length=40),
                  cache: LayerCache = Depends(get_cache)) -> dict:
    try:
        return intel.matrix(request.app.state.kb, _entities(cache), scope)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/report/weekly.md", response_class=PlainTextResponse)
async def weekly_report(request: Request, cache: LayerCache = Depends(get_cache),
                        repo: HistoryRepository = Depends(get_history),
                        alerts_repo: AlertRepository = Depends(get_alerts)):
    current = {s.status.layer: s.entities for s in cache.all()}
    week = await repo.query("incidents", datetime.now(UTC) - timedelta(days=7), limit=20000)
    md = report.weekly(request.app.state.kb, current, week or current.get("incidents", []),
                       await alerts_repo.recent(200), request.app.state.settings.mode)
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8", headers=_attachment("informe-semanal.md"))
