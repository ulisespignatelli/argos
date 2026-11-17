from fastapi import Request

from app.services.cache import LayerCache
from app.services.hub import Hub
from app.storage.alerts import AlertRepository
from app.storage.history import HistoryRepository


def get_cache(request: Request) -> LayerCache:
    return request.app.state.cache


def get_history(request: Request) -> HistoryRepository:
    return request.app.state.history


def get_hub(request: Request) -> Hub:
    return request.app.state.hub


def get_alerts(request: Request) -> AlertRepository:
    return request.app.state.alerts
