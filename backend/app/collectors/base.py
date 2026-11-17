"""Interfaz comun de los recolectores. Agregar una fuente = agregar una subclase."""
from abc import ABC, abstractmethod

import httpx

from app.domain.models import Entity


class CollectorError(Exception):
    pass


class Collector(ABC):
    name: str          # fuente, ej. "usgs"
    layer: str         # capa que alimenta
    interval: float    # segundos entre consultas
    keep_history: bool = False

    @abstractmethod
    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        """Consulta la fuente y devuelve entidades normalizadas. No toca la API ni la base."""
