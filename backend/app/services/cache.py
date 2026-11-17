"""Estado actual de cada capa, en memoria. La API lee de aca; nunca consulta las fuentes."""
import asyncio

from app.domain.models import Entity, LayerStatus, Snapshot, utcnow


class LayerCache:
    def __init__(self):
        self._snapshots: dict[str, Snapshot] = {}
        self._lock = asyncio.Lock()

    def register(self, layer: str, source: str) -> None:
        self._snapshots.setdefault(layer, Snapshot(status=LayerStatus(layer=layer, source=source), entities=[]))

    async def replace(self, layer: str, entities: list[Entity]) -> Snapshot:
        async with self._lock:
            snap = self._snapshots[layer]
            snap = Snapshot(status=snap.status.model_copy(update={"updated_at": utcnow(), "count": len(entities),
                                                                   "error": None}),
                            entities=entities)
            self._snapshots[layer] = snap
            return snap

    async def set_error(self, layer: str, error: str) -> LayerStatus:
        async with self._lock:
            snap = self._snapshots[layer]
            status = snap.status.model_copy(update={"error": error})
            self._snapshots[layer] = Snapshot(status=status, entities=snap.entities)
            return status

    def get(self, layer: str) -> Snapshot | None:
        return self._snapshots.get(layer)

    def statuses(self) -> list[LayerStatus]:
        return [s.status for s in self._snapshots.values()]

    def all(self) -> list[Snapshot]:
        return list(self._snapshots.values())
