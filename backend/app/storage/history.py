"""Historial en SQLite. Interfaz chica para poder cambiarlo por Postgres/PostGIS sin tocar el resto."""
import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta

from app.domain.models import Entity

SCHEMA_VERSION = 2
SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id TEXT NOT NULL,
    layer TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    lat REAL,
    lon REAL,
    label TEXT NOT NULL,
    attrs TEXT NOT NULL,
    PRIMARY KEY (id, observed_at)
);
CREATE INDEX IF NOT EXISTS ix_obs_layer_time ON observations (layer, observed_at);
"""


class HistoryRepository:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        if self._db.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
            # v1 guardaba aviones y sismos con coordenadas obligatorias: se descarta.
            self._db.execute("DROP TABLE IF EXISTS observations")
            self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._db.executescript(SCHEMA)
        self._lock = asyncio.Lock()

    async def save(self, entities: list[Entity]) -> None:
        rows = [(e.id, e.layer, e.observed_at.isoformat(), e.lat, e.lon, e.label, json.dumps(e.attrs))
                for e in entities]
        async with self._lock:
            await asyncio.to_thread(self._insert, rows)

    def _insert(self, rows):
        with self._db:
            self._db.executemany("INSERT OR IGNORE INTO observations VALUES (?,?,?,?,?,?,?)", rows)

    async def query(self, layer: str, since: datetime, limit: int = 5000) -> list[Entity]:
        """Ultima observacion de cada entidad de la capa desde `since`, de la mas nueva a la mas vieja."""
        async with self._lock:
            rows = await asyncio.to_thread(lambda: self._db.execute(
                "SELECT id, layer, MAX(observed_at), lat, lon, label, attrs FROM observations"
                " WHERE layer=? AND observed_at>=? GROUP BY id ORDER BY MAX(observed_at) DESC LIMIT ?",
                (layer, since.isoformat(), limit)).fetchall())
        return [Entity(id=r[0], layer=r[1], observed_at=datetime.fromisoformat(r[2]), lat=r[3], lon=r[4],
                       label=r[5], attrs=json.loads(r[6])) for r in rows]

    async def prune(self, days: int) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        async with self._lock:
            def run():
                with self._db:
                    return self._db.execute("DELETE FROM observations WHERE observed_at<?", (cutoff,)).rowcount
            return await asyncio.to_thread(run)

    def close(self) -> None:
        self._db.close()
