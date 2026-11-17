"""Alertas y valores ya vistos (para detectar novedades aunque se reinicie el servidor)."""
import asyncio
import sqlite3
from datetime import datetime

from app.domain.models import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_at ON alerts (at);
CREATE TABLE IF NOT EXISTS seen_values (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);
"""


class AlertRepository:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(SCHEMA)
        self._lock = asyncio.Lock()

    async def add(self, alert: Alert) -> bool:
        """Guarda la alerta; devuelve False si ya existia (deduplicacion por id)."""
        async with self._lock:
            def run():
                with self._db:
                    cur = self._db.execute("INSERT OR IGNORE INTO alerts VALUES (?,?,?)",
                                           (alert.id, alert.at.isoformat(), alert.model_dump_json()))
                    return cur.rowcount == 1
            return await asyncio.to_thread(run)

    async def recent(self, limit: int = 50) -> list[Alert]:
        async with self._lock:
            rows = await asyncio.to_thread(lambda: self._db.execute(
                "SELECT data FROM alerts ORDER BY at DESC LIMIT ?", (limit,)).fetchall())
        return [Alert.model_validate_json(r[0]) for r in rows]

    async def seen(self, kind: str) -> set[str]:
        async with self._lock:
            rows = await asyncio.to_thread(lambda: self._db.execute(
                "SELECT value FROM seen_values WHERE kind=?", (kind,)).fetchall())
        return {r[0] for r in rows}

    async def mark_seen(self, kind: str, values: set[str], at: datetime) -> None:
        async with self._lock:
            def run():
                with self._db:
                    self._db.executemany("INSERT OR IGNORE INTO seen_values VALUES (?,?,?)",
                                         [(kind, v, at.isoformat()) for v in values])
            await asyncio.to_thread(run)

    def close(self) -> None:
        self._db.close()
