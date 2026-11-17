"""Cache persistente de geolocalizaciones: cada IP se consulta una sola vez cada `ttl_days`."""
import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone

from app.domain.models import GeoInfo

SCHEMA = """
CREATE TABLE IF NOT EXISTS geoip (
    ip TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class GeoCache:
    def __init__(self, path: str, ttl_days: int = 30):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(SCHEMA)
        self._lock = asyncio.Lock()
        self.ttl = timedelta(days=ttl_days)

    async def get_many(self, ips: set[str]) -> dict[str, GeoInfo]:
        if not ips:
            return {}
        cutoff = (datetime.now(timezone.utc) - self.ttl).isoformat()
        ips_list = list(ips)
        async with self._lock:
            def run():
                rows = []
                for i in range(0, len(ips_list), 500):   # limite de parametros de SQLite
                    part = ips_list[i:i + 500]
                    rows += self._db.execute(
                        f"SELECT data FROM geoip WHERE updated_at>=? AND ip IN ({','.join('?' * len(part))})",
                        (cutoff, *part)).fetchall()
                return rows
            rows = await asyncio.to_thread(run)
        return {g.ip: g for g in (GeoInfo.model_validate_json(r[0]) for r in rows)}

    async def put_many(self, infos: dict[str, GeoInfo]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        rows = [(ip, g.model_dump_json(), now) for ip, g in infos.items()]
        async with self._lock:
            def run():
                with self._db:
                    self._db.executemany("INSERT OR REPLACE INTO geoip VALUES (?,?,?)", rows)
            await asyncio.to_thread(run)

    def close(self) -> None:
        self._db.close()
