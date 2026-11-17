from app.collectors.base import Collector, CollectorError
from app.domain.models import Entity, utcnow
from app.services.cache import LayerCache
from app.services.scheduler import Scheduler
from app.storage.history import HistoryRepository


class FakeHub:
    def __init__(self):
        self.sent = []

    async def broadcast(self, msg):
        self.sent.append(msg)


class Fake(Collector):
    name, layer, interval, keep_history = "fake", "c2", 1, True

    def __init__(self):
        self.fail = False

    async def fetch(self, client):
        if self.fail:
            raise CollectorError("fuente caida")
        return [Entity(id="fake:1", layer="c2", label="x", observed_at=utcnow(), attrs={"ip": "1.1.1.1"})]


class Tagger:
    async def enrich(self, entities):
        return [e.model_copy(update={"lat": 1.0, "lon": 2.0}) for e in entities]


async def test_enrich_store_then_failure_keeps_last_data(tmp_path):
    cache, hub, repo, c = LayerCache(), FakeHub(), HistoryRepository(str(tmp_path / "h.db")), Fake()
    s = Scheduler([c], cache, hub, repo, client=None, enrichers=[Tagger()])
    assert await s.run_once(c)
    snap = cache.get("c2")
    assert snap.status.count == 1 and snap.entities[0].lat == 1.0
    assert hub.sent[-1]["type"] == "snapshot"
    assert len(await repo.query("c2", since=utcnow().replace(year=2000))) == 1

    c.fail = True
    assert not await s.run_once(c)
    snap = cache.get("c2")
    assert snap.status.error == "fuente caida" and len(snap.entities) == 1
    assert hub.sent[-1]["type"] == "status"


def test_history_migrates_v1_schema(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE observations (id TEXT, layer TEXT, observed_at TEXT, lat REAL NOT NULL, lon REAL NOT NULL,"
               " label TEXT, attrs TEXT, PRIMARY KEY (id, observed_at))")
    db.commit()
    db.close()
    HistoryRepository(path)
    cols = {r[1]: r[3] for r in sqlite3.connect(path).execute("PRAGMA table_info(observations)")}
    assert cols["lat"] == 0   # ya no es NOT NULL
