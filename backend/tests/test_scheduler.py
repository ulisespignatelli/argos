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
    name, layer, interval, keep_history = "fake", "earthquakes", 1, True

    def __init__(self):
        self.fail = False

    async def fetch(self, client):
        if self.fail:
            raise CollectorError("fuente caida")
        return [Entity(id="fake:1", layer="earthquakes", lat=1, lon=2, label="x", observed_at=utcnow())]


async def test_success_then_failure_keeps_last_data(tmp_path):
    cache, hub, repo, c = LayerCache(), FakeHub(), HistoryRepository(str(tmp_path / "h.db")), Fake()
    s = Scheduler([c], cache, hub, repo, client=None)
    assert await s.run_once(c)
    assert cache.get("earthquakes").status.count == 1
    assert hub.sent[-1]["type"] == "snapshot"
    assert len(await repo.query("earthquakes", since=utcnow().replace(year=2000))) == 1

    c.fail = True
    assert not await s.run_once(c)
    snap = cache.get("earthquakes")
    assert snap.status.error == "fuente caida" and len(snap.entities) == 1   # conserva el ultimo dato bueno
    assert hub.sent[-1]["type"] == "status"
