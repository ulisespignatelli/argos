from fastapi.testclient import TestClient

from app.main import create_app


def test_demo_end_to_end(settings):
    app = create_app(settings, start_scheduler=False)
    with TestClient(app) as client:
        sched = app.state.scheduler
        client.portal.call(lambda: _run_all(sched))
        assert client.get("/api/health").json()["mode"] == "demo"
        layers = {s["layer"]: s for s in client.get("/api/layers").json()}
        assert layers["c2"]["count"] == 160 and layers["kev"]["count"] == 24
        c2 = client.get("/api/layers/c2").json()["entities"]
        assert all(e["lat"] is not None and e["attrs"]["country"] for e in c2)   # geolocalizados
        kev = client.get("/api/layers/kev").json()["entities"]
        assert all(e["lat"] is None for e in kev)
        assert client.get("/api/layers/nada").status_code == 404
        assert len(client.get("/api/history/kev", params={"hours": 24 * 62}).json()) == 24
        with client.websocket_connect("/ws") as ws:
            got = {ws.receive_json()["snapshot"]["status"]["layer"] for _ in range(2)}
            assert got == {"c2", "kev"}


def test_live_without_key_reports_error(tmp_path):
    from app.core.config import Settings
    s = Settings(mode="live", db_path=str(tmp_path / "l.db"), threatfox_key="", geoip="none")
    app = create_app(s, start_scheduler=False)
    with TestClient(app) as client:
        sched = app.state.scheduler
        c2 = next(c for c in sched.collectors if c.layer == "c2")
        assert client.portal.call(lambda: sched.run_once(c2)) is False
        st = {x["layer"]: x for x in client.get("/api/layers").json()}["c2"]
        assert "ARGOS_THREATFOX_KEY" in st["error"]


async def _run_all(sched):
    for c in sched.collectors:
        await sched.run_once(c)
