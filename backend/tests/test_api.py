from fastapi.testclient import TestClient

from app.main import create_app


def test_rest_and_websocket(settings):
    app = create_app(settings, start_scheduler=False)
    with TestClient(app) as client:
        sched = app.state.scheduler
        client.portal.call(lambda: _run_all(sched))
        assert client.get("/api/health").json()["mode"] == "demo"
        layers = {s["layer"]: s for s in client.get("/api/layers").json()}
        assert layers["aircraft"]["count"] == 120 and layers["earthquakes"]["count"] == 25
        assert len(client.get("/api/layers/aircraft").json()["entities"]) == 120
        assert client.get("/api/layers/nada").status_code == 404
        assert len(client.get("/api/history/earthquakes", params={"hours": 48}).json()) == 25
        assert client.get("/api/history/aircraft").json() == []   # los aviones no se historizan
        with client.websocket_connect("/ws") as ws:
            got = {ws.receive_json()["snapshot"]["status"]["layer"] for _ in range(2)}
            assert got == {"aircraft", "earthquakes"}


async def _run_all(sched):
    for c in sched.collectors:
        await sched.run_once(c)
