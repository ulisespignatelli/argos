from fastapi.testclient import TestClient

from app.main import create_app


def test_demo_end_to_end(settings):
    app = create_app(settings, start_scheduler=False)
    with TestClient(app) as client:
        sched = app.state.scheduler
        client.portal.call(lambda: _run_all(sched))
        assert client.get("/api/health").json()["mode"] == "demo"
        layers = {s["layer"]: s for s in client.get("/api/layers").json()}
        assert layers["c2"]["count"] == 130 and layers["kev"]["count"] == 20 and layers["urls"]["count"] == 70
        c2 = client.get("/api/layers/c2").json()["entities"]
        assert all(e["lat"] is not None and e["attrs"]["country"] for e in c2)   # geolocalizados
        kev = client.get("/api/layers/kev").json()["entities"]
        assert all(e["lat"] is None for e in kev)
        assert client.get("/api/layers/nada").status_code == 404
        assert len(client.get("/api/history/kev", params={"hours": 24 * 62}).json()) == 20
        with client.websocket_connect("/ws") as ws:
            got = {ws.receive_json()["snapshot"]["status"]["layer"] for _ in range(5)}
            assert got == {"c2", "kev", "urls", "incidents", "events"}
            assert ws.receive_json()["type"] == "alerts"

        # Correlacion: una IP que es C2 y ademas aloja URLs de malware
        urls = client.get("/api/layers/urls").json()["entities"]
        c2_ips = {e["attrs"]["ip"] for e in c2}
        shared = next(e["attrs"]["ip"] for e in urls if e["attrs"].get("ip") in c2_ips)
        p = client.get("/api/pivot", params={"kind": "ip", "value": shared}).json()
        layers_hit = {e["layer"] for e in p["entities"]}
        assert layers_hit == {"c2", "urls"} and any(g["kind"] == "malware" for g in p["groups"])
        assert client.get("/api/pivot", params={"kind": "nada", "value": "x"}).status_code == 422

        # Alertas: la demo evoluciona y dispara familia nueva, pais vigilado y KEV de ransomware
        for _ in range(6):
            client.portal.call(lambda: _run_all(sched))
        rules = {a["rule"] for a in client.get("/api/alerts").json()}
        assert {"familia_nueva", "pais_vigilado", "kev_nueva", "victima_pais_vigilado"} <= rules

        # Exportacion
        r = client.get("/api/export/c2.csv", params={"malware": "Cobalt Strike"})
        assert r.headers["content-disposition"].startswith("attachment") and r.text.startswith("ip,port,malware")
        assert all("Cobalt Strike" in line for line in r.text.strip().splitlines()[1:])
        assert "# Total:" in client.get("/api/export/blocklist.txt").text
        bundle = client.get("/api/export/stix.json").json()
        assert bundle["type"] == "bundle" and any(o["type"] == "indicator" for o in bundle["objects"])
        assert r.headers["x-content-type-options"] == "nosniff"

        # Inteligencia: los C2 de Cobalt Strike quedan ligados a los actores que lo usan (ATT&CK S0154)
        c2_now = client.get("/api/layers/c2").json()["entities"]
        cs = next(e for e in c2_now if e["attrs"]["malware"] == "Cobalt Strike")
        assert cs["attrs"]["software_id"] == "S0154" and cs["attrs"]["actors"]
        inc = client.get("/api/layers/incidents").json()["entities"]
        akira = next(e for e in inc if e["attrs"]["group"] == "akira")
        assert "G1024" in akira["attrs"]["actors"] and akira["lat"] is not None
        active = client.get("/api/actors", params={"active_only": True}).json()
        assert active and all(a["activity"] > 0 for a in active)
        prof = client.get("/api/actors/G1024").json()
        assert prof["name"] == "Akira" and prof["active"]["incidents"] > 0 and prof["techniques"]
        assert client.get("/api/actors/G9999").status_code == 404
        m = client.get("/api/attack/matrix").json()
        assert m["max"] > 0 and len(m["tactics"]) >= 14
        assert client.get("/api/attack/matrix", params={"scope": "actor:G0032"}).json()["label"] == "Lazarus Group"
        assert client.get("/api/attack/matrix", params={"scope": "nada"}).status_code == 422
        piv = client.get("/api/pivot", params={"kind": "actor", "value": "G1024"}).json()
        assert piv["total"] > 0 and any(g["kind"] == "country" for g in piv["groups"])
        md = client.get("/api/report/weekly.md").text
        assert md.startswith("# ARGOS") and "Latinoamérica" in md and "datos simulados" in md


def test_live_without_key_reports_error(tmp_path):
    from app.core.config import Settings
    s = Settings(mode="live", db_path=str(tmp_path / "l.db"), abusech_key="", geoip="none")
    app = create_app(s, start_scheduler=False)
    with TestClient(app) as client:
        sched = app.state.scheduler
        c2 = next(c for c in sched.collectors if c.layer == "c2")
        assert client.portal.call(lambda: sched.run_once(c2)) is False
        st = {x["layer"]: x for x in client.get("/api/layers").json()}["c2"]
        assert "ARGOS_ABUSECH_KEY" in st["error"]


async def _run_all(sched):
    for c in sched.collectors:
        await sched.run_once(c)


def test_rate_limit(tmp_path):
    from app.core.config import Settings
    s = Settings(mode="demo", db_path=str(tmp_path / "r.db"), rate_limit_per_minute=5)
    with TestClient(create_app(s, start_scheduler=False)) as client:
        codes = [client.get("/api/health").status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[-1] == 429


def test_demo_and_live_use_separate_databases(monkeypatch):
    from app.core.config import Settings
    monkeypatch.delenv("ARGOS_DB", raising=False)
    monkeypatch.setenv("ARGOS_MODE", "demo")
    assert Settings().db_path == "argos-demo.db"
    monkeypatch.setenv("ARGOS_MODE", "live")
    assert Settings().db_path == "argos-live.db"
