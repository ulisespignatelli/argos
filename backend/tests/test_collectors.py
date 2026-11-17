import httpx
import pytest

from app.collectors import opensky, usgs
from app.collectors.base import CollectorError
from app.collectors.demo import DemoAircraft, DemoEarthquakes

USGS_SAMPLE = {"features": [
    {"id": "us7000abc", "properties": {"mag": 5.4, "place": "Coquimbo, Chile", "time": 1763400000000, "url": "u"},
     "geometry": {"coordinates": [-71.3, -30.1, 45.0]}},
    {"id": "bad", "properties": {"mag": None}, "geometry": {"coordinates": [0, 0]}},
]}
OPENSKY_SAMPLE = {"states": [
    ["e8044e", "ARG1302 ", "Argentina", 1, 1763400000, -58.5, -34.8, 10600.0, False, 236.0, 182.0, 0, None, 0, "7700"],
    ["abc123", None, "Chile", 1, 1763400000, None, None, None, True, 0, 0, 0, None, 0, None],
]}


def client_for(status, payload):
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(status, json=payload)))


async def test_usgs_parse_and_fetch():
    async with client_for(200, USGS_SAMPLE) as c:
        items = await usgs.UsgsEarthquakes().fetch(c)
    assert len(items) == 1
    q = items[0]
    assert q.id == "usgs:us7000abc" and q.lat == -30.1 and q.lon == -71.3
    assert q.attrs["mag"] == 5.4 and q.attrs["depth_km"] == 45.0


async def test_opensky_parse_skips_missing_position():
    async with client_for(200, OPENSKY_SAMPLE) as c:
        items = await opensky.OpenSkyAircraft((-56, -80, -15, -30)).fetch(c)
    assert [e.label for e in items] == ["ARG1302"]
    assert items[0].attrs["squawk"] == "7700"


async def test_opensky_rate_limit_is_reported():
    async with client_for(429, {}) as c:
        with pytest.raises(CollectorError, match="limite"):
            await opensky.OpenSkyAircraft((-56, -80, -15, -30)).fetch(c)


async def test_demo_collectors_are_valid_and_deterministic():
    a1, a2 = await DemoAircraft().fetch(None), await DemoAircraft().fetch(None)
    assert len(a1) == 120 and [e.id for e in a1] == [e.id for e in a2]
    assert all(-90 <= e.lat <= 90 and -180 <= e.lon <= 180 for e in a1)
    assert len(await DemoEarthquakes().fetch(None)) == 25
