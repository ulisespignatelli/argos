"""Arma la lista de recolectores segun la configuracion."""
from app.collectors.base import Collector
from app.collectors.demo import DemoAircraft, DemoEarthquakes
from app.collectors.opensky import OpenSkyAircraft
from app.collectors.usgs import UsgsEarthquakes
from app.core.config import Settings


def build_collectors(s: Settings) -> list[Collector]:
    if s.mode == "demo":
        return [DemoAircraft(), DemoEarthquakes()]
    return [OpenSkyAircraft(s.opensky_bbox, s.opensky_interval), UsgsEarthquakes(s.usgs_interval)]
