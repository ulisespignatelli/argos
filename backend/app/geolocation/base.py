from abc import ABC, abstractmethod

from app.domain.models import GeoInfo


class Geolocator(ABC):
    """Puerto de geolocalizacion: recibe IPs y devuelve las que pudo ubicar."""
    name: str

    @abstractmethod
    async def locate(self, ips: list[str]) -> dict[str, GeoInfo]:
        ...
