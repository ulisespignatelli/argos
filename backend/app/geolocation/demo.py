"""Ubicaciones simuladas y estables (misma IP, mismo lugar) para el modo demo."""
import hashlib

from app.domain.models import GeoInfo
from app.geolocation.base import Geolocator

# Ciudades con mucha infraestructura de hosting, que es donde suelen aparecer los C2.
CITIES = [
    ("Amsterdam", "Países Bajos", "NL", 52.37, 4.90), ("Frankfurt", "Alemania", "DE", 50.11, 8.68),
    ("Ashburn", "Estados Unidos", "US", 39.04, -77.49), ("Dallas", "Estados Unidos", "US", 32.78, -96.80),
    ("Los Angeles", "Estados Unidos", "US", 34.05, -118.24), ("Moscú", "Rusia", "RU", 55.76, 37.62),
    ("Singapur", "Singapur", "SG", 1.35, 103.82), ("Hong Kong", "Hong Kong", "HK", 22.32, 114.17),
    ("São Paulo", "Brasil", "BR", -23.55, -46.63), ("París", "Francia", "FR", 48.86, 2.35),
    ("Londres", "Reino Unido", "GB", 51.51, -0.13), ("Bucarest", "Rumania", "RO", 44.43, 26.10),
    ("Kiev", "Ucrania", "UA", 50.45, 30.52), ("Seúl", "Corea del Sur", "KR", 37.57, 126.98),
    ("Tokio", "Japón", "JP", 35.68, 139.69), ("Helsinki", "Finlandia", "FI", 60.17, 24.94),
    ("Toronto", "Canadá", "CA", 43.65, -79.38), ("Buenos Aires", "Argentina", "AR", -34.60, -58.38),
]
ORGS = ["Hosting Demo BV", "Cloud Demo LLC", "VPS Demo Ltd", "Datacenter Demo GmbH"]


class DemoGeolocator(Geolocator):
    name = "demo"

    async def locate(self, ips: list[str]) -> dict[str, GeoInfo]:
        out = {}
        for ip in ips:
            h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
            local = ip.startswith("203.0.113.") and int(ip.rsplit(".", 1)[1]) >= 200   # ver collectors/demo.py
            # El ultimo lugar de CITIES se reserva para las IPs "locales" de la demo.
            city, country, cc, lat, lon = CITIES[-1] if local else CITIES[h % (len(CITIES) - 1)]
            jitter_lat, jitter_lon = ((h >> 8) % 100 - 50) / 60, ((h >> 16) % 100 - 50) / 60
            out[ip] = GeoInfo(ip=ip, lat=lat + jitter_lat, lon=lon + jitter_lon, country=country, country_code=cc,
                              city=city, asn=f"AS{64512 + h % 1000}", org=ORGS[(h >> 24) % len(ORGS)])
        return out
