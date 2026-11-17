"""Datos simulados para mostrar el sistema sin red ni claves.

Las IPs salen de los rangos reservados para documentacion (RFC 5737): nunca se senala
como maliciosa una IP real. Los CVE son ficticios (prefijo DEMO).
"""
import ipaddress
import random
from datetime import datetime, timedelta, timezone

import httpx

from app.collectors.base import Collector
from app.domain.models import Entity

FAMILIES = [("Cobalt Strike", 30), ("AsyncRAT", 16), ("Remcos", 14), ("Sliver", 10), ("QakBot", 8),
            ("DCRat", 8), ("Havoc", 6), ("Mythic", 5), ("Lumma Stealer", 9), ("Vidar", 6)]
PORTS = [443, 80, 8080, 8443, 4444, 2404, 7443, 50050, 31337, 1177]
DOC_NETS = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
REPORTERS = ["abuse_ch", "drb_ra", "Gi7w0rm", "malpulse", "ThreatHunter_ar"]


class DemoC2(Collector):
    name, layer, keep_history = "demo", "c2", True

    def __init__(self, interval: float = 20, count: int = 160, seed: int = 21):
        self.interval = interval
        r = random.Random(seed)
        pool = [str(ip) for net in DOC_NETS for ip in ipaddress.ip_network(net).hosts()]
        ips = r.sample(pool, count)
        weights = [w for _, w in FAMILIES]
        self.items = [(i, ips[i], r.choices(FAMILIES, weights)[0][0], r.choice(PORTS),
                       r.choice([50, 75, 100]), r.uniform(0, 3 * 86400), r.choice(REPORTERS)) for i in range(count)]

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        now = datetime.now(timezone.utc)
        out = []
        for i, ip, malware, port, conf, age, reporter in self.items:
            seen = now - timedelta(seconds=age)
            out.append(Entity(
                id=f"demo:c2-{i}", layer="c2", label=f"{malware} · {ip}", observed_at=seen,
                attrs={"ip": ip, "port": port, "malware": malware, "malware_id": None,
                       "threat_type": "Botnet C&C", "confidence": conf, "first_seen": seen.isoformat(),
                       "reporter": reporter, "tags": ["demo"], "reference": None, "source_url": None},
            ))
        return out


class DemoKev(Collector):
    name, layer, keep_history = "demo", "kev", True

    def __init__(self, interval: float = 600, count: int = 24, seed: int = 5):
        self.interval = interval
        r = random.Random(seed)
        products = [("Acme", "VPN Gateway"), ("Contoso", "Mail Server"), ("Globex", "Firewall OS"),
                    ("Initech", "File Transfer"), ("Umbrella", "Web Portal"), ("Hooli", "Remote Desktop")]
        kinds = ["Inyección de comandos", "Evasión de autenticación", "Ejecución remota de código",
                 "Recorrido de directorios", "Deserialización insegura", "Escalada de privilegios"]
        self.items = [(f"DEMO-2026-{1000 + i}", *r.choice(products), r.choice(kinds), r.randint(0, 60),
                       r.random() < .3) for i in range(count)]

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        out = [Entity(id=f"demo:{cve}", layer="kev", label=f"{cve} · {vendor} {product}",
                      observed_at=today - timedelta(days=age),
                      attrs={"cve": cve, "vendor": vendor, "product": product, "name": f"{vendor} {product}: {kind}",
                             "description": f"{kind} en {vendor} {product} (dato simulado).",
                             "action": "Aplicar el parche del fabricante.", "due_date": None,
                             "ransomware": rw, "cwes": [], "source_url": None})
               for cve, vendor, product, kind, age, rw in self.items]
        return sorted(out, key=lambda e: e.observed_at, reverse=True)
