"""Datos simulados para mostrar el sistema sin red ni claves.

- Las IPs salen de los rangos reservados para documentacion (RFC 5737) y los dominios de los
  reservados por RFC 2606 (.example): nunca se senala como maliciosa una IP o un dominio real.
- Los CVE son ficticios (prefijo DEMO).
- El mundo evoluciona en cada ciclo (aparecen C2, una familia nueva y CVE nuevos) para que
  el motor de alertas tenga algo que mostrar.
"""
import ipaddress
import random
from datetime import UTC, datetime, timedelta

import httpx

from app.collectors.base import Collector
from app.domain.models import Entity

FAMILIES = [("Cobalt Strike", 30), ("AsyncRAT", 16), ("Remcos", 14), ("Sliver", 10), ("QakBot", 8),
            ("DCRat", 8), ("Havoc", 6), ("Mythic", 5), ("Lumma Stealer", 9), ("Vidar", 6)]
NEW_FAMILY = "Pikabot"
PORTS = [443, 80, 8080, 8443, 4444, 2404, 7443, 50050, 31337, 1177]
REPORTERS = ["abuse_ch", "drb_ra", "Gi7w0rm", "malpulse", "ThreatHunter_ar"]
# 203.0.113.200-254 queda reservado para los C2 "argentinos" de la demo (ver geolocation/demo.py).
LOCAL_RANGE = range(200, 255)


def _doc_ips() -> tuple[list[str], list[str]]:
    general, local = [], []
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        for ip in ipaddress.ip_network(net).hosts():
            (local if net.startswith("203.") and ip.packed[-1] in LOCAL_RANGE else general).append(str(ip))
    return general, local


class DemoC2(Collector):
    name, layer, keep_history = "demo", "c2", True
    BASE, STEP = 130, 6

    def __init__(self, interval: float = 20, count: int = 160, seed: int = 21):
        self.interval, self.cycle = interval, 0
        r = random.Random(seed)
        general, local = _doc_ips()
        ips = r.sample(general, count - 4) + r.sample(local, 4)   # 4 C2 "argentinos" al final
        weights = [w for _, w in FAMILIES]
        self.items = []
        for i in range(count):
            family = r.choices(FAMILIES, weights)[0][0]
            if 140 <= i < 148:
                family = NEW_FAMILY           # familia que "aparece" a mitad de la demo
            self.items.append((i, ips[i], family, r.choice(PORTS), r.choice([50, 75, 100]),
                               r.uniform(0, 3 * 86400) if i < self.BASE else r.uniform(0, 1800), r.choice(REPORTERS)))

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        visible = min(len(self.items), self.BASE + self.STEP * self.cycle)
        self.cycle += 1
        now = datetime.now(UTC)
        out = []
        for i, ip, malware, port, conf, age, reporter in self.items[:visible]:
            seen = now - timedelta(seconds=age)
            out.append(Entity(
                id=f"demo:c2-{i}", layer="c2", label=f"{malware} · {ip}", observed_at=seen,
                attrs={"ip": ip, "port": port, "malware": malware, "malware_id": None,
                       "threat_type": "Botnet C&C", "confidence": conf, "first_seen": seen.isoformat(),
                       "reporter": reporter, "tags": ["demo"], "reference": None, "source_url": None},
            ))
        return out


class DemoUrls(Collector):
    """URLs de descarga de malware. Una parte se aloja en IPs que tambien son C2: correlacion visible."""
    name, layer, keep_history = "demo", "urls", True

    def __init__(self, interval: float = 30, count: int = 70, seed: int = 33, shared_from: DemoC2 | None = None):
        self.interval = interval
        r = random.Random(seed)
        general, _ = _doc_ips()
        shared = [it[1] for it in (shared_from.items[:DemoC2.BASE] if shared_from else [])]
        words = ["update", "cdn", "secure-login", "invoice", "drive-share", "patch", "files", "office-docs"]
        tlds = ["example", "example.com", "example.net", "example.org"]
        self.items = []
        for i in range(count):
            if i < 30:
                host = r.choice(shared) if shared and i < 18 else r.choice(general)
            else:
                host = f"{r.choice(words)}-{r.randint(10, 99)}.{r.choice(tlds)}"
            path = r.choice(["/bin.sh", "/payload.exe", "/i.ps1", "/mozi.m", "/doc.zip", "/x86"])
            self.items.append((i, host, path, r.choice(["online", "online", "offline"]),
                               r.choice([["elf", "mozi"], ["exe", "AsyncRAT"], ["ps1"], ["zip", "Lumma"]]),
                               r.uniform(0, 3 * 86400), r.choice(REPORTERS)))

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        now = datetime.now(UTC)
        out = []
        for i, host, path, status, tags, age, reporter in self.items:
            attrs = {"url": f"http://{host}{path}", "host": host, "status": status, "threat": "malware_download",
                     "tags": tags, "reporter": reporter, "source_url": None}
            if host[0].isdigit():
                attrs["ip"] = host
            out.append(Entity(id=f"demo:url-{i}", layer="urls", label=host,
                              observed_at=now - timedelta(seconds=age), attrs=attrs))
        return out


class DemoKev(Collector):
    name, layer, keep_history = "demo", "kev", True
    BASE = 20

    def __init__(self, interval: float = 45, count: int = 24, seed: int = 5):
        self.interval, self.cycle = interval, 0
        r = random.Random(seed)
        products = [("Acme", "VPN Gateway"), ("Contoso", "Mail Server"), ("Globex", "Firewall OS"),
                    ("Initech", "File Transfer"), ("Umbrella", "Web Portal"), ("Hooli", "Remote Desktop")]
        kinds = ["Inyección de comandos", "Evasión de autenticación", "Ejecución remota de código",
                 "Recorrido de directorios", "Deserialización insegura", "Escalada de privilegios"]
        self.items = []
        for i in range(count):
            late = i >= self.BASE   # los ultimos aparecen durante la demo, recien publicados
            self.items.append((f"DEMO-2026-{1000 + i}", *r.choice(products), r.choice(kinds),
                               0 if late else r.randint(1, 60), late or r.random() < .3))

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        visible = min(len(self.items), self.BASE + self.cycle)
        self.cycle += 1
        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        out = [Entity(id=f"demo:{cve}", layer="kev", label=f"{cve} · {vendor} {product}",
                      observed_at=today - timedelta(days=age),
                      attrs={"cve": cve, "vendor": vendor, "product": product, "name": f"{vendor} {product}: {kind}",
                             "description": f"{kind} en {vendor} {product} (dato simulado).",
                             "action": "Aplicar el parche del fabricante.", "due_date": None,
                             "ransomware": rw, "cwes": [], "source_url": None})
               for cve, vendor, product, kind, age, rw in self.items[:visible]]
        return sorted(out, key=lambda e: e.observed_at, reverse=True)
