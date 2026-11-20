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


DEMO_GROUPS = [("akira", 14), ("qilin", 12), ("lockbit3", 9), ("play", 8), ("ransomhub", 7), ("medusa", 5),
               ("blackbasta", 4), ("safepay", 6), ("dragonforce", 4), ("Wizard Spider", 4)]
DEMO_VICTIMS = ["Logística", "Agroindustrias", "Clínica", "Constructora", "Distribuidora", "Municipalidad",
                "Transportes", "Laboratorios", "Metalúrgica", "Cooperativa", "Estudio Jurídico", "Hotelera",
                "Textil", "Software"]
DEMO_SECTORS = ["Salud", "Manufactura", "Gobierno", "Transporte", "Educación", "Finanzas", "Comercio", "Tecnología"]
DEMO_COUNTRIES = [("AR", 8), ("BR", 10), ("MX", 8), ("CL", 5), ("CO", 5), ("PE", 3), ("UY", 2), ("US", 14), ("ES", 6),
                  ("DE", 5), ("IT", 5), ("FR", 4), ("GB", 4), ("CA", 3), ("AU", 2), ("IN", 2)]


class DemoIncidents(Collector):
    """Victimas ficticias ("... Demo SA") reivindicadas por grupos reales, con fuerte presencia de Latinoamerica."""
    name, layer, keep_history = "demo", "incidents", True
    BASE, STEP = 70, 3

    def __init__(self, countries: dict, interval: float = 25, count: int = 85, seed: int = 9):
        from app.collectors.ransomware_live import place
        self.interval, self.cycle, self.countries, self._place = interval, 0, countries, place
        r = random.Random(seed)
        g, gw = zip(*DEMO_GROUPS, strict=True)
        c, cw = zip(*DEMO_COUNTRIES, strict=True)
        self.items = []
        for i in range(count):
            late = i >= self.BASE
            cc = "AR" if late and i % 3 == 0 else r.choices(c, cw)[0]   # algunas victimas argentinas aparecen en vivo
            self.items.append((i, f"{r.choice(DEMO_VICTIMS)} Demo {chr(65 + i % 26)}{i} SA", r.choices(g, gw)[0], cc,
                               r.choice(DEMO_SECTORS), r.uniform(0, 600) if late else r.uniform(0, 7 * 86400)))

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        visible = min(len(self.items), self.BASE + self.STEP * self.cycle)
        self.cycle += 1
        now = datetime.now(UTC)
        out = []
        for i, victim, group, cc, sector, age in self.items[:visible]:
            lat, lon = self._place(cc, f"demo-{i}", self.countries)
            out.append(Entity(id=f"demo:inc-{i}", layer="incidents", lat=lat, lon=lon, label=victim,
                              observed_at=now - timedelta(seconds=age),
                              attrs={"kind": "ransomware", "victim": victim, "group": group, "claim": True,
                                     "sector": sector, "country_code": cc,
                                     "country": self.countries.get(cc, {}).get("name"),
                                     "website": None, "attack_date": None, "source_url": None}))
        return out


# Noticias ficticias: medios inventados (.example), CVE del año 2099 y empresas "Demo". Pasan por el mismo
# extractor que las reales, asi la demo ejercita la clasificacion, la agrupacion y la verificacion.
DEMO_NEWS = [
    ("Boletín Oficial Demo", True, "[DEMO] CISA-like advisory: CVE-2099-0101 in Demo Gateway actively exploited", 2),
    ("Prensa Demo", False, "[DEMO] Hackers exploit CVE-2099-0101 zero-day in Demo Gateway appliances", 1.5),
    ("Diario Seguro Demo", False, "[DEMO] Akira ransomware gang claims attack on Logística Demo SA in Chile", 6),
    ("Prensa Demo", False, "[DEMO] Akira ransomware hits Chilean logistics firm Logística Demo SA", 5),
    ("Prensa Demo", False, "[DEMO] North Korean hackers linked to crypto heist at fictional DemoExchange", 30),
    ("Boletín Oficial Demo", True, "[DEMO] Europol: police arrest 4 in takedown of demo botnet in Spain", 20),
    ("Diario Seguro Demo", False, "[DEMO] DDoS attack disrupts government portals in Argentina", 9),
    ("Prensa Demo", False, "[DEMO] Data breach at Retail Demo SA exposes customer records in Mexico", 40),
    ("Boletín SCI Demo", True, "[DEMO] Vulnerabilities in Demo PLC firmware affect industrial control systems", 50),
    ("Diario Seguro Demo", False, "[DEMO] Russian state-sponsored group Sandworm Team targets energy grid in Ukraine",
     70),
    ("Prensa Demo", False, "[DEMO] New Lumma Stealer campaign spreads through fake updates in Brazil", 80),
    ("Diario Seguro Demo", False, "[DEMO] Qilin ransomware claims hospital attack in Colombia", 0.4),
    ("Boletín Oficial Demo", True, "[DEMO] Critical vulnerability CVE-2099-0202 in Demo Mail Server", 0.2),
]


class DemoNews(Collector):
    name, layer, keep_history = "demo", "events", True
    BASE, STEP = 11, 1

    def __init__(self, kb, interval: float = 30):
        from app.services.news_extract import Extractor
        self.kb, self.interval, self.cycle = kb, interval, 0
        self.extractor = Extractor(kb)

    async def fetch(self, client: httpx.AsyncClient) -> list[Entity]:
        from app.collectors.news import build_events
        from app.services.news_extract import NewsItem
        visible = min(len(DEMO_NEWS), self.BASE + self.STEP * self.cycle)
        self.cycle += 1
        now = datetime.now(UTC)
        items = [NewsItem(title=t, url=f"https://news{i}.example/nota-{i}", published=now - timedelta(hours=h),
                          source=src, official=off, default_type="ot" if "SCI" in src else None)
                 for i, (src, off, t, h) in enumerate(DEMO_NEWS[:visible])]
        return build_events(self.extractor, self.kb, items, frozenset({"CVE-2099-0101"}), now=now)
