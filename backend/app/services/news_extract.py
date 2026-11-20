"""Convierte noticias y avisos (RSS/Atom) en eventos estructurados, solo con reglas: sin IA ni servicios pagos.

Etapas:
1. parse_feed: XML -> lista de NewsItem (titulo, enlace, fecha, resumen). El XML se lee con defusedxml.
2. Extractor.extract: CVE (regex), grupos y malware (diccionario MITRE ATT&CK + alias), paises (nombres en
   castellano e ingles, gentilicios) y tipo de ataque (palabras clave). Cada decision queda anotada en
   "reasons" para que el analista vea POR QUE se clasifico asi.
3. cluster: varias fuentes que hablan de lo mismo (mismo CVE, mismo actor y tipo, o titulo casi igual)
   se agrupan en un solo evento.
4. status: verificado (fuente oficial, 2+ medios o CVE en el catalogo KEV) o "1 fuente".

Del articulo solo se guarda el titulo, el enlace, la fecha y el medio: el resumen se usa para extraer
datos y se descarta (no se republica contenido ajeno).
"""
from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from defusedxml import ElementTree

from app.knowledge.kb import KnowledgeBase

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")

# Tipos de evento, en orden de prioridad para elegir el principal.
TYPES = ["policial", "cripto", "ransomware", "ddos", "ot", "estado_nacion", "fuga", "vulnerabilidad", "malware",
         "caida"]
TYPE_LABELS = {
    "policial": "Operación policial", "cripto": "Robo de criptoactivos", "ransomware": "Ransomware",
    "ddos": "Denegación de servicio (DDoS)", "ot": "Sabotaje OT / ICS", "estado_nacion": "Estado-nación",
    "fuga": "Intrusión / fuga de datos", "vulnerabilidad": "Vulnerabilidad crítica", "malware": "Malware / botnet",
    "caida": "Caída de servicio",
}


def _rx(*words: str) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(words) + r")", re.IGNORECASE)


KEYWORDS: dict[str, re.Pattern] = {
    "policial": _rx(r"arrest(?:ed|s)?\b", r"extradit", r"sentenced\b", r"takedown", r"taken down", r"dismantl",
                    r"seiz(?:ed|ure|es)\b", r"law enforcement", r"europol\b", r"interpol\b", r"indict",
                    r"pleads? guilty", r"charged\b", r"detenid", r"arrestad", r"desarticul", r"incautad", r"extraditad",
                    r"condenad", r"operaci[oó]n policial"),
    "cripto_base": _rx(r"crypto(?!min|jack)", r"bitcoin", r"ethereum", r"defi\b", r"blockchain", r"web3\b", r"cripto"),
    "cripto_robo": _rx(r"stolen", r"steal", r"theft", r"heist", r"drain", r"hack", r"exploit", r"robo\b",
                       r"robad", r"sustra"),
    "ransomware": _rx(r"ransomware", r"ransom\b", r"extortion", r"double extortion", r"leak site", r"extorsi[oó]n",
                      r"secuestro de datos"),
    "ddos": _rx(r"ddos\b", r"denial[- ]of[- ]service", r"denegaci[oó]n de servicio"),
    "ot": _rx(r"ics\b", r"scada", r"industrial control", r"\bplc\b", r"plcs\b", r"operational technology",
              r"\bot\b security", r"water (?:utilit|facilit|system|treatment)", r"sistemas? de control industrial",
              r"infraestructura cr[ií]tica"),
    "estado_nacion": _rx(r"state[- ]sponsored", r"nation[- ]state", r"state[- ]backed", r"state[- ]linked",
                         r"apt\d+", r"cyber[- ]?espionage", r"espionage", r"espionaje", r"patrocinad[oa]s? por"),
    "fuga": _rx(r"breach", r"data leak", r"leaked", r"exposed (?:data|records|database)", r"stolen data",
                r"records exposed", r"filtraci[oó]n", r"fuga de datos", r"datos expuestos", r"brecha",
                r"cyber[- ]?attack", r"hacked\b", r"intrusion", r"compromised", r"security incident",
                r"ciberataque", r"hackead", r"intrusi[oó]n", r"incidente de seguridad"),
    "explotado": _rx(r"exploited", r"actively exploit", r"active exploitation", r"exploitation attempts",
                     r"in the wild", r"zero[- ]day", r"0[- ]day",
                     r"under attack", r"explotad", r"d[ií]a cero", r"explotaci[oó]n activa"),
    "vulnerabilidad": _rx(r"vulnerabilit", r"flaws?\b", r"bugs?\b", r"zero[- ]days?", r"remote code execution",
                          r"\brce\b",
                          r"patch(?:es|ed)?\b", r"advisory", r"vulnerabilidad", r"ejecuci[oó]n remota",
                          r"actualizaci[oó]n de seguridad"),
    "malware": _rx(r"botnet", r"worm\b", r"gusano", r"stealer", r"trojan", r"troyano", r"backdoor", r"loader\b",
                   r"malware", r"infostealer", r"rootkit", r"wiper"),
    "caida": _rx(r"outage", r"service disruption", r"systems? down", r"knocked offline", r"ca[ií]da del servicio",
                 r"interrupci[oó]n del servicio", r"fuera de servicio"),
}

# Palabras que, cerca de un nombre de una sola palabra, confirman que se habla de un grupo o de malware
# (evita que "Royal", "Play" o "Snake" se lean como malware en cualquier titulo).
CONTEXT = _rx(r"ransomware", r"malware", r"botnet", r"gang", r"group", r"grupo", r"banda", r"hackers?", r"apt",
              r"actors?", r"operators?", r"affiliates?", r"backdoor", r"trojan", r"stealer", r"loader", r"variant",
              r"family", r"campaign", r"campaña", r"claims?", r"claimed", r"reivindic", r"attack", r"ataque",
              r"espionage", r"espionaje", r"linked", r"attributed", r"crew", r"threat",
              r"korea's", r"russia's", r"china's", r"iran's", r"stolen by", r"robad[oa]s? por")

# Nombres que usa la prensa y no figuran como alias en ATT&CK.
NEWS_ALIASES = {"Lazarus": "Lazarus Group", "LockBit": "LockBit 3.0", "ALPHV": "BlackCat", "Clop": "Cl0p",
                "RansomHub": "RansomHub", "Black Basta": "Black Basta", "Sandworm": "Sandworm Team",
                "Fancy Bear": "APT28", "Cozy Bear": "APT29", "Charming Kitten": "Magic Hound"}

# Gentilicios frecuentes en titulares (ingles y castellano).
DEMONYMS = {
    "russian": "RU", "chinese": "CN", "north korean": "KP", "iranian": "IR", "ukrainian": "UA", "israeli": "IL",
    "american": "US", "british": "GB", "brazilian": "BR", "argentine": "AR", "argentinian": "AR", "mexican": "MX",
    "chilean": "CL", "colombian": "CO", "peruvian": "PE", "german": "DE", "french": "FR", "spanish": "ES",
    "italian": "IT", "japanese": "JP", "south korean": "KR", "indian": "IN", "australian": "AU",
    "canadian": "CA", "dutch": "NL", "polish": "PL", "turkish": "TR", "vietnamese": "VN", "pakistani": "PK",
    "taiwanese": "TW", "belarusian": "BY", "ruso": "RU", "rusos": "RU", "chino": "CN", "chinos": "CN",
    "norcoreano": "KP", "norcoreanos": "KP", "iraní": "IR", "iraníes": "IR", "argentino": "AR",
    "argentina": "AR", "brasileño": "BR", "mexicano": "MX", "chileno": "CL", "colombiano": "CO",
}
# Un gentilicio seguido de estas palabras indica ORIGEN del atacante, no victima.
ORIGIN_AFTER = _rx(r"state", r"government[- ](?:backed|linked|sponsored|hackers)", r"hackers?", r"apt",
                   r"threat actors?", r"nation", r"backed", r"linked",
                   r"sponsored", r"spies", r"military", r"intelligence", r"cyber ?criminals?", r"gang", r"group",
                   r"operatives", r"espionage")
TARGETED = re.compile(r"(target\w*|against|attacks? on|hit|breach\w*|contra|atac\w*)\s+(?:the\s+|el\s+|la\s+)?$")
ORIGIN_BEFORE = _rx(r"hackers?", r"grupos?", r"actores", r"espías", r"ciberdelincuentes")
# Nombres de pais que tambien son nombres propios o estados: se ignoran.
AMBIGUOUS_COUNTRIES = {"Jordan", "Georgia", "Chad", "Jersey", "Guernsey", "Niger", "Dominica", "Isle of Man"}
# Paises cuyos grupos "hackers <gentilicio>" suelen ser estatales; igual se aclara "según la nota".
STATE_ORIGINS = {"RU", "CN", "KP", "IR", "BY"}
OFFICIAL_HINT = ("cisa", "cert", "incibe", "csirt", "ncsc", "europol")


@dataclass
class NewsItem:
    title: str
    url: str
    published: datetime
    source: str
    official: bool = False
    summary: str = ""
    default_type: str | None = None   # p. ej. el feed de avisos SCI de INCIBE es siempre OT


@dataclass
class Extracted:
    item: NewsItem
    types: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)     # IDs de grupo MITRE
    software: list[str] = field(default_factory=list)   # IDs de software MITRE (solo malware)
    victims: list[str] = field(default_factory=list)    # codigos de pais
    origins: list[str] = field(default_factory=list)    # codigos de pais
    exploited: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def primary(self) -> str | None:
        return next((t for t in self.types), None)


# --------------------------------------------------------------------------------------------- parseo


def _text(el) -> str:
    return html.unescape(TAG_RE.sub(" ", "".join(el.itertext()) if el is not None else "")).strip()


def _date(raw: str) -> datetime | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        d = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_feed(xml: bytes | str, source: str, official: bool = False, default_type: str | None = None,
               now: datetime | None = None) -> list[NewsItem]:
    """Lee RSS 2.0, RSS 1.0 (RDF) o Atom. Ignora entradas sin titulo, enlace o fecha valida."""
    root = ElementTree.fromstring(xml)
    now = now or datetime.now(UTC)
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        fields: dict[str, str] = {}
        for child in el:
            name = _local(child.tag)
            if name == "link":
                href = child.get("href")
                if href and child.get("rel", "alternate") == "alternate":
                    fields.setdefault("link", href.strip())
                elif (child.text or "").strip():
                    fields.setdefault("link", child.text.strip())
            elif name in ("title", "pubdate", "published", "updated", "date", "description", "summary", "content",
                          "encoded"):
                fields.setdefault(name, _text(child))
        title = re.sub(r"\s+", " ", fields.get("title", "")).strip()
        link = fields.get("link", "")
        when = next((d for k in ("pubdate", "published", "date", "updated") if (d := _date(fields.get(k, "")))), None)
        if not title or not link.startswith(("https://", "http://")) or not when:
            continue
        summary = " ".join(fields.get(k, "") for k in ("description", "summary", "content", "encoded"))
        out.append(NewsItem(title=title[:300], url=link, published=min(when, now), source=source, official=official,
                            summary=re.sub(r"\s+", " ", summary)[:4000], default_type=default_type))
    return out


# --------------------------------------------------------------------------------------------- extraccion


def _is_titleword(name: str) -> bool:
    """Una sola palabra, solo letras, con forma de palabra comun ("Royal", "Snake"): necesita contexto."""
    return " " not in name and name.isalpha() and (name.istitle() or name.islower())


class Extractor:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self._names = self._build_names()
        self._countries = self._build_countries()

    def _build_names(self) -> list[tuple[re.Pattern, str, str, bool]]:
        """(patron, tipo, id, necesita_contexto) para grupos y malware de ATT&CK."""
        seen: set[str] = set()
        out = []

        def add(name: str, kind: str, ident: str):
            name = name.strip()
            if len(name) < 4 or name.lower() in seen:
                return
            seen.add(name.lower())
            pat = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])")
            out.append((pat, kind, ident, _is_titleword(name)))

        for gid, g in self.kb.groups.items():
            for n in [g["name"], *g["aliases"]]:
                add(n, "actor", gid)
        for n, target in NEWS_ALIASES.items():
            if (gid := self.kb.match_group(target)):
                add(n, "actor", gid)
            elif (sid := self.kb.match_software(target)):
                add(n, "software", sid)
        for sid, s in self.kb.software.items():
            if s["type"] != "malware":
                continue
            for n in [s["name"], *s["aliases"]]:
                add(n, "software", sid)
        return out

    def _build_countries(self) -> list[tuple[re.Pattern, str]]:
        out = []
        for cc, c in self.kb.countries.items():
            names = {c["name"], *c.get("en", [])}
            for n in names:
                if n in AMBIGUOUS_COUNTRIES or len(n) < 4:
                    continue
                out.append((re.compile(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])"), cc))
        return out

    def _names_in(self, text: str) -> tuple[list[str], list[str], list[str]]:
        actors, software, reasons = [], [], []
        for pat, kind, ident, needs_context in self._names:
            m = pat.search(text)
            if not m:
                continue
            if needs_context:
                window = text[max(0, m.start() - 40): m.end() + 40]
                if not CONTEXT.search(window.replace(m.group(0), " ")):
                    continue
            target = actors if kind == "actor" else software
            if ident in target:
                continue
            target.append(ident)
            if kind == "actor":
                reasons.append(f"grupo: {self.kb.groups[ident]['name']} (MITRE {ident})")
            else:
                reasons.append(f"malware: {self.kb.software[ident]['name']} (MITRE {ident})")
        return actors, software, reasons

    def _places(self, text: str) -> tuple[list[str], list[str]]:
        victims, origins = [], []
        low = text.lower()
        for dem, cc in sorted(DEMONYMS.items(), key=lambda kv: -len(kv[0])):
            for m in re.finditer(r"(?<![\w-])" + re.escape(dem) + r"(?![\w-])", low):
                after, before = low[m.end(): m.end() + 30], low[max(0, m.start() - 25): m.start()]
                targeted = TARGETED.search(before)
                if not targeted and (ORIGIN_AFTER.match(after.strip()) or ORIGIN_BEFORE.search(before)):
                    origins.append(cc)
                elif not after.startswith(("-speaking", " speaking", " language", " authorities", " police")):
                    victims.append(cc)    # "Chilean hospital", "empresa argentina"
        for pat, cc in self._countries:
            for m in pat.finditer(text):
                around = text[max(0, m.start() - 25): m.end() + 25].lower()
                after = text[m.end(): m.end() + 3]
                attributed = re.search(r"(linked to|backed by|attributed to|stolen by|vinculad[oa]s? a|"
                                       r"atribuid[oa]s? a)", around) or after.startswith(("'s ", "’s "))
                (origins if attributed else victims).append(cc)
        if re.search(r"(?<![\w.])(?:US|U\.S\.)(?![\w])", text):   # "US" en mayusculas: Estados Unidos
            victims.append("US")
        origins = list(dict.fromkeys(origins))
        return [c for c in dict.fromkeys(victims) if c not in origins], origins

    def extract(self, item: NewsItem, kev_ids: set[str] | frozenset = frozenset()) -> Extracted:
        title, body = item.title, item.summary
        text = f"{title}. {body}"
        ex = Extracted(item=item)
        ex.cves = list(dict.fromkeys(f"CVE-{y}-{n}" for y, n in CVE_RE.findall(text)))[:12]
        ex.actors, ex.software, name_reasons = self._names_in(text)
        ex.victims, ex.origins = self._places(text)
        for gid in ex.actors:
            cc = self.kb.groups[gid]["country"]
            if cc and cc not in ex.origins:
                ex.origins.append(cc)
                ex.victims = [v for v in ex.victims if v != cc]

        def hit(key: str, where: str = text) -> str | None:
            m = KEYWORDS[key].search(where)
            return m.group(0).lower() if m else None

        types: dict[str, str] = {}
        # Las palabras del titulo pesan mas: un resumen puede mencionar de pasada otros temas.
        for key in ("policial", "ransomware", "ddos", "ot", "estado_nacion", "fuga", "malware", "caida"):
            w = hit(key, title) or (hit(key, body) if key in ("ransomware", "estado_nacion") else None)
            if w:
                types[key] = f"palabra: {w}"
        if hit("cripto_base", title) and hit("cripto_robo", text):
            types["cripto"] = f"palabra: {hit('cripto_base', title)} + {hit('cripto_robo', text)}"
        ex.exploited = bool(hit("explotado", text)) or any(c.upper() in kev_ids for c in ex.cves)
        if ex.cves or hit("vulnerabilidad", title):
            types["vulnerabilidad"] = (f"CVE: {', '.join(ex.cves[:3])}" if ex.cves
                                       else f"palabra: {hit('vulnerabilidad', title)}")
        if any(self.kb.groups[g]["country"] for g in ex.actors) and "estado_nacion" not in types:
            types["estado_nacion"] = "grupo con país atribuido (MITRE/MISP)"
        elif ex.origins and "estado_nacion" not in types and re.search(r"state|nation|government|estado", text, re.I):
            types["estado_nacion"] = "origen estatal mencionado"
        if ex.software and not types:
            types["malware"] = "malware identificado"
        if item.default_type and item.default_type not in types:
            types[item.default_type] = f"fuente: {item.source}"
        if ex.origins and "estado_nacion" not in types and set(ex.origins) & STATE_ORIGINS and \
                re.search(r"hackers?|apt|actors?|group|grupo|spies|esp[ií]as", text, re.I):
            names = ", ".join(self.kb.country(c)["name"] for c in ex.origins if self.kb.country(c))
            types["estado_nacion"] = f"atacantes vinculados a {names} según la nota"
        order = list(TYPES)
        if ex.exploited and "vulnerabilidad" in types:   # una vulnerabilidad explotada pesa mas que "breach"
            order.remove("vulnerabilidad")
            order.insert(order.index("fuga"), "vulnerabilidad")
        ex.types = [t for t in order if t in types]
        ex.reasons = [types[t] for t in ex.types] + name_reasons
        if ex.exploited:
            ex.reasons.append("explotación activa mencionada o CVE en catálogo KEV")
        return ex


# --------------------------------------------------------------------------------------------- agrupacion

STOP = set("the a an of in on for to and with by from at as is are new over after its via de la el los las en y "
           "del por con para un una que se al".split())


def _tokens(title: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9áéíóúñ]+", title.lower()) if w not in STOP and len(w) > 2}


def _similar(a: str, b: str) -> bool:
    ta, tb = _tokens(a), _tokens(b)
    return bool(ta and tb) and len(ta & tb) / len(ta | tb) >= 0.5


def cluster(items: list[Extracted], days: float = 4) -> list[list[Extracted]]:
    """Une notas que hablan del mismo hecho: mismo CVE, mismo actor/malware con el mismo tipo, o titulo casi igual."""
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int):
        parent[find(i)] = find(j)

    for i, a in enumerate(items):
        for j in range(i):
            b = items[j]
            same_cve = bool(set(a.cves) & set(b.cves))   # el mismo CVE es el mismo tema, sin limite de dias
            if not same_cve and abs((a.item.published - b.item.published).total_seconds()) > days * 86400:
                continue
            same_actor = bool(set(a.actors + a.software) & set(b.actors + b.software)) and a.primary == b.primary
            if same_cve or same_actor or _similar(a.item.title, b.item.title):
                union(i, j)
    groups: dict[int, list[Extracted]] = {}
    for i, x in enumerate(items):
        groups.setdefault(find(i), []).append(x)
    return list(groups.values())


def status(group: list[Extracted], kev_ids: set[str] | frozenset = frozenset()) -> tuple[str, str]:
    """('verificado' | 'una_fuente', motivo)."""
    outlets = {x.item.source for x in group}
    if any(x.item.official for x in group):
        return "verificado", "publicado por una fuente oficial"
    if any(c.upper() in kev_ids for x in group for c in x.cves):
        return "verificado", "CVE confirmado como explotado por CISA (KEV)"
    if len(outlets) >= 2:
        return "verificado", f"{len(outlets)} medios independientes"
    return "una_fuente", "por ahora, un solo medio"


def event_id(group: list[Extracted]) -> str:
    """ID estable: no cambia cuando se suman fuentes nuevas al mismo hecho."""
    first = min(group, key=lambda x: (x.item.published, x.item.url))
    key = (sorted({c for x in group for c in x.cves}) or [first.item.url])[0]
    return "evt:" + hashlib.sha256(key.encode()).hexdigest()[:16]


def is_official(source: str) -> bool:
    return any(h in source.lower() for h in OFFICIAL_HINT)
