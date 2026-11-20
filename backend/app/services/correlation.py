"""Correlacion: dado un dato (IP, red, pais, familia, host o actor), encuentra todo lo conectado.

Recorre lo que ya esta en la cache, asi que no consulta ninguna fuente. Es lo que permite
"pivotear": pasar de una IP a su red, de la red a otras IPs maliciosas, de ahi a sus familias y actores...
"""
from collections import Counter
from collections.abc import Callable

from app.domain.models import Entity, Pivot, PivotGroup, PivotItem

KINDS = {   # tipo de nodo -> atributos de la entidad (el primero que exista)
    "ip": ("ip",),
    "asn": ("asn",),
    "country": ("country_code",),
    "malware": ("malware", "group"),    # familia del C2, o grupo de ransomware de un ataque
    "host": ("host",),
    "actor": ("actors",),               # lista de grupos de ATT&CK
}
LABELS = {"ip": "IPs", "asn": "Redes (ASN)", "country": "Países", "malware": "Familias y grupos de ransomware",
          "host": "Hosts", "actor": "Actores (MITRE ATT&CK)"}
MAX_ITEMS, MAX_ENTITIES = 15, 200


def _values(e: Entity, kind: str) -> list[str]:
    for key in KINDS[kind]:
        v = e.attrs.get(key)
        if v:
            return [str(x) for x in v] if isinstance(v, list) else [str(v)]
    return []


def _norm(kind: str, v: str) -> str:
    s = str(v or "").strip()
    return s.upper() if kind in ("asn", "country", "actor") else s.lower() if kind in ("malware", "host") else s


def pivot(entities: list[Entity], kind: str, value: str,
          label: Callable[[str, str], str | None] = lambda k, v: None) -> Pivot:
    if kind not in KINDS:
        raise ValueError(f"tipo desconocido: {kind}")
    target = value.strip()
    t = _norm(kind, target)
    match = [e for e in entities if t in {_norm(kind, v) for v in _values(e, kind)}]

    groups = []
    for other in KINDS:
        if other == kind:
            continue
        counts = Counter(v for e in match for v in set(_values(e, other)))
        if other == "host":   # un host que es una IP ya aparece en el grupo de IPs
            counts = Counter({h: n for h, n in counts.items() if not h[:1].isdigit()})
        if counts:
            items = [PivotItem(value=v, count=n, label=label(other, v)) for v, n in counts.most_common(MAX_ITEMS)]
            groups.append(PivotGroup(kind=other, label=LABELS[other], items=items))

    # Segundo grado: otras IPs maliciosas en la misma red que la IP investigada.
    if kind == "ip":
        asns = {e.attrs.get("asn") for e in match if e.attrs.get("asn")}
        if asns:
            neighbors = Counter(e.attrs["ip"] for e in entities
                                if e.attrs.get("asn") in asns and e.attrs.get("ip") and e.attrs["ip"] != target)
            if neighbors:
                items = [PivotItem(value=v, count=n) for v, n in neighbors.most_common(MAX_ITEMS)]
                groups.append(PivotGroup(kind="ip", label="IPs vecinas en la misma red", items=items))

    match.sort(key=lambda e: e.observed_at, reverse=True)
    return Pivot(kind=kind, value=target, total=len(match), groups=groups, entities=match[:MAX_ENTITIES])
