"""Correlacion: dado un dato (IP, red, pais, familia o host), encuentra todo lo conectado.

Recorre lo que ya esta en la cache, asi que no consulta ninguna fuente. Es lo que permite
"pivotear": pasar de una IP a su red, de la red a otras IPs maliciosas, de ahi a sus familias...
"""
from collections import Counter

from app.domain.models import Entity, Pivot, PivotGroup, PivotItem

KINDS = {   # tipo de nodo -> atributo de la entidad
    "ip": "ip",
    "asn": "asn",
    "country": "country_code",
    "malware": "malware",
    "host": "host",
}
LABELS = {"ip": "IPs", "asn": "Redes (ASN)", "country": "Países", "malware": "Familias de malware", "host": "Hosts"}
MAX_ITEMS, MAX_ENTITIES = 15, 200


def pivot(entities: list[Entity], kind: str, value: str) -> Pivot:
    if kind not in KINDS:
        raise ValueError(f"tipo desconocido: {kind}")
    key = KINDS[kind]
    target = value.strip()
    match = [e for e in entities if _norm(kind, e.attrs.get(key)) == _norm(kind, target)]

    groups = []
    for other, other_key in KINDS.items():
        if other == kind:
            continue
        counts = Counter(str(e.attrs[other_key]) for e in match if e.attrs.get(other_key))
        if other == "host":   # un host que es una IP ya aparece en el grupo de IPs
            counts = Counter({h: n for h, n in counts.items() if not h[:1].isdigit()})
        if counts:
            groups.append(PivotGroup(kind=other, label=LABELS[other],
                                     items=[PivotItem(value=v, count=n) for v, n in counts.most_common(MAX_ITEMS)]))

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


def _norm(kind: str, v) -> str:
    s = str(v or "").strip()
    return s.upper() if kind in ("asn", "country") else s.lower() if kind in ("malware", "host") else s
