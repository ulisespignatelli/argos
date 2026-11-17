"""Exportacion de indicadores: CSV, lista de bloqueo y STIX 2.1 (estandar para compartir inteligencia)."""
import csv
import io
import uuid
from datetime import UTC, datetime

from app.domain.models import Entity

NAMESPACE = uuid.UUID("6f1c3c1e-6b8a-4c43-9f0b-0a7c2c1d5e11")   # ids deterministas: mismo IOC, mismo id
CSV_FIELDS = ["ip", "port", "malware", "confidence", "first_seen", "country_code", "country", "asn", "org",
              "source_url"]


def filter_c2(entities: list[Entity], malware: str | None = None, country: str | None = None) -> list[Entity]:
    out = entities
    if malware:
        out = [e for e in out if str(e.attrs.get("malware", "")).lower() == malware.lower()]
    if country:
        out = [e for e in out if str(e.attrs.get("country_code", "")).upper() == country.upper()]
    return out


def to_csv(entities: list[Entity]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for e in entities:
        w.writerow({k: _csv_safe(e.attrs.get(k)) for k in CSV_FIELDS})
    return buf.getvalue()


def _csv_safe(v) -> str:
    """Evita inyeccion de formulas al abrir el CSV en Excel (=, +, -, @ al inicio)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def to_blocklist(entities: list[Entity], generated: datetime | None = None) -> str:
    ips = sorted({str(e.attrs["ip"]) for e in entities if e.attrs.get("ip")})
    when = (generated or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = ["# ARGOS - lista de bloqueo de servidores C2", f"# Generada: {when}", f"# Total: {len(ips)} IPs",
              "# Fuente: ThreatFox (abuse.ch)", ""]
    return "\n".join(header + ips) + "\n"


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + ':' + key)}"


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def to_stix(entities: list[Entity], generated: datetime | None = None) -> dict:
    now = _ts(generated or datetime.now(UTC))
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", "argos"), "created": now,
                "modified": now, "name": "ARGOS", "identity_class": "system"}
    objects: list[dict] = [identity]
    malware_ids: dict[str, str] = {}
    for e in entities:
        fam = str(e.attrs.get("malware") or "")
        if fam and fam not in malware_ids:
            malware_ids[fam] = _sid("malware", fam.lower())
            objects.append({"type": "malware", "spec_version": "2.1", "id": malware_ids[fam], "created": now,
                            "modified": now, "name": fam, "is_family": True, "created_by_ref": identity["id"]})
    seen: set[str] = set()
    for e in entities:
        ip = str(e.attrs.get("ip") or "")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        kind = "ipv6-addr" if ":" in ip else "ipv4-addr"
        ind_id = _sid("indicator", ip)
        first = e.attrs.get("first_seen")
        valid_from = _ts(datetime.fromisoformat(first)) if first else _ts(e.observed_at)
        indicator = {"type": "indicator", "spec_version": "2.1", "id": ind_id, "created": now, "modified": now,
                     "name": f"C2 {e.attrs.get('malware') or ''}: {ip}".strip(),
                     "indicator_types": ["malicious-activity"],
                     "pattern": f"[{kind}:value = '{ip}']", "pattern_type": "stix", "valid_from": valid_from,
                     "created_by_ref": identity["id"]}
        if isinstance(e.attrs.get("confidence"), int):
            indicator["confidence"] = e.attrs["confidence"]
        if e.attrs.get("source_url"):
            indicator["external_references"] = [{"source_name": "ThreatFox", "url": e.attrs["source_url"]}]
        objects.append(indicator)
        fam = str(e.attrs.get("malware") or "")
        if fam in malware_ids:
            objects.append({"type": "relationship", "spec_version": "2.1", "id": _sid("relationship", ip + fam),
                            "created": now, "modified": now, "relationship_type": "indicates",
                            "source_ref": ind_id, "target_ref": malware_ids[fam], "created_by_ref": identity["id"]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
