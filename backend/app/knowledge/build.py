"""Genera el indice compacto de conocimiento a partir de fuentes abiertas.

    python -m app.knowledge.build            # descarga y regenera
    python -m app.knowledge.build --from DIR # usa archivos ya descargados

Fuentes:
- MITRE ATT&CK Enterprise (STIX 2.1): tacticas, tecnicas, grupos, software y sus relaciones.
  (c) The MITRE Corporation. Uso libre con atribucion: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
- MISP Galaxy, threat-actor (CC0 1.0): pais atribuido y alias de los actores.

El resultado (attack_index.json) se versiona en el repo para que ARGOS funcione sin red.
"""
import argparse
import json
import pathlib
import re
import urllib.request

ATTACK_INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
MISP_ACTORS = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
OUT = pathlib.Path(__file__).parent / "data" / "attack_index.json"

TACTICS_ES = {
    "reconnaissance": "Reconocimiento", "resource-development": "Desarrollo de recursos",
    "initial-access": "Acceso inicial", "execution": "Ejecución", "persistence": "Persistencia",
    "privilege-escalation": "Escalada de privilegios", "stealth": "Sigilo",
    "defense-impairment": "Debilitamiento de defensas",
    "defense-evasion": "Evasión de defensas", "credential-access": "Acceso a credenciales",
    "discovery": "Descubrimiento",
    "lateral-movement": "Movimiento lateral", "collection": "Recolección", "command-and-control": "Comando y control",
    "exfiltration": "Exfiltración", "impact": "Impacto",
}


def _get(url: str) -> dict:
    if not url.startswith("https://raw.githubusercontent.com/"):
        raise ValueError(f"origen no permitido: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "argos-osint"})  # noqa: S310 (origen validado arriba)
    with urllib.request.urlopen(req, timeout=180) as r:   # noqa: S310
        return json.loads(r.read())


def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _first_sentences(text: str, limit: int = 420) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)   # enlaces markdown -> texto
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    return (cut[: cut.rfind(". ") + 1] if ". " in cut else cut.rsplit(" ", 1)[0] + "…").strip()


def build(attack: dict, misp: dict, version: str = "?") -> dict:
    objs = [o for o in attack["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in objs}
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    tactics = []
    for ref in matrix["tactic_refs"]:
        t = by_id[ref]
        short = t["x_mitre_shortname"]
        tactics.append({"id": _ext_id(t), "short": short, "name": t["name"],
                        "name_es": TACTICS_ES.get(short, t["name"])})

    techniques = {}
    for o in objs:
        if o["type"] != "attack-pattern" or not _ext_id(o):
            continue
        tid = _ext_id(o)
        techniques[tid] = {"name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                                         if p.get("kill_chain_name") == "mitre-attack"],
                           "sub": bool(o.get("x_mitre_is_subtechnique"))}

    groups, software = {}, {}
    for o in objs:
        eid = _ext_id(o)
        if not eid:
            continue
        if o["type"] == "intrusion-set":
            groups[eid] = {"name": o["name"], "aliases": [a for a in o.get("aliases", []) if a != o["name"]],
                           "description": _first_sentences(o.get("description", "")),
                           "techniques": set(), "software": set(), "country": None, "sponsor": None}
        elif o["type"] in ("malware", "tool"):
            software[eid] = {"name": o["name"], "type": o["type"],
                             "aliases": [a for a in o.get("x_mitre_aliases", []) if a != o["name"]],
                             "techniques": set(), "groups": set()}

    for r in objs:
        if r["type"] != "relationship" or r.get("relationship_type") != "uses":
            continue
        src, dst = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
        if not src or not dst:
            continue
        s_id, d_id = _ext_id(src), _ext_id(dst)
        if src["type"] == "intrusion-set" and s_id in groups:
            if dst["type"] == "attack-pattern" and d_id in techniques:
                groups[s_id]["techniques"].add(d_id)
            elif dst["type"] in ("malware", "tool") and d_id in software:
                groups[s_id]["software"].add(d_id)
                software[d_id]["groups"].add(s_id)
        elif (src["type"] in ("malware", "tool") and s_id in software
              and dst["type"] == "attack-pattern" and d_id in techniques):
            software[s_id]["techniques"].add(d_id)

    # MISP: pais y patrocinador sospechado. Primero por enlace explicito a ATT&CK, despues por nombre o alias.
    name_index = {}
    for gid, g in groups.items():
        for n in [g["name"], *g["aliases"]]:
            name_index.setdefault(norm(n), gid)
    matched = 0
    for v in misp.get("values", []):
        meta = v.get("meta", {})
        country = meta.get("country")
        if not country:
            continue
        gid = None
        for ref in meta.get("refs", []):
            m = re.search(r"attack\.mitre\.org/groups/(G\d{4})", ref)
            if m and m.group(1) in groups:
                gid = m.group(1)
                break
        if not gid:
            for n in [v.get("value", ""), *meta.get("synonyms", [])]:
                gid = name_index.get(norm(n))
                if gid:
                    break
        if gid and not groups[gid]["country"]:
            sponsor = meta.get("cfr-suspected-state-sponsor")
            groups[gid]["country"] = str(country).upper()[:2]
            groups[gid]["sponsor"] = sponsor if isinstance(sponsor, str) else None
            matched += 1

    for g in groups.values():
        g["techniques"], g["software"] = sorted(g["techniques"]), sorted(g["software"])
    for s in software.values():
        s["techniques"], s["groups"] = sorted(s["techniques"]), sorted(s["groups"])
    return {"attack_version": version, "tactics": tactics,
            "techniques": techniques, "groups": groups, "software": software,
            "stats": {"groups": len(groups), "software": len(software), "techniques": len(techniques),
                      "groups_with_country": matched}}


def norm(name: str) -> str:
    """Normaliza nombres para comparar: 'Lumma Stealer', 'LummaStealer' y 'lumma-stealer' son lo mismo."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", help="carpeta con enterprise.json y misp-actors.json ya descargados")
    ap.add_argument("--version", default="?", help="version de ATT&CK de los archivos locales")
    args = ap.parse_args()
    if args.src:
        d = pathlib.Path(args.src)
        attack, misp = json.loads((d / "enterprise.json").read_text()), json.loads((d / "misp-actors.json").read_text())
        version = args.version
    else:
        index = _get(ATTACK_INDEX)
        latest = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")["versions"][0]
        url, version = latest["url"], latest["version"]
        attack, misp = _get(url), _get(MISP_ACTORS)
    data = build(attack, misp, version)
    OUT.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    print(f"{OUT} · ATT&CK {data['attack_version']} · {data['stats']}")


if __name__ == "__main__":
    main()
