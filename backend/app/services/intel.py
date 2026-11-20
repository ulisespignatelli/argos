"""Vistas de inteligencia sobre la cache: actores activos, perfil de actor y matriz ATT&CK dinamica.

"Activo" significa que hoy hay indicadores vivos (C2, URLs o ataques reivindicados) vinculados al actor
o a su software. La matriz no muestra lo que un actor usa "en general", sino lo que esta en uso esta semana.
"""
from collections import Counter, defaultdict

from app.domain.models import Entity
from app.knowledge.kb import KnowledgeBase

LAYER_KEYS = {"c2": "c2", "urls": "urls", "incidents": "incidents"}


def _by_layer(entities: list[Entity]) -> dict[str, list[Entity]]:
    out: dict[str, list[Entity]] = defaultdict(list)
    for e in entities:
        out[e.layer].append(e)
    return out


def active_actors(kb: KnowledgeBase, entities: list[Entity]) -> list[dict]:
    """Actividad de cada actor, separando lo atribuido directamente de lo inferido por el software que usa.

    La relevancia pondera por exclusividad: si una familia la usan 40 grupos (Cobalt Strike), cada indicador
    suma 1/40 a cada uno; si la usa un solo grupo, suma 1. Asi una herramienta compartida no infla el ranking.
    """
    counts: dict[str, Counter] = defaultdict(Counter)
    relevance: Counter = Counter()
    for e in entities:
        if e.layer not in LAYER_KEYS:
            continue
        direct = set(e.attrs.get("actors_direct") or [])
        sid = e.attrs.get("software_id")
        sharing = max(1, len(kb.software.get(sid, {}).get("groups", []))) if sid else 1
        for gid in e.attrs.get("actors") or []:
            counts[gid][e.layer] += 1
            if gid in direct:
                counts[gid]["direct"] += 1
                relevance[gid] += 1.0
            else:
                counts[gid]["via"] += 1
                relevance[gid] += 1.0 / sharing
    rows = []
    for gid in kb.groups:
        c = counts.get(gid, Counter())
        rows.append({**kb.actor_summary(gid), "active": {k: c.get(k, 0) for k in LAYER_KEYS},
                     "direct": c.get("direct", 0), "via_software": c.get("via", 0),
                     "relevance": round(relevance.get(gid, 0.0), 2),
                     "activity": c.get("direct", 0) + c.get("via", 0), "techniques": len(kb.groups[gid]["techniques"])})
    rows.sort(key=lambda r: (-r["relevance"], -r["activity"], r["name"].lower()))
    return rows


def actor_profile(kb: KnowledgeBase, gid: str, entities: list[Entity]) -> dict | None:
    if gid not in kb.groups:
        return None
    g = kb.groups[gid]
    linked = [e for e in entities if gid in (e.attrs.get("actors") or [])]
    per_sw = Counter(e.attrs.get("software_id") for e in linked if e.attrs.get("software_id"))
    software = [{"id": sid, "name": kb.software[sid]["name"], "type": kb.software[sid]["type"],
                 "active": per_sw.get(sid, 0)} for sid in g["software"] if sid in kb.software]
    software.sort(key=lambda s: (-s["active"], s["name"].lower()))
    incidents = sorted((e for e in linked if e.layer == "incidents"), key=lambda e: e.observed_at, reverse=True)
    return {**kb.actor_summary(gid), "description": g["description"],
            "techniques": [{"id": t, "name": kb.techniques[t]["name"], "tactics": kb.techniques[t]["tactics"]}
                           for t in g["techniques"] if t in kb.techniques],
            "software": software,
            "active": {k: sum(1 for e in linked if e.layer == k) for k in LAYER_KEYS},
            "direct": sum(1 for e in linked if gid in (e.attrs.get("actors_direct") or [])),
            "incidents": [e.model_dump(mode="json") for e in incidents[:25]]}


def _parents(kb: KnowledgeBase, techniques: list[str]) -> set[str]:
    """Una tecnica cuenta una sola vez aunque el software use varias de sus subtecnicas."""
    return {kb.technique_parent(t) for t in techniques}


def matrix(kb: KnowledgeBase, entities: list[Entity], scope: str = "active") -> dict:
    """Puntaje por tecnica (agrupando subtecnicas en su tecnica padre).

    - active: suma, por cada software con indicadores vivos, la cantidad de indicadores de ese software.
    - actor:G0032: 2 puntos si el grupo usa la tecnica directamente, +1 por cada software suyo que la usa.
    - software:S0154: 1 punto por tecnica del software.
    """
    score: Counter = Counter()
    contrib: dict[str, Counter] = defaultdict(Counter)
    label = "Indicadores activos"
    if scope == "active":
        per_sw = Counter(e.attrs.get("software_id") for e in entities if e.attrs.get("software_id"))
        for sid, n in per_sw.items():
            for p in _parents(kb, kb.software.get(sid, {}).get("techniques", [])):
                score[p] += n
                contrib[p][kb.software[sid]["name"]] += n
    elif scope.startswith("actor:") and scope[6:] in kb.groups:
        g = kb.groups[scope[6:]]
        label = g["name"]
        for p in _parents(kb, g["techniques"]):
            score[p] += 2
            contrib[p][g["name"]] += 2
        for sid in g["software"]:
            for p in _parents(kb, kb.software.get(sid, {}).get("techniques", [])):
                score[p] += 1
                contrib[p][kb.software[sid]["name"]] += 1
    elif scope.startswith("software:") and scope[9:] in kb.software:
        s = kb.software[scope[9:]]
        label = s["name"]
        for p in _parents(kb, s["techniques"]):
            score[p] += 1
            contrib[p][s["name"]] += 1
    else:
        raise ValueError(f"alcance desconocido: {scope}")

    tactics = []
    for tac in kb.tactics:
        techs = [{"id": tid, "name": t["name"], "score": score.get(tid, 0),
                  "top": [n for n, _ in contrib[tid].most_common(4)]}
                 for tid, t in kb.techniques.items() if not t["sub"] and tac["short"] in t["tactics"]]
        techs.sort(key=lambda x: (-x["score"], x["id"]))
        tactics.append({**tac, "techniques": techs, "used": sum(1 for x in techs if x["score"] > 0)})
    return {"scope": scope, "label": label, "max": max(score.values(), default=0), "tactics": tactics,
            "attack_version": kb.attack.get("attack_version")}
