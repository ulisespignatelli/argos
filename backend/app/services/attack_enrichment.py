"""Enlaza cada indicador con MITRE ATT&CK: familia -> software -> grupos que lo usan -> tecnicas.

Asi un servidor C2 de Cobalt Strike queda vinculado a los actores que usan Cobalt Strike, y un ataque
de ransomware reivindicado por "akira" queda vinculado al grupo Akira y a sus tecnicas.
"""
from app.domain.models import Entity
from app.knowledge.kb import KnowledgeBase

MAX_NAMES = 12   # nombres para mostrar; la lista de IDs va completa para no perder vinculos


class AttackEnricher:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    def _candidates(self, e: Entity) -> list[str]:
        a = e.attrs
        if e.layer == "c2":
            return [str(a.get("malware") or "")]
        if e.layer == "incidents":
            return [str(a.get("group") or "")]
        if e.layer == "urls":
            return [str(t) for t in a.get("tags") or []]
        return []

    async def enrich(self, entities: list[Entity]) -> list[Entity]:
        out = []
        for e in entities:
            names = [n for n in self._candidates(e) if n]
            if not names:
                out.append(e)
                continue
            sid = gid_direct = None
            for n in names:
                sid = sid or self.kb.match_software(n)
                gid_direct = gid_direct or self.kb.match_group(n)
            actors: list[str] = []
            if gid_direct:
                actors.append(gid_direct)
            if sid:
                actors += [g for g in self.kb.software[sid]["groups"] if g not in actors]
            if not sid and not actors:
                out.append(e)
                continue
            extra = {"software_id": sid, "software": self.kb.software[sid]["name"] if sid else None,
                     "actors": actors, "actors_total": len(actors),
                     "actors_direct": [gid_direct] if gid_direct else [],
                     "actor_names": [self.kb.groups[g]["name"] for g in actors[:MAX_NAMES]]}
            # Origen atribuido: solo cuando el propio grupo (no un usuario mas del software) tiene pais segun MISP.
            if gid_direct and self.kb.groups[gid_direct]["country"]:
                cc = self.kb.groups[gid_direct]["country"]
                c = self.kb.country(cc)
                if c:
                    extra["origin"] = {"country": cc, "name": c["name"], "lat": c["lat"], "lon": c["lon"],
                                       "actor": gid_direct}
            out.append(e.model_copy(update={"attrs": {**e.attrs, **extra}}))
        return out
