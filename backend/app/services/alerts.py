"""Motor de alertas: compara cada actualizacion con la anterior y avisa lo que importa.

Reglas:
- familia de malware nunca vista antes (persistente: sobrevive a reinicios)
- C2 nuevo en un pais vigilado (ARGOS_WATCH_COUNTRIES)
- vulnerabilidad explotada nueva, con severidad alta si se usa en ransomware
- crecimiento brusco de los C2 de una familia
"""
import hashlib
import logging
from collections import Counter

from app.domain.models import Alert, Entity, utcnow
from app.services.hub import Hub
from app.storage.alerts import AlertRepository

log = logging.getLogger(__name__)


def _id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


class AlertEngine:
    def __init__(self, repo: AlertRepository, hub: Hub, watch_countries: tuple[str, ...] = ()):
        self.repo, self.hub, self.watch = repo, hub, set(watch_countries)

    async def on_snapshot(self, layer: str, previous: list[Entity] | None, current: list[Entity]) -> list[Alert]:
        alerts: list[Alert] = []
        if layer == "c2":
            alerts += await self._new_families(current)
            if previous is not None:
                alerts += self._watched_countries(previous, current)
                alerts += self._surges(previous, current)
        elif layer == "kev" and previous is not None:
            alerts += self._new_kev(previous, current)

        fresh = []
        for a in alerts:
            if await self.repo.add(a):
                fresh.append(a)
                await self.hub.broadcast({"type": "alert", "alert": a.model_dump(mode="json")})
        if fresh:
            log.info("%d alertas nuevas (%s)", len(fresh), layer)
        return fresh

    async def _new_families(self, current: list[Entity]) -> list[Alert]:
        families = {str(e.attrs["malware"]) for e in current if e.attrs.get("malware")}
        known = await self.repo.seen("malware")
        new = families - known
        await self.repo.mark_seen("malware", new, utcnow())
        if not known:   # primera ejecucion: se registra la linea de base sin alertar
            return []
        counts = Counter(str(e.attrs.get("malware")) for e in current)
        return [Alert(id=_id("new_family", f), at=utcnow(), severity="alta", rule="familia_nueva",
                      title=f"Familia nueva: {f}",
                      detail=f"Aparece por primera vez, con {counts[f]} servidor(es) C2.",
                      pivot_kind="malware", pivot_value=f) for f in sorted(new)]

    def _watched_countries(self, previous: list[Entity], current: list[Entity]) -> list[Alert]:
        if not self.watch:
            return []
        before = {e.id for e in previous}
        out = []
        for e in current:
            cc = str(e.attrs.get("country_code") or "")
            if e.id not in before and cc in self.watch:
                ip, fam = str(e.attrs.get("ip")), str(e.attrs.get("malware"))
                out.append(Alert(id=_id("watched", e.id), at=utcnow(), severity="alta", rule="pais_vigilado",
                                 title=f"C2 nuevo en {e.attrs.get('country') or cc}: {fam}",
                                 detail=f"{ip} ({e.attrs.get('org') or 'red desconocida'}).",
                                 pivot_kind="ip", pivot_value=ip))
        return out

    def _surges(self, previous: list[Entity], current: list[Entity]) -> list[Alert]:
        before = Counter(str(e.attrs.get("malware")) for e in previous)
        now = Counter(str(e.attrs.get("malware")) for e in current)
        out = []
        for fam, n in now.items():
            b = before.get(fam, 0)
            if b >= 5 and n - b >= 10 and n >= b * 1.5:
                out.append(Alert(id=_id("surge", fam, str(n // 10)), at=utcnow(), severity="media", rule="crecimiento",
                                 title=f"Crecimiento de {fam}", detail=f"Pasó de {b} a {n} servidores C2.",
                                 pivot_kind="malware", pivot_value=fam))
        return out

    def _new_kev(self, previous: list[Entity], current: list[Entity]) -> list[Alert]:
        before = {e.id for e in previous}
        out = []
        for e in current:
            if e.id in before:
                continue
            rw = e.attrs.get("ransomware") is True
            out.append(Alert(id=_id("kev", e.id), at=utcnow(), severity="alta" if rw else "media", rule="kev_nueva",
                             title=f"Explotada: {e.attrs.get('cve')}" + (" (ransomware)" if rw else ""),
                             detail=str(e.attrs.get("name") or e.label)))
        return out
