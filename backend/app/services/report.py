"""Informe semanal en Markdown, listo para publicar o enviar."""
from collections import Counter
from datetime import UTC, datetime, timedelta

from app.domain.models import Alert, Entity
from app.knowledge.kb import LATAM, KnowledgeBase


def weekly(kb: KnowledgeBase, current: dict[str, list[Entity]], incidents_week: list[Entity], alerts: list[Alert],
           mode: str) -> str:
    now = datetime.now(UTC)
    since = now - timedelta(days=7)
    c2, urls, kev = current.get("c2", []), current.get("urls", []), current.get("kev", [])
    inc = [e for e in incidents_week if e.observed_at >= since]
    demo = " · **datos simulados (modo demo)**" if mode == "demo" else ""
    kev_week = [e for e in kev if e.observed_at >= since]
    lines = ["# ARGOS · Informe semanal de amenazas",
             f"_Semana del {since:%d/%m/%Y} al {now:%d/%m/%Y}_{demo}",
             "", "## Resumen", "",
             f"- **{len({e.attrs.get('ip') for e in c2})}** servidores C2 activos de "
             f"**{len({e.attrs.get('malware') for e in c2})}** familias de malware.",
             f"- **{sum(1 for e in urls if e.attrs.get('status') == 'online')}** URLs de malware activas.",
             f"- **{len(inc)}** víctimas de ransomware reivindicadas por los grupos (no confirmadas).",
             f"- **{len(kev_week)}** vulnerabilidades sumadas al catálogo de explotadas de CISA, "
             f"**{sum(1 for e in kev_week if e.attrs.get('ransomware'))}** usadas por ransomware.",
             "", "## Familias de malware con más infraestructura", "", "| Familia | Servidores C2 |", "|---|---|"]
    for fam, n in Counter(e.attrs.get("malware") for e in c2).most_common(8):
        lines.append(f"| {fam} | {n} |")
    lines += ["", "## Grupos de ransomware más activos", "", "| Grupo | Víctimas reivindicadas |", "|---|---|"]
    for g, n in Counter(e.attrs.get("group") for e in inc).most_common(8):
        lines.append(f"| {g} | {n} |")
    latam = [e for e in inc if e.attrs.get("country_code") in LATAM]
    lines += ["", "## Latinoamérica", ""]
    if latam:
        lines.append(f"{len(latam)} víctimas reivindicadas en la región:")
        lines.append("")
        for cc, n in Counter(e.attrs.get("country_code") for e in latam).most_common():
            lines.append(f"- {kb.country(cc)['name'] if kb.country(cc) else cc}: {n}")
    else:
        lines.append("Sin víctimas reivindicadas en la región esta semana.")
    techs = Counter()
    for e in c2 + inc:
        sid = e.attrs.get("software_id")
        for p in {kb.technique_parent(t) for t in (kb.software.get(sid, {}).get("techniques", []) if sid else [])}:
            techs[p] += 1
    lines += ["", "## Técnicas MITRE ATT&CK más presentes en la actividad de la semana", "",
              "| Técnica | Nombre | Peso |", "|---|---|---|"]
    for tid, n in techs.most_common(10):
        lines.append(f"| [{tid}](https://attack.mitre.org/techniques/{tid}/) | {kb.techniques[tid]['name']} | {n} |")
    events = sorted((e for e in current.get("events", []) if e.observed_at >= since),
                    key=lambda e: (e.attrs.get("status") != "verificado", -int(e.attrs.get("n_sources") or 0)))
    lines += ["", "## Eventos de la semana (avisos oficiales y prensa especializada)", ""]
    for e in events[:12]:
        a = e.attrs
        mark = "✔ verificado" if a.get("status") == "verificado" else "1 fuente"
        lines.append(f"- **{a.get('kind_label')}** · [{a.get('title')}]({a.get('source_url')}) · {mark}"
                     f" · {a.get('n_sources')} fuente(s)")
    if not events:
        lines.append("Sin eventos registrados esta semana.")
    high = [a for a in alerts if a.severity == "alta" and a.at >= since]
    lines += ["", "## Alertas de severidad alta", ""]
    lines += [f"- {a.at:%d/%m %H:%M} · {a.title}" for a in high[:15]] or ["Sin alertas de severidad alta."]
    lines += ["", "---",
              "Fuentes: ThreatFox y URLhaus (abuse.ch), CISA KEV, ransomware.live, MITRE ATT&CK®, MISP Galaxy, "
              "avisos de CISA, CERT-EU e INCIBE-CERT y prensa especializada (solo título y enlace).",
              "Las reivindicaciones de ransomware las publican los propios grupos y pueden ser falsas o exageradas.",
              f"Generado por ARGOS el {now:%d/%m/%Y %H:%M} UTC."]
    return "\n".join(lines) + "\n"
