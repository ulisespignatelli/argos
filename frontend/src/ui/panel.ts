import { api } from "../api/client";
import { eventAttrs, str, type Alert, type Entity } from "../api/types";
import { CATEGORIES, CATEGORY, categoryCounts, on, sectorEs, visibleEvents, visibleIncidents, WINDOWS, windowed } from "../state/selectors";
import type { HeatMode, State, Store, TimeWindow } from "../state/store";
import { dayDate, familyColor, guessKind, LATAM, safeLink, timeAgo } from "../util/format";
import { el } from "./dom";

const SOURCES: { id: string; label: string }[] = [
  { id: "incidents", label: "Ransomware · ransomware.live o RansomLook" },
  { id: "c2", label: "Servidores C2 · ThreatFox" },
  { id: "urls", label: "URLs de malware · URLhaus" },
  { id: "kev", label: "Vulnerabilidades explotadas · CISA KEV" },
  { id: "events", label: "Avisos y noticias · CISA, CERT-EU, INCIBE y prensa" },
];
const HEAT: [HeatMode, string][] = [["off", "Apagado"], ["hex", "Hexágonos"], ["country", "Por país"]];
type Tab = "alerts" | "events" | "attacks" | "families" | "kev";

/** Panel izquierdo: fuentes, region, busqueda, exportacion y pestañas. */
export function mountPanel(root: HTMLElement, store: Store, focusEntity: (e: Entity) => void): void {
  const modeBadge = el("div", "badge", "DATOS SIMULADOS · víctimas, IPs y dominios ficticios");

  // Capas por tipo de ataque: un interruptor y un contador por tipo.
  const cats = el("div", "cats");
  const catRow = new Map<string, { row: HTMLElement; n: HTMLElement }>();
  cats.append(el("h2", "cats-h", "Capas · tipo de ataque"));
  for (const c of CATEGORIES) {
    const row = el("button", "cat");
    row.type = "button";
    row.title = c.hint;
    row.style.setProperty("--c", c.color);
    const n = el("span", "cat-n", "0");
    row.append(el("span", "cat-dot"), el("span", "cat-l", c.label), n);
    row.addEventListener("click", () => store.toggle(c.id, !on(store.get(), c.id)));
    if (c.id === "c2") cats.append(el("div", "cats-sep"));
    cats.append(row);
    catRow.set(c.id, { row, n });
  }
  const heat = el("div", "seg seg-heat");
  const heatBtn = new Map<HeatMode, HTMLButtonElement>();
  for (const [k, label] of HEAT) {
    const b = el("button", "", label);
    b.type = "button";
    b.addEventListener("click", () => store.set({ heat: k }));
    heat.append(b);
    heatBtn.set(k, b);
  }
  const heatRow = el("div", "heat-row");
  heatRow.append(el("span", "", "Mapa de calor"), heat);
  cats.append(heatRow);

  // Estado de las fuentes (plegable)
  const sources = el("details", "sources");
  const sourcesSum = el("summary", "", "Fuentes");
  sources.append(sourcesSum);
  const sourceStatus = new Map<string, HTMLElement>();
  for (const src of SOURCES) {
    const row = el("div", "source");
    const status = el("span", "status", "esperando datos…");
    row.append(el("span", "name", src.label), status);
    sources.append(row);
    sourceStatus.set(src.id, status);
  }

  // Region
  const region = el("div", "seg");
  const regionBtn = { world: el("button", "", "Mundo"), latam: el("button", "", "Latinoamérica") };
  for (const [k, b] of Object.entries(regionBtn) as ["world" | "latam", HTMLButtonElement][]) {
    b.type = "button";
    b.addEventListener("click", () => store.set({ region: k }));
    region.append(b);
  }

  // Ventana de tiempo
  const win = el("div", "seg seg-time");
  const winBtn = new Map<TimeWindow, HTMLButtonElement>();
  for (const [k, w] of Object.entries(WINDOWS) as [TimeWindow, (typeof WINDOWS)[TimeWindow]][]) {
    const b = el("button", "", w.label);
    b.type = "button";
    b.title = `Ataques y vulnerabilidades de ${w.long}`;
    b.addEventListener("click", () => store.set({ timeWindow: k }));
    win.append(b);
    winBtn.set(k, b);
  }

  // Sectores
  const sectors = el("div", "sectors");

  // Aviso de clave faltante (ThreatFox y URLhaus)
  const keyHelp = el("div", "keyhelp");
  keyHelp.hidden = true;
  keyHelp.append(el("b", "", "Falta la clave de abuse.ch"),
    el("p", "", "Sin ella no hay servidores C2 ni URLs de malware. Es gratis: entrá a auth.abuse.ch, iniciá sesión "
      + "con GitHub o Google, generá la Auth-Key en tu perfil y pegala en backend\\.env como ARGOS_ABUSECH_KEY. "
      + "Después reiniciá el backend."));

  // Busqueda: escribir resalta; Enter abre una investigacion.
  const search = el("input", "search");
  search.type = "search";
  search.placeholder = "IP, ASN, país, grupo, actor (G0032)… · Enter";
  search.addEventListener("input", () => store.set({ search: search.value }));
  search.addEventListener("keydown", (ev) => {
    const v = search.value.trim();
    if (ev.key !== "Enter" || !v) return;
    const kind = guessKind(v);
    store.investigate(kind, ["country", "asn", "actor"].includes(kind) ? v.toUpperCase() : v, true);
  });

  // Exportacion
  const exp = el("div", "export");
  exp.append(el("span", "", "Exportar C2:"));
  for (const [fmt, text] of [["c2.csv", "CSV"], ["blocklist.txt", "Bloqueo"], ["stix.json", "STIX 2.1"]] as const) {
    const a = el("a", "", text);
    a.href = api.exportUrl(fmt);
    a.setAttribute("download", "");
    exp.append(a);
  }

  // Pestanas
  const tabs = el("div", "tabs");
  const tabBtn: Record<Tab, HTMLButtonElement> = {
    alerts: el("button", "", "Alertas"), events: el("button", "", "Eventos"), attacks: el("button", "", "Ataques"),
    families: el("button", "", "Familias"), kev: el("button", "", "CVE"),
  };
  const body = el("div", "scroll");
  let tab: Tab = "alerts";
  for (const [k, b] of Object.entries(tabBtn) as [Tab, HTMLButtonElement][]) {
    b.type = "button";
    b.addEventListener("click", () => {
      tab = k;
      render(store.get());
    });
    tabs.append(b);
  }

  const controls = el("div", "controls");
  controls.append(keyHelp, cats, sources, region, win, sectors, search, exp);
  root.append(modeBadge, controls, tabs, body);

  function render(s: State): void {
    for (const [k, b] of Object.entries(tabBtn) as [Tab, HTMLButtonElement][]) b.classList.toggle("on", k === tab);
    const high = s.alerts.filter((a) => a.severity === "alta").length;
    tabBtn.alerts.textContent = s.alerts.length ? `Alertas ${s.alerts.length}` : "Alertas";
    tabBtn.alerts.classList.toggle("hot", high > 0);
    const inRegion = (e: Entity) => s.region === "world" || LATAM.has(str(e.attrs.country_code));
    body.replaceChildren(...(
      tab === "alerts" ? renderAlerts(s.alerts)
        : tab === "events" ? renderEvents(visibleEvents(s).filter(inRegion))
        : tab === "attacks" ? renderAttacks(visibleIncidents(s).filter(inRegion), s.region)
          : tab === "families" ? renderFamilies(s.entities.c2 ?? [], s)
            : renderKev(windowed(s, "kev").sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at)))));
  }

  /** Sectores mas golpeados en la ventana actual; clic para filtrar el mapa y la lista. */
  function renderSectors(s: State): void {
    const counts = new Map<string, number>();
    for (const e of windowed(s, "incidents")) {
      const k = sectorEs(e.attrs.sector);
      if (k !== "Sin sector") counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    const top = [...counts].sort((a, b) => b[1] - a[1]).slice(0, 8);
    sectors.replaceChildren(...top.map(([name, n]) => {
      const c = el("button", s.sector === name ? "chip-btn on" : "chip-btn");
      c.type = "button";
      c.append(document.createTextNode(`${name} `), el("b", "", String(n)));
      c.addEventListener("click", () => store.set({ sector: s.sector === name ? null : name }));
      return c;
    }));
  }

  function renderAlerts(alerts: Alert[]): HTMLElement[] {
    if (!alerts.length) return [el("p", "empty", "Sin alertas por ahora. Se generan con familias nuevas, C2 o víctimas en países vigilados y vulnerabilidades explotadas nuevas.")];
    return alerts.slice(0, 60).map((a) => {
      const li = el("div", `alert sev-${a.severity}`);
      const top = el("div", "row");
      top.append(el("span", "sev", a.severity), el("span", "t", a.title), el("span", "s", timeAgo(a.at)));
      li.append(top, el("div", "d", a.detail));
      if (a.pivot_kind && a.pivot_value) {
        li.classList.add("click");
        li.addEventListener("click", () => a.pivot_kind === "event" ? store.selectEvent(a.pivot_value!)
          : store.investigate(a.pivot_kind!, a.pivot_value!, true));
      }
      return li;
    });
  }

  function renderEvents(events: Entity[]): HTMLElement[] {
    if (!events.length) return [el("p", "empty", "Sin eventos en esta ventana. Se arman con avisos oficiales y prensa especializada, cada 30 minutos.")];
    const sorted = [...events].sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at));
    return [el("p", "ov-note", "Clasificación automática por reglas. Verificado = fuente oficial, 2+ medios o CVE en el catálogo KEV."),
      ...sorted.slice(0, 100).map((e) => {
        const a = eventAttrs(e);
        const li = el("div", "evt");
        li.style.setProperty("--c", CATEGORY[a.kind]?.color ?? "#fff");
        const top = el("div", "row");
        top.append(el("span", "evt-k", a.kind_label), el("span", a.status === "verificado" ? "evt-st ok" : "evt-st",
          a.status === "verificado" ? "verificado" : "1 fuente"), el("span", "s", timeAgo(e.observed_at)));
        const where = a.countries.map((c) => c.code).join(" ") || "global";
        li.append(top, el("div", "t", a.title), el("div", "d", `${where} · ${a.n_sources} fuente(s)${a.cves.length ? ` · ${a.cves[0].id}` : ""}`));
        li.addEventListener("click", () => {
          store.select(e);
          focusEntity(e);
        });
        return li;
      })];
  }

  function renderAttacks(incidents: Entity[], reg: string): HTMLElement[] {
    if (!incidents.length) return [el("p", "empty", reg === "latam" ? "Sin víctimas reivindicadas en la región." : "Sin datos todavía.")];
    const unplaced = incidents.filter((e) => e.lat == null).length;
    const sorted = [...incidents].sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at));
    const note = "Víctimas que los grupos publican en sus sitios de filtración. Una reivindicación no es una confirmación."
      + (unplaced ? ` ${unplaced} sin país conocido: figuran acá pero no en el mapa.` : "");
    return [el("p", "ov-note", note),
      ...sorted.slice(0, 80).map((e) => {
        const li = el("div", "attack");
        const top = el("div", "row");
        top.append(el("span", "cc", str(e.attrs.country_code) || "··"), el("span", "t", str(e.attrs.victim)), el("span", "s", timeAgo(e.observed_at)));
        const sub = el("div", "d");
        sub.append(el("b", "", str(e.attrs.group)), document.createTextNode(` · ${sectorEs(e.attrs.sector)}`));
        li.append(top, sub);
        li.addEventListener("click", () => {
          store.select(e);
          focusEntity(e);
        });
        return li;
      })];
  }

  function renderFamilies(c2: Entity[], s: State): HTMLElement[] {
    const counts = new Map<string, number>();
    for (const e of c2) counts.set(str(e.attrs.malware), (counts.get(str(e.attrs.malware)) ?? 0) + 1);
    const top = [...counts].sort((a, b) => b[1] - a[1]).slice(0, 20);
    if (!top.length) return [el("p", "empty", "Sin datos todavía.")];
    const max = top[0][1];
    const current = s.trail.at(-1);
    return top.map(([name, n]) => {
      const li = el("div", "family");
      li.classList.toggle("on", current?.kind === "malware" && current.value === name);
      const dot = el("span", "dot");
      dot.style.background = familyColor(name);
      const bar = el("span", "bar");
      bar.style.width = `${(n / max) * 100}%`;
      bar.style.background = familyColor(name);
      li.append(dot, el("span", "t", name), el("span", "n", String(n)), bar);
      li.title = `Investigar ${name}`;
      li.addEventListener("click", () => store.investigate("malware", name, true));
      return li;
    });
  }

  function renderKev(kev: Entity[]): HTMLElement[] {
    if (!kev.length) return [el("p", "empty", "Sin datos todavía.")];
    return kev.slice(0, 60).map((e) => {
      const a = e.attrs;
      const li = el("div", "kev");
      const top = el("div", "row");
      top.append(el("span", "cve", str(a.cve)));
      if (a.ransomware === true) top.append(el("span", "tag", "ransomware"));
      top.append(el("span", "s", dayDate(e.observed_at)));
      const detail = el("div", "detail");
      detail.append(el("p", "", str(a.description) || str(a.name)), el("p", "act", `Acción: ${str(a.action) || "—"}`));
      const link = safeLink(str(a.source_url), "Ver en NVD ↗");
      if (link) detail.append(link);
      li.append(top, el("div", "prod", `${str(a.vendor)} ${str(a.product)}`.trim()), detail);
      li.addEventListener("click", (ev) => {
        if ((ev.target as HTMLElement).tagName !== "A") li.classList.toggle("open");
      });
      return li;
    });
  }

  store.subscribe((s, prev) => {
    modeBadge.hidden = s.mode !== "demo";
    regionBtn.world.classList.toggle("on", s.region === "world");
    regionBtn.latam.classList.toggle("on", s.region === "latam");
    for (const [id, node] of sourceStatus) {
      const status = s.statuses[id];
      if (!status) continue;
      const when = status.updated_at ? new Date(status.updated_at).toLocaleTimeString("es-AR", { hour12: false }) : "—";
      node.textContent = status.error ? `error: ${status.error}` : `${status.count} registros · ${when}`;
      node.classList.toggle("err", !!status.error);
    }
    for (const [k, b] of winBtn) b.classList.toggle("on", k === s.timeWindow);
    for (const [k, b] of heatBtn) b.classList.toggle("on", k === s.heat);
    const failed = SOURCES.filter((x) => s.statuses[x.id]?.error).length;
    sourcesSum.textContent = failed ? `Fuentes · ${failed} con error` : "Fuentes";
    sourcesSum.classList.toggle("err", failed > 0);
    const counts = categoryCounts(s);
    for (const [id, { row, n }] of catRow) {
      row.classList.toggle("off", !on(s, id));
      n.textContent = String(counts[id] ?? 0);
      row.classList.toggle("zero", !counts[id]);
    }
    const missingKey = ["c2", "urls"].some((id) => (s.statuses[id]?.error ?? "").includes("ARGOS_ABUSECH_KEY"));
    keyHelp.hidden = !missingKey || s.mode === "demo";
    if (s === prev || s.timeWindow !== prev.timeWindow || s.sector !== prev.sector || s.history !== prev.history
        || s.entities.incidents !== prev.entities.incidents) renderSectors(s);

    // Re-render solo si cambio algo que la pestana activa muestra (no pisa una vulnerabilidad abierta).
    const changed = s === prev || s.region !== prev.region || s.timeWindow !== prev.timeWindow || s.sector !== prev.sector
      || s.history !== prev.history
      || (tab === "alerts" && s.alerts !== prev.alerts)
      || (tab === "attacks" && s.entities.incidents !== prev.entities.incidents)
      || (tab === "events" && (s.entities.events !== prev.entities.events || s.visible !== prev.visible))
      || (tab === "families" && (s.entities.c2 !== prev.entities.c2 || s.trail !== prev.trail))
      || (tab === "kev" && s.entities.kev !== prev.entities.kev)
      || s.alerts.length !== prev.alerts.length;
    if (changed) render(s);
  });
}
