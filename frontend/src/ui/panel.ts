import { api } from "../api/client";
import { str, type Alert, type Entity } from "../api/types";
import type { State, Store } from "../state/store";
import { dayDate, familyColor, guessKind, safeLink, timeAgo } from "../util/format";
import { el } from "./dom";

const CONNECTION_LABEL = { connecting: "conectando…", open: "en vivo", closed: "sin conexión" } as const;
const SOURCES: { id: string; label: string; map: boolean }[] = [
  { id: "c2", label: "Servidores C2 · ThreatFox", map: true },
  { id: "urls", label: "URLs de malware · URLhaus", map: true },
  { id: "kev", label: "Vulnerabilidades explotadas · CISA", map: false },
];
type Tab = "alerts" | "families" | "kev";

/** Panel izquierdo: estado, fuentes, busqueda, exportacion y pestañas de alertas, familias y vulnerabilidades. */
export function mountPanel(root: HTMLElement, store: Store): void {
  const conn = el("span", "conn");
  const header = el("div", "brand");
  header.append(el("h1", "", "ARGOS"), conn);
  const modeBadge = el("div", "badge", "DATOS SIMULADOS · IPs y dominios de documentación");

  // Estadisticas
  const stats = el("div", "stats");
  const st = { c2: el("b"), fam: el("b"), urls: el("b"), kev: el("b") };
  for (const [b, label] of [[st.c2, "IPs C2"], [st.fam, "familias"], [st.urls, "URLs activas"], [st.kev, "CVE ransomware"]] as const) {
    const box = el("div", "stat");
    box.append(b, el("span", "", label));
    stats.append(box);
  }

  // Fuentes
  const sources = el("div", "sources");
  const sourceStatus = new Map<string, HTMLElement>();
  for (const src of SOURCES) {
    const row = el("label", "source");
    if (src.map) {
      const box = el("input");
      box.type = "checkbox";
      box.checked = true;
      box.title = "Mostrar en el mapa";
      box.addEventListener("change", () => store.toggle(src.id, box.checked));
      row.append(box);
    } else row.append(el("span"));
    const status = el("span", "status", "esperando datos…");
    row.append(el("span", "name", src.label), status);
    sources.append(row);
    sourceStatus.set(src.id, status);
  }

  // Busqueda: escribir resalta; Enter abre una investigacion.
  const search = el("input", "search");
  search.type = "search";
  search.placeholder = "IP, ASN, país, host o malware · Enter para investigar";
  search.addEventListener("input", () => store.set({ search: search.value }));
  search.addEventListener("keydown", (ev) => {
    const v = search.value.trim();
    if (ev.key === "Enter" && v) store.investigate(guessKind(v), guessKind(v) === "country" || guessKind(v) === "asn" ? v.toUpperCase() : v, true);
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
    alerts: el("button", "", "Alertas"), families: el("button", "", "Familias"), kev: el("button", "", "Vulnerabilidades"),
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

  root.append(header, el("div", "sub", "Inteligencia de amenazas · fuentes abiertas"), modeBadge, stats, sources, search, exp, tabs, body);

  function render(s: State): void {
    for (const [k, b] of Object.entries(tabBtn) as [Tab, HTMLButtonElement][]) b.classList.toggle("on", k === tab);
    const high = s.alerts.filter((a) => a.severity === "alta").length;
    tabBtn.alerts.textContent = s.alerts.length ? `Alertas (${s.alerts.length})` : "Alertas";
    tabBtn.alerts.classList.toggle("hot", high > 0);
    body.replaceChildren(
      ...(tab === "alerts" ? renderAlerts(s.alerts) : tab === "families" ? renderFamilies(s.entities.c2 ?? [], s) : renderKev(s.entities.kev ?? [])),
    );
  }

  function renderAlerts(alerts: Alert[]): HTMLElement[] {
    if (!alerts.length) return [el("p", "empty", "Sin alertas por ahora. Se generan cuando aparece una familia nueva, un C2 en un país vigilado o una vulnerabilidad explotada nueva.")];
    return alerts.slice(0, 60).map((a) => {
      const li = el("div", `alert sev-${a.severity}`);
      const top = el("div", "row");
      top.append(el("span", "sev", a.severity), el("span", "t", a.title), el("span", "s", timeAgo(a.at)));
      li.append(top, el("div", "d", a.detail));
      if (a.pivot_kind && a.pivot_value) {
        li.classList.add("click");
        li.addEventListener("click", () => store.investigate(a.pivot_kind!, a.pivot_value!, true));
      }
      return li;
    });
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
    conn.textContent = CONNECTION_LABEL[s.connection];
    conn.dataset.state = s.connection;
    modeBadge.hidden = s.mode !== "demo";
    for (const [id, node] of sourceStatus) {
      const status = s.statuses[id];
      if (!status) continue;
      const when = status.updated_at ? new Date(status.updated_at).toLocaleTimeString("es-AR", { hour12: false }) : "—";
      node.textContent = status.error ? `error: ${status.error}` : `${status.count} registros · ${when}`;
      node.classList.toggle("err", !!status.error);
    }
    const c2 = s.entities.c2 ?? [], urls = s.entities.urls ?? [], kev = s.entities.kev ?? [];
    st.c2.textContent = String(new Set(c2.map((e) => str(e.attrs.ip))).size);
    st.fam.textContent = String(new Set(c2.map((e) => str(e.attrs.malware))).size);
    st.urls.textContent = String(urls.filter((e) => e.attrs.status === "online").length);
    st.kev.textContent = String(kev.filter((e) => e.attrs.ransomware === true).length);

    // Re-render solo si cambio algo que la pestana activa muestra (no pisa una vulnerabilidad abierta).
    const changed = s === prev
      || (tab === "alerts" && s.alerts !== prev.alerts)
      || (tab === "families" && (s.entities.c2 !== prev.entities.c2 || s.trail !== prev.trail))
      || (tab === "kev" && s.entities.kev !== prev.entities.kev)
      || s.alerts.length !== prev.alerts.length;
    if (changed) render(s);
  });
}
