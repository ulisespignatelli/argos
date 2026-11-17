import { str, type Entity } from "../api/types";
import type { MapLayer } from "../layers/types";
import type { State, Store } from "../state/store";
import { dayDate, familyColor, safeLink } from "../util/format";
import { el } from "./dom";

const CONNECTION_LABEL = { connecting: "conectando…", open: "en vivo", closed: "sin conexión" } as const;
const SOURCES: Record<string, string> = { c2: "Servidores C2 · ThreatFox", kev: "Vulnerabilidades explotadas · CISA" };

export function mountPanel(root: HTMLElement, store: Store, layers: MapLayer[]): void {
  // Encabezado
  const conn = el("span", "conn");
  const header = el("div", "brand");
  header.append(el("h1", "", "ARGOS"), conn);
  const modeBadge = el("div", "badge", "DATOS SIMULADOS · IPs de documentación (RFC 5737)");

  // Estadisticas
  const stats = el("div", "stats");
  const statC2 = el("b"), statFam = el("b"), statCountries = el("b"), statKev = el("b");
  for (const [b, label] of [[statC2, "servidores C2"], [statFam, "familias"], [statCountries, "países"], [statKev, "CVE con ransomware"]] as const) {
    const box = el("div", "stat");
    box.append(b, el("span", "", label));
    stats.append(box);
  }

  // Fuentes
  const sources = el("div", "sources");
  const sourceRows = new Map<string, HTMLElement>();
  const c2Layer = layers.find((l) => l.id === "c2");
  for (const id of Object.keys(SOURCES)) {
    const row = el("label", "source");
    if (id === "c2" && c2Layer) {
      const box = el("input");
      box.type = "checkbox";
      box.checked = true;
      box.title = "Mostrar en el mapa";
      box.addEventListener("change", () => store.toggle("c2", box.checked));
      row.append(box);
    } else row.append(el("span", "nobox"));
    const st = el("span", "status", "esperando datos…");
    row.append(el("span", "name", SOURCES[id]), st);
    sources.append(row);
    sourceRows.set(id, st);
  }

  // Busqueda
  const search = el("input", "search");
  search.type = "search";
  search.placeholder = "Buscar IP, malware, país o ASN";
  search.addEventListener("input", () => store.set({ search: search.value }));

  // Familias
  const famTitle = el("h2", "", "Familias de malware");
  const famList = el("ul", "families");

  // Vulnerabilidades
  const kevTitle = el("h2", "", "Explotadas recientemente");
  const kevList = el("ul", "kev");

  const scroll = el("div", "scroll");
  scroll.append(famTitle, famList, kevTitle, kevList);
  root.append(header, el("div", "sub", "Inteligencia de amenazas · fuentes abiertas"), modeBadge, stats, sources, search, scroll);

  store.subscribe((s: State, prev: State) => {
    conn.textContent = CONNECTION_LABEL[s.connection];
    conn.dataset.state = s.connection;
    modeBadge.hidden = s.mode !== "demo";

    for (const [id, node] of sourceRows) {
      const st = s.statuses[id];
      if (!st) continue;
      const when = st.updated_at ? new Date(st.updated_at).toLocaleTimeString("es-AR", { hour12: false }) : "—";
      node.textContent = st.error ? `error: ${st.error}` : `${st.count} registros · ${when}`;
      node.classList.toggle("err", !!st.error);
    }

    const c2 = s.entities.c2 ?? [];
    const kev = s.entities.kev ?? [];
    if (c2 !== prev.entities.c2 || s.family !== prev.family || s === prev) renderFamilies(c2, s.family);
    if (kev !== prev.entities.kev || s === prev) renderKev(kev);

    statC2.textContent = String(new Set(c2.map((e) => str(e.attrs.ip))).size);
    statFam.textContent = String(new Set(c2.map((e) => str(e.attrs.malware))).size);
    statCountries.textContent = String(new Set(c2.map((e) => str(e.attrs.country_code)).filter(Boolean)).size);
    statKev.textContent = String(kev.filter((e) => e.attrs.ransomware === true).length);
  });

  function renderFamilies(c2: Entity[], active: string | null): void {
    const counts = new Map<string, number>();
    for (const e of c2) counts.set(str(e.attrs.malware), (counts.get(str(e.attrs.malware)) ?? 0) + 1);
    const top = [...counts].sort((a, b) => b[1] - a[1]).slice(0, 12);
    const max = top[0]?.[1] ?? 1;
    famList.replaceChildren(
      ...(top.length
        ? top.map(([name, n]) => {
            const li = el("li");
            li.classList.toggle("on", active === name);
            li.classList.toggle("dim", active !== null && active !== name);
            const dot = el("span", "dot");
            dot.style.background = familyColor(name);
            const bar = el("span", "bar");
            bar.style.width = `${(n / max) * 100}%`;
            bar.style.background = familyColor(name);
            li.append(dot, el("span", "t", name), el("span", "n", String(n)), bar);
            li.title = active === name ? "Quitar filtro" : `Mostrar solo ${name}`;
            li.addEventListener("click", () => store.set({ family: active === name ? null : name }));
            return li;
          })
        : [el("li", "empty", "Sin datos todavía.")]),
    );
  }

  function renderKev(kev: Entity[]): void {
    kevList.replaceChildren(
      ...(kev.length
        ? kev.slice(0, 40).map((e) => {
            const a = e.attrs;
            const li = el("li");
            const top = el("div", "row");
            top.append(el("span", "cve", str(a.cve)));
            if (a.ransomware === true) top.append(el("span", "tag", "ransomware"));
            top.append(el("span", "s", dayDate(e.observed_at)));
            const detail = el("div", "detail");
            detail.append(el("p", "", str(a.description) || str(a.name)), el("p", "act", `Acción: ${str(a.action) || "—"}`));
            const link = safeLink(str(a.source_url), "Ver en NVD");
            if (link) detail.append(link);
            li.append(top, el("div", "prod", `${str(a.vendor)} ${str(a.product)}`.trim()), detail);
            li.addEventListener("click", (ev) => {
              if ((ev.target as HTMLElement).tagName !== "A") li.classList.toggle("open");
            });
            return li;
          })
        : [el("li", "empty", "Sin datos todavía.")]),
    );
  }
}

