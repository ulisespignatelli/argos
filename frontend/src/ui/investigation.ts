import type L from "leaflet";
import { api } from "../api/client";
import { str, type ActorProfile, type Entity, type Pivot } from "../api/types";
import type { Investigation, Store } from "../state/store";
import { defang, KIND_LABEL, kindColor, shortDate } from "../util/format";
import { el } from "./dom";
import { eventCard } from "./eventCard";
import { incidentCard } from "./incidentCard";

const SVG = "http://www.w3.org/2000/svg";
const MAX_NODES = 18;

/** Panel derecho: investigacion por correlacion, con grafo navegable y lista de indicadores. */
export function mountInvestigation(root: HTMLElement, store: Store, map: L.Map, focusEntity: (e: Entity) => void): void {
  let requestSeq = 0;
  let profile: ActorProfile | null = null;

  store.subscribe((s, prev) => {
    if (s.selected !== prev.selected && s.selected && !s.trail.length) {
      document.body.classList.add("investigating");
      root.hidden = false;
      root.replaceChildren(s.selected.layer === "events" ? eventCard(s.selected, store) : incidentCard(s.selected, store));
      return;
    }
    if (s.trail !== prev.trail || s === prev || (s.selected !== prev.selected && !s.selected)) {
      const cur = s.trail.at(-1);
      document.body.classList.toggle("investigating", !!cur);
      if (!cur) {
        root.hidden = true;
        return;
      }
      root.hidden = false;
      const seq = ++requestSeq;
      root.replaceChildren(header(s.trail), el("p", "empty", "Correlacionando…"));
      profile = null;
      if (cur.kind === "actor") {
        api.actor(cur.value).then((p) => {
          if (seq !== requestSeq) return;
          profile = p;
          const st = store.get();
          if (st.pivot) root.replaceChildren(header(st.trail), ...body(st.pivot));
        }).catch(() => {});
      }
      api.pivot(cur.kind, cur.value)
        .then((p) => seq === requestSeq && store.set({ pivot: p, pivotError: null }))
        .catch((err: Error) => seq === requestSeq && store.set({ pivot: null, pivotError: err.message }));
      return;
    }
    if (s.pivot !== prev.pivot || s.pivotError !== prev.pivotError) {
      root.replaceChildren(header(s.trail), ...(s.pivot ? body(s.pivot) : [el("p", "err", s.pivotError ?? "")]));
      if (s.pivot && s.pivot.entities !== prev.pivot?.entities && prev.pivot?.value !== s.pivot.value) fit(s.pivot);
    }
  });

  // Si llegan datos nuevos mientras hay una investigacion abierta, se actualiza sola.
  store.subscribe((s, prev) => {
    const cur = s.trail.at(-1);
    if (cur && s !== prev && (s.entities.c2 !== prev.entities.c2 || s.entities.urls !== prev.entities.urls)) {
      api.pivot(cur.kind, cur.value).then((p) => store.get().trail.at(-1) === cur && store.set({ pivot: p })).catch(() => {});
    }
  });

  function crumbText(t: Investigation): string {
    if (t.kind === "actor") return `${KIND_LABEL.actor}: ${t.label ?? (profile && profile.id === t.value ? profile.name : t.value)}`;
    return `${KIND_LABEL[t.kind]}: ${t.kind === "ip" ? defang(t.value) : t.value}`;
  }

  function header(trail: Investigation[]): HTMLElement {
    const h = el("div", "inv-head");
    const crumbs = el("div", "crumbs");
    trail.forEach((t, i) => {
      if (i) crumbs.append(el("span", "sep", "›"));
      const c = el("button", i === trail.length - 1 ? "crumb cur" : "crumb", crumbText(t));
      c.type = "button";
      c.addEventListener("click", () => store.back(trail.length - 1 - i));
      crumbs.append(c);
    });
    const close = el("button", "close", "×");
    close.type = "button";
    close.title = "Cerrar investigación";
    close.addEventListener("click", () => store.closeInvestigation());
    h.append(el("h2", "", "Investigación"), close, crumbs);
    return h;
  }

  /** Ficha del actor: quien es, a quien se le atribuye, que usa y que hay activo hoy. */
  function actorCard(a: ActorProfile): HTMLElement {
    const card = el("div", "actor-card");
    const name = el("div", "ac-name");
    name.append(el("b", "", a.name), el("small", "", [a.id, ...a.aliases.slice(0, 4)].join(" · ")));
    const origin = el("div", "ac-origin", a.country_name
      ? `Atribuido a ${a.country_name}${a.sponsor ? ` · patrocinio sospechado: ${a.sponsor}` : ""} (según MISP)`
      : "Sin atribución de país en fuentes abiertas");
    const stats = el("div", "ac-stats");
    for (const [n, label] of [[a.direct, "atribuidos"], [a.active.c2 + a.active.urls, "de su software"],
      [a.active.incidents, "ataques"], [a.techniques.length, "técnicas"]] as const) {
      const b = el("div", "");
      b.append(el("b", "", String(n)), el("span", "", label));
      stats.append(b);
    }
    card.append(name, origin, el("p", "ac-desc", a.description), stats);
    const sw = a.software.filter((x) => x.active > 0).concat(a.software.filter((x) => x.active === 0)).slice(0, 14);
    if (sw.length) {
      const chips = el("div", "chips");
      for (const x of sw) {
        const c = el("button", x.active ? "chip" : "chip dim");
        c.type = "button";
        c.append(el("span", "", x.name), el("b", "", x.active ? String(x.active) : x.type === "tool" ? "herr." : "—"));
        c.title = x.active ? `${x.active} indicadores vivos de ${x.name}` : `${x.name}: sin indicadores vivos hoy`;
        c.addEventListener("click", () => store.investigate("malware", x.name));
        chips.append(c);
      }
      card.append(el("h3", "", "Software que usa (ATT&CK)"), chips);
    }
    const acts = el("div", "actions");
    const mx = el("button", "", "Ver sus técnicas en la matriz");
    mx.type = "button";
    mx.addEventListener("click", () => store.openMatrix(`actor:${a.id}`));
    acts.append(mx);
    const link = el("a", "", "Ficha en MITRE ↗");
    link.href = a.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    acts.append(link);
    card.append(acts);
    return card;
  }

  function body(p: Pivot): HTMLElement[] {
    const out: HTMLElement[] = [];
    if (p.kind === "actor" && profile && profile.id === p.value) out.push(actorCard(profile));
    const summary = el("p", "inv-sum");
    summary.textContent = p.total
      ? `${p.total} indicador${p.total === 1 ? "" : "es"} vinculados. Hacé clic en un nodo para seguir investigando.`
      : "No hay indicadores actuales vinculados a este dato.";
    out.push(summary);
    if (p.total) out.push(graph(p));

    for (const g of p.groups) {
      const sec = el("div", "inv-group");
      sec.append(el("h3", "", g.label));
      const list = el("div", "chips");
      for (const it of g.items) {
        const chip = el("button", "chip");
        chip.type = "button";
        chip.style.borderColor = kindColor(g.kind, it.value);
        chip.append(el("span", "", g.kind === "ip" ? defang(it.value) : it.label ?? it.value), el("b", "", String(it.count)));
        chip.addEventListener("click", () => store.investigate(g.kind, it.value, false, it.label ?? undefined));
        list.append(chip);
      }
      sec.append(list);
      out.push(sec);
    }

    if ((p.kind === "malware" || p.kind === "country") && p.entities.some((e) => e.layer === "c2")) {
      const exp = el("div", "export");
      exp.append(el("span", "", "Exportar esta selección:"));
      const filter = p.kind === "malware" ? { malware: p.value } : { country: p.value };
      for (const [fmt, text] of [["c2.csv", "CSV"], ["blocklist.txt", "Bloqueo"], ["stix.json", "STIX"]] as const) {
        const a = el("a", "", text);
        a.href = api.exportUrl(fmt, filter);
        a.setAttribute("download", "");
        exp.append(a);
      }
      out.push(exp);
    }

    if (p.entities.length) {
      const sec = el("div", "inv-group");
      sec.append(el("h3", "", `Indicadores (${p.entities.length}${p.total > p.entities.length ? ` de ${p.total}` : ""})`));
      for (const e of p.entities.slice(0, 80)) {
        const row = el("div", "ioc");
        const value = e.layer === "urls" ? defang(str(e.attrs.url))
          : e.layer === "incidents" ? str(e.attrs.victim)
            : `${defang(str(e.attrs.ip))}${e.attrs.port ? `:${str(e.attrs.port)}` : ""}`;
        const kindLabel = e.layer === "urls" ? "URL" : e.layer === "incidents" ? "ATAQUE" : "C2";
        const detail = e.layer === "incidents" ? `${str(e.attrs.group)} · ${str(e.attrs.country) || "—"}` : str(e.attrs.malware) || str(e.attrs.status);
        row.append(el("span", `kind k-${e.layer}`, kindLabel), el("span", "v", value),
          el("span", "s", `${detail} · ${shortDate(e.observed_at)}`));
        if (e.lat != null) {
          row.classList.add("click");
          row.addEventListener("click", () => focusEntity(e));
        }
        sec.append(row);
      }
      out.push(sec);
    }
    return out;
  }

  /** Grafo radial: el dato investigado en el centro y sus conexiones alrededor, agrupadas por tipo. */
  function graph(p: Pivot): HTMLElement {
    const W = 340, H = 260, cx = W / 2, cy = H / 2;
    const nodes = p.groups.flatMap((g) => g.items.slice(0, 6).map((it) => ({ kind: g.kind, ...it }))).slice(0, MAX_NODES);
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("class", "graph");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `Conexiones de ${p.value}`);
    const max = Math.max(1, ...nodes.map((n) => n.count));
    nodes.forEach((n, i) => {
      const ang = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
      const x = cx + Math.cos(ang) * 105, y = cy + Math.sin(ang) * 95;
      const line = document.createElementNS(SVG, "line");
      Object.entries({ x1: cx, y1: cy, x2: x, y2: y }).forEach(([k, v]) => line.setAttribute(k, String(v)));
      line.setAttribute("class", "edge");
      line.setAttribute("stroke-width", String(0.6 + (n.count / max) * 2.4));
      svg.append(line);
      const g = document.createElementNS(SVG, "g");
      g.setAttribute("class", "gnode");
      const c = document.createElementNS(SVG, "circle");
      c.setAttribute("cx", String(x));
      c.setAttribute("cy", String(y));
      c.setAttribute("r", String(5 + (n.count / max) * 6));
      c.setAttribute("fill", kindColor(n.kind, n.value));
      const t = document.createElementNS(SVG, "text");
      t.setAttribute("x", String(x));
      t.setAttribute("y", String(y + (y >= cy ? 20 : -12)));
      t.setAttribute("text-anchor", "middle");
      const label = n.label ?? n.value;
      t.textContent = label.length > 16 ? `${label.slice(0, 15)}…` : label;
      const title = document.createElementNS(SVG, "title");
      title.textContent = `${KIND_LABEL[n.kind]}: ${n.label ?? n.value} (${n.count})`;
      g.append(title, c, t);
      g.addEventListener("click", () => store.investigate(n.kind, n.value, false, n.label ?? undefined));
      svg.append(g);
    });
    const center = document.createElementNS(SVG, "g");
    const cc = document.createElementNS(SVG, "circle");
    cc.setAttribute("cx", String(cx));
    cc.setAttribute("cy", String(cy));
    cc.setAttribute("r", "16");
    cc.setAttribute("fill", kindColor(p.kind, p.value));
    cc.setAttribute("class", "center");
    const ct = document.createElementNS(SVG, "text");
    ct.setAttribute("x", String(cx));
    ct.setAttribute("y", String(cy + 4));
    ct.setAttribute("text-anchor", "middle");
    ct.setAttribute("class", "center-label");
    ct.textContent = KIND_LABEL[p.kind];
    center.append(cc, ct);
    svg.append(center);
    const wrap = el("div", "graph-wrap");
    wrap.append(svg as unknown as HTMLElement);
    return wrap;
  }

  /** Encuadra el mapa sobre los indicadores investigados que tienen ubicacion. */
  function fit(p: Pivot): void {
    const pts = p.entities.filter((e) => e.lat != null && e.lon != null).map((e) => [e.lat!, e.lon!] as [number, number]);
    if (!pts.length) return;
    if (pts.length === 1) map.flyTo(pts[0], Math.max(map.getZoom(), 5), { duration: 0.8 });
    else map.flyToBounds(pts, { padding: [60, 60], maxZoom: 6, duration: 0.8 });
  }
}
