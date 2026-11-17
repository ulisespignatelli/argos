import type L from "leaflet";
import { api } from "../api/client";
import { str, type Entity, type Pivot, type PivotKind } from "../api/types";
import type { Store } from "../state/store";
import { defang, KIND_LABEL, kindColor, shortDate } from "../util/format";
import { el } from "./dom";

const SVG = "http://www.w3.org/2000/svg";
const MAX_NODES = 18;

/** Panel derecho: investigacion por correlacion, con grafo navegable y lista de indicadores. */
export function mountInvestigation(root: HTMLElement, store: Store, map: L.Map, focusEntity: (e: Entity) => void): void {
  let requestSeq = 0;

  store.subscribe((s, prev) => {
    if (s.trail !== prev.trail || s === prev) {
      const cur = s.trail.at(-1);
      document.body.classList.toggle("investigating", !!cur);
      if (!cur) {
        root.hidden = true;
        return;
      }
      root.hidden = false;
      const seq = ++requestSeq;
      root.replaceChildren(header(s.trail), el("p", "empty", "Correlacionando…"));
      api.pivot(cur.kind, cur.value)
        .then((p) => seq === requestSeq && store.set({ pivot: p, pivotError: null }))
        .catch((err: Error) => seq === requestSeq && store.set({ pivot: null, pivotError: err.message }));
      return;
    }
    if (s.pivot !== prev.pivot || s.pivotError !== prev.pivotError) {
      root.replaceChildren(header(s.trail), ...(s.pivot ? body(s.pivot) : [el("p", "err", s.pivotError ?? "")]));
      if (s.pivot) fit(s.pivot);
    }
  });

  // Si llegan datos nuevos mientras hay una investigacion abierta, se actualiza sola.
  store.subscribe((s, prev) => {
    const cur = s.trail.at(-1);
    if (cur && s !== prev && (s.entities.c2 !== prev.entities.c2 || s.entities.urls !== prev.entities.urls)) {
      api.pivot(cur.kind, cur.value).then((p) => store.get().trail.at(-1) === cur && store.set({ pivot: p })).catch(() => {});
    }
  });

  function header(trail: { kind: PivotKind; value: string }[]): HTMLElement {
    const h = el("div", "inv-head");
    const crumbs = el("div", "crumbs");
    trail.forEach((t, i) => {
      if (i) crumbs.append(el("span", "sep", "›"));
      const c = el("button", i === trail.length - 1 ? "crumb cur" : "crumb", `${KIND_LABEL[t.kind]}: ${t.kind === "ip" ? defang(t.value) : t.value}`);
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

  function body(p: Pivot): HTMLElement[] {
    const out: HTMLElement[] = [];
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
        chip.append(el("span", "", g.kind === "ip" ? defang(it.value) : it.value), el("b", "", String(it.count)));
        chip.addEventListener("click", () => store.investigate(g.kind, it.value));
        list.append(chip);
      }
      sec.append(list);
      out.push(sec);
    }

    if (p.kind === "malware" || p.kind === "country") {
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
        const value = e.layer === "urls" ? defang(str(e.attrs.url)) : `${defang(str(e.attrs.ip))}${e.attrs.port ? `:${str(e.attrs.port)}` : ""}`;
        row.append(el("span", `kind k-${e.layer}`, e.layer === "urls" ? "URL" : "C2"), el("span", "v", value),
          el("span", "s", `${str(e.attrs.malware) || str(e.attrs.status)} · ${shortDate(e.observed_at)}`));
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
      const label = n.value;
      t.textContent = label.length > 16 ? `${label.slice(0, 15)}…` : label;
      const title = document.createElementNS(SVG, "title");
      title.textContent = `${KIND_LABEL[n.kind]}: ${n.value} (${n.count})`;
      g.append(title, c, t);
      g.addEventListener("click", () => store.investigate(n.kind, n.value));
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
