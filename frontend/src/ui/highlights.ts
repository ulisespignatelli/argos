import { eventAttrs, str } from "../api/types";
import { AGE } from "../layers/incidentLayer";
import { CATEGORY, windowed } from "../state/selectors";
import type { State, Store } from "../state/store";
import { el } from "./dom";

const DAY = 86400000;

/**
 * Franja de destacados sobre el mapa: lo mas importante de los ultimos dias, sacado de las alertas de
 * severidad alta y de las vulnerabilidades explotadas por ransomware. Y la leyenda de colores por antiguedad.
 */
export function mountHighlights(root: HTMLElement, legend: HTMLElement, store: Store): void {
  for (const a of AGE) {
    const it = el("span", "lg-item");
    const dot = el("span", "dot");
    dot.style.background = a.color;
    it.append(dot, document.createTextNode(a.label));
    legend.append(it);
  }
  const ev = el("span", "lg-item");
  ev.append(el("span", "lg-ring"), document.createTextNode("evento verificado"));
  const ev1 = el("span", "lg-item");
  ev1.append(el("span", "lg-ring dashed"), document.createTextNode("1 fuente"));
  legend.append(ev, ev1);
  const arc = el("span", "lg-item");
  const d = el("span", "lg-arc");
  arc.append(d, document.createTextNode("origen atribuido"));
  legend.append(arc);

  let dismissed = new Set<string>();
  const render = (s: State) => {
    const now = Date.now();
    const items: { key: string; tag: string; text: string; go?: () => void; color?: string; cls?: string }[] = [];
    for (const al of s.alerts.filter((x) => x.severity === "alta" && x.pivot_kind !== "event"
        && now - Date.parse(x.at) < 3 * DAY).slice(0, 1)) {
      items.push({ key: al.id, tag: "Alerta", text: al.title,
        go: al.pivot_kind && al.pivot_value ? () => store.investigate(al.pivot_kind as never, al.pivot_value!, true) : undefined });
    }
    // Eventos globales: lo verificado y con mas fuentes de las ultimas 72 horas.
    const events = windowed(s, "events").filter((e) => now - Date.parse(e.observed_at) < 3 * DAY)
      .sort((a, b) => Number(eventAttrs(b).status === "verificado") - Number(eventAttrs(a).status === "verificado")
        || eventAttrs(b).n_sources - eventAttrs(a).n_sources || Date.parse(b.observed_at) - Date.parse(a.observed_at));
    for (const e of events.slice(0, 3)) {
      const a = eventAttrs(e);
      const date = new Date(e.observed_at).toLocaleDateString("es-AR", { day: "numeric", month: "short" });
      items.push({ key: e.id, tag: a.status === "verificado" ? "Verificado" : "1 fuente", cls: a.status === "verificado" ? "ok" : "one",
        text: `${a.kind_label} · ${a.title} · ${date}`, color: CATEGORY[a.kind]?.color, go: () => store.select(e) });
    }
    const mentioned = items.map((i) => i.text).join(" ");
    for (const k of windowed(s, "kev").filter((e) => e.attrs.ransomware === true && now - Date.parse(e.observed_at) < 7 * DAY
        && !mentioned.includes(str(e.attrs.cve))).slice(0, 2)) {
      items.push({ key: k.id, tag: "Explotada", text: `${str(k.attrs.cve)} · ${str(k.attrs.vendor)} ${str(k.attrs.product)} (usada por ransomware)` });
    }
    const visible = items.filter((i) => !dismissed.has(i.key)).slice(0, 3);
    root.replaceChildren(...visible.map((i) => {
      const b = el("div", i.go ? "hl click" : "hl");
      const x = el("button", "hl-x", "×");
      x.type = "button";
      x.title = "Ocultar";
      x.addEventListener("click", (ev) => {
        ev.stopPropagation();
        dismissed = new Set([...dismissed, i.key]);
        render(store.get());
      });
      if (i.color) b.style.setProperty("--c", i.color);
      b.append(el("span", `hl-tag ${i.cls ?? ""}`, i.tag), el("span", "hl-t", i.text), x);
      if (i.go) b.addEventListener("click", i.go);
      return b;
    }));
  };
  store.subscribe((s, prev) => {
    if (s === prev || s.alerts !== prev.alerts || s.entities.kev !== prev.entities.kev || s.history !== prev.history
        || s.entities.events !== prev.entities.events) render(s);
  });
}
