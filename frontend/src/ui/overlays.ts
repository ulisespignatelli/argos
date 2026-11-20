import { api } from "../api/client";
import type { ActorSummary, MatrixData } from "../api/types";
import type { Store } from "../state/store";
import { el } from "./dom";

/** Ventanas superpuestas: listado de actores y matriz MITRE ATT&CK. */
export function mountOverlays(root: HTMLElement, store: Store): void {
  let actorsCache: ActorSummary[] | null = null;
  let showAll = false;

  root.addEventListener("click", (ev) => {
    if (ev.target === root) store.set({ overlay: null });
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && store.get().overlay) store.set({ overlay: null });
  });

  store.subscribe((s, prev) => {
    if (s.overlay === prev.overlay && s.matrixScope === prev.matrixScope && s !== prev) return;
    root.hidden = !s.overlay;
    if (s.overlay === "actors") void renderActors();
    if (s.overlay === "matrix") void renderMatrix(s.matrixScope);
  });

  function frame(title: string, extra?: HTMLElement): { card: HTMLElement; body: HTMLElement } {
    const card = el("div", "ov-card");
    const head = el("div", "ov-head");
    const close = el("button", "close", "×");
    close.type = "button";
    close.title = "Cerrar (Esc)";
    close.addEventListener("click", () => store.set({ overlay: null }));
    head.append(el("h2", "", title));
    if (extra) head.append(extra);
    head.append(close);
    const body = el("div", "ov-body");
    card.append(head, body);
    root.replaceChildren(card);
    return { card, body };
  }

  async function renderActors(): Promise<void> {
    const tools = el("div", "ov-tools");
    const q = el("input", "search");
    q.type = "search";
    q.placeholder = "Buscar actor o alias (Lazarus, APT28, Akira…)";
    const only = el("label", "ov-check");
    const box = el("input");
    box.type = "checkbox";
    box.checked = true;
    only.append(box, document.createTextNode(" solo con actividad hoy"));
    tools.append(q, only);
    const { body } = frame("Actores de amenaza · MITRE ATT&CK", tools);
    body.append(el("p", "empty", "Cargando…"));
    try {
      actorsCache = actorsCache ?? (await api.actors(false));
    } catch (err) {
      body.replaceChildren(el("p", "err", (err as Error).message));
      return;
    }
    const table = el("div", "actors");
    const draw = () => {
      const term = q.value.trim().toLowerCase();
      const rows = (actorsCache ?? []).filter((a) => (!box.checked || a.activity > 0)
        && (!term || [a.name, a.id, ...a.aliases].some((n) => n.toLowerCase().includes(term))));
      const head = el("div", "a-row a-head");
      head.append(el("span", "", "Actor"), el("span", "", "Origen atribuido"), el("span", "n", "Atribuidos"),
        el("span", "n", "Vía su software"), el("span", "n", "Relevancia"), el("span", "n", "Técnicas"));
      table.replaceChildren(head, ...rows.slice(0, 200).map((a) => {
        const r = el("button", "a-row");
        r.type = "button";
        const name = el("span", "a-name");
        name.append(el("b", "", a.name), el("small", "", [a.id, ...a.aliases.slice(0, 3)].join(" · ")));
        r.append(name, el("span", "a-country", a.country_name ?? "sin atribución"),
          el("span", "n hot", String(a.direct || "")), el("span", "n", String(a.via_software || "")),
          el("span", "n", a.relevance ? a.relevance.toFixed(1) : ""), el("span", "n dim", String(a.techniques)));
        r.addEventListener("click", () => store.investigate("actor", a.id, true, a.name));
        return r;
      }));
      if (!rows.length) table.append(el("p", "empty", "Ningún actor coincide."));
    };
    q.addEventListener("input", draw);
    box.addEventListener("change", draw);
    draw();
    body.replaceChildren(el("p", "ov-note", "Atribuidos: indicadores vinculados directamente al grupo. Vía su software: indicadores de familias que el grupo usa, "
      + "lo que no prueba que sean suyos. La relevancia pondera por exclusividad: un servidor de Cobalt Strike, que usan decenas de "
      + "grupos, suma poco a cada uno; una familia exclusiva suma completo."), table);
    q.focus();
  }

  async function renderMatrix(scope: string): Promise<void> {
    const tools = el("div", "ov-tools");
    const cur = store.get().trail.at(-1);
    const scopes: [string, string][] = [["active", "Actividad de hoy"]];
    if (cur?.kind === "actor") scopes.push([`actor:${cur.value}`, cur.label ?? cur.value]);
    if (scope.startsWith("actor:") && !scopes.some(([k]) => k === scope)) scopes.push([scope, scope.slice(6)]);
    for (const [key, label] of scopes) {
      const b = el("button", key === scope ? "chip-btn on" : "chip-btn", label);
      b.type = "button";
      b.addEventListener("click", () => store.openMatrix(key));
      tools.append(b);
    }
    const all = el("label", "ov-check");
    const box = el("input");
    box.type = "checkbox";
    box.checked = showAll;
    all.append(box, document.createTextNode(" mostrar técnicas sin uso"));
    tools.append(all);
    const { body } = frame("Matriz MITRE ATT&CK", tools);
    body.append(el("p", "empty", "Calculando…"));
    let data: MatrixData;
    try {
      data = await api.matrix(scope);
    } catch (err) {
      body.replaceChildren(el("p", "err", (err as Error).message));
      return;
    }
    const draw = () => {
      showAll = box.checked;
      const grid = el("div", "matrix");
      for (const tac of data.tactics) {
        const col = el("div", "m-col");
        const h = el("div", "m-head");
        h.append(el("b", "", tac.name_es), el("small", "", `${tac.used} en uso`));
        col.append(h);
        for (const t of tac.techniques.filter((x) => showAll || x.score > 0)) {
          const cell = el("a", "m-cell");
          cell.href = `https://attack.mitre.org/techniques/${t.id}/`;
          cell.target = "_blank";
          cell.rel = "noopener noreferrer";
          const alpha = data.max ? 0.12 + 0.78 * (t.score / data.max) : 0;
          if (t.score > 0) cell.style.background = `rgba(252, 92, 101, ${alpha.toFixed(2)})`;
          cell.title = t.score > 0 ? `${t.id} · ${t.name}\nPeso ${t.score}: ${t.top.join(", ")}` : `${t.id} · ${t.name}`;
          cell.append(el("span", "", t.name), el("small", "", t.id));
          col.append(cell);
        }
        if (!tac.used && !showAll) col.append(el("p", "m-none", "—"));
        grid.append(col);
      }
      body.replaceChildren(el("p", "ov-note", scope === "active"
        ? "Peso de cada técnica según la cantidad de indicadores vivos cuyo software la usa. Cambia en tiempo real con la actividad."
        : `Técnicas de ${data.label}: 2 puntos si el grupo la usa directamente, +1 por cada software suyo que la usa.`), grid,
      el("p", "ov-foot", `MITRE ATT&CK® ${data.attack_version} · © The MITRE Corporation. Clic en una técnica para ver su ficha oficial.`));
    };
    box.addEventListener("change", draw);
    draw();
  }
}
