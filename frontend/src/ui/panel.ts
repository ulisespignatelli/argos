import type { MapLayer } from "../layers/types";
import type { State, Store } from "../state/store";

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

const CONNECTION_LABEL = { connecting: "conectando…", open: "en vivo", closed: "sin conexión" } as const;

/** Panel lateral: estado de conexion, capas con su estado, buscador y feed de sismos. */
export function mountPanel(root: HTMLElement, store: Store, layers: MapLayer[], onSearch: (q: string) => void): void {
  const header = el("div", "brand");
  header.append(el("h1", "", "ARGOS"), el("span", "conn"));
  const sub = el("div", "sub", "Conciencia situacional · fuentes abiertas");
  const modeBadge = el("div", "badge", "DATOS SIMULADOS");

  const list = el("div", "layers");
  const rows = new Map<string, { count: HTMLElement; status: HTMLElement; box: HTMLInputElement }>();
  for (const layer of layers) {
    const row = el("label", "layer");
    const box = el("input");
    box.type = "checkbox";
    box.checked = true;
    box.addEventListener("change", () => store.toggle(layer.id, box.checked));
    const name = el("span", "name");
    const dot = el("span", "dot");
    dot.style.background = layer.color;
    name.append(dot, document.createTextNode(layer.title));
    const count = el("span", "count", "0");
    const status = el("span", "status", "esperando datos…");
    row.append(box, name, count, status);
    list.append(row);
    rows.set(layer.id, { count, status, box });
  }

  const search = el("input", "search");
  search.type = "search";
  search.placeholder = "Buscar vuelo (ej. ARG1302)";
  search.addEventListener("input", () => onSearch(search.value));

  const feedTitle = el("h2", "", "Sismos recientes");
  const feed = el("ul", "feed");

  root.append(header, sub, modeBadge, list, search, feedTitle, feed);

  store.subscribe((s: State, prev: State) => {
    const conn = header.querySelector(".conn") as HTMLElement;
    conn.textContent = CONNECTION_LABEL[s.connection];
    conn.dataset.state = s.connection;
    modeBadge.hidden = s.mode !== "demo";

    for (const [id, r] of rows) {
      const st = s.statuses[id];
      r.count.textContent = String(s.entities[id]?.length ?? 0);
      r.box.checked = s.visible[id] ?? true;
      if (!st) continue;
      const when = st.updated_at ? new Date(st.updated_at).toLocaleTimeString("es-AR", { hour12: false }) : "—";
      r.status.textContent = st.error ? `error: ${st.error}` : `${st.source} · ${when}`;
      r.status.classList.toggle("err", !!st.error);
    }

    if (s.entities.earthquakes !== prev.entities.earthquakes || feed.childElementCount === 0) {
      const quakes = [...(s.entities.earthquakes ?? [])]
        .sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))
        .slice(0, 30);
      feed.replaceChildren(
        ...(quakes.length
          ? quakes.map((q) => {
              const li = el("li");
              li.append(
                el("span", "t", q.label),
                el("span", "s", new Date(q.observed_at).toLocaleString("es-AR", { hour12: false, day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })),
              );
              li.addEventListener("click", () => layers.find((l) => l.id === "earthquakes")?.focus(q));
              return li;
            })
          : [el("li", "empty", "Sin sismos todavía.")]),
      );
    }
  });
}
