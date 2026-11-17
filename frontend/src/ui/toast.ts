import type { Alert } from "../api/types";
import type { Store } from "../state/store";
import { el } from "./dom";

/**
 * Avisos flotantes para las alertas que llegan en vivo (no para las que se cargan al conectar).
 * Si llegan varias juntas, se agrupan en un solo aviso para no tapar el mapa.
 */
export function createToaster(root: HTMLElement, store: Store): (a: Alert) => void {
  let pending: Alert[] = [];
  let timer: number | undefined;

  function show(node: HTMLElement): void {
    root.append(node);
    while (root.childElementCount > 3) root.firstElementChild?.remove();
    window.setTimeout(() => node.classList.add("out"), 7000);
    window.setTimeout(() => node.remove(), 7600);
  }

  function flush(): void {
    const batch = pending.filter((a) => a.severity !== "baja");
    pending = [];
    if (!batch.length) return;
    if (batch.length > 2) {
      const high = batch.filter((a) => a.severity === "alta").length;
      const t = el("div", `toast ${high ? "sev-alta" : "sev-media"}`);
      t.append(el("b", "", `${batch.length} alertas nuevas`), el("span", "", batch.slice(0, 3).map((a) => a.title).join(" · ")));
      show(t);
      return;
    }
    for (const a of batch) {
      const t = el("div", `toast sev-${a.severity}`);
      t.append(el("b", "", a.title), el("span", "", a.detail));
      if (a.pivot_kind && a.pivot_value) {
        t.classList.add("click");
        t.title = "Investigar";
        t.addEventListener("click", () => {
          store.investigate(a.pivot_kind!, a.pivot_value!, true);
          t.remove();
        });
      }
      show(t);
    }
  }

  return (a: Alert) => {
    pending.push(a);
    window.clearTimeout(timer);
    timer = window.setTimeout(flush, 400);
  };
}
