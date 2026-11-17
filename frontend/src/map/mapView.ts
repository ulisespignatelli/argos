import L from "leaflet";
import { createBaseLayer } from "./tiles";

/** Crea el mapa base. No sabe nada de capas ni de datos. */
export function createMap(el: HTMLElement): L.Map {
  const map = L.map(el, { zoomControl: false, worldCopyJump: true, preferCanvas: true }).setView([-33, -62], 4);
  L.control.zoom({ position: "bottomright" }).addTo(map);
  createBaseLayer().addTo(map);
  return map;
}

/** Popup armado con textContent: los datos vienen de fuentes externas, nunca se insertan como HTML. */
export function popup(title: string, rows: [string, string][]): HTMLElement {
  const root = document.createElement("div");
  const b = document.createElement("b");
  b.textContent = title;
  const dl = document.createElement("dl");
  for (const [k, v] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v;
    dl.append(dt, dd);
  }
  root.append(b, dl);
  return root;
}
