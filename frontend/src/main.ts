import "leaflet/dist/leaflet.css";
import "./styles.css";
import { api, LiveConnection } from "./api/client";
import { createLayers } from "./layers/registry";
import { createMap } from "./map/mapView";
import { store } from "./state/store";
import { mountPanel } from "./ui/panel";

const map = createMap(document.getElementById("map")!);
const layers = createLayers();
layers.forEach((l) => l.mount(map));

// Datos -> capas: cada capa se redibuja solo cuando cambian sus entidades o su visibilidad.
store.subscribe((s, prev) => {
  for (const layer of layers) {
    const ents = s.entities[layer.id];
    if (ents && (ents !== prev.entities[layer.id] || s === prev)) layer.update(ents);
    if (s.visible[layer.id] !== prev.visible[layer.id]) layer.setVisible(s.visible[layer.id] ?? true);
  }
});

function onSearch(q: string): void {
  for (const layer of layers) {
    const hit = layer.highlight(q);
    if (hit && q.trim().length >= 3) {
      layer.focus(hit);
      break;
    }
  }
}

mountPanel(document.getElementById("panel")!, store, layers, onSearch);

api.health().then((h) => store.set({ mode: h.mode })).catch(() => store.set({ mode: null }));

new LiveConnection(
  (msg) => (msg.type === "snapshot" ? store.applySnapshot(msg.snapshot.status, msg.snapshot.entities) : store.applyStatus(msg.status)),
  (connection) => store.set({ connection }),
).start();

// Para depurar desde la consola del navegador.
Object.assign(window, { argos: { map, store, layers } });
