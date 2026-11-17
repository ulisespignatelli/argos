import L from "leaflet";
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

// Estado -> capas: cada capa se redibuja solo cuando cambia lo que le importa.
let lastFocused = "";
store.subscribe((s, prev) => {
  for (const layer of layers) {
    const ents = s.entities[layer.id];
    if (ents && (ents !== prev.entities[layer.id] || s === prev)) layer.update(ents);
    if (s.visible[layer.id] !== prev.visible[layer.id]) layer.setVisible(s.visible[layer.id] ?? true);
    const filterChanged = s.search !== prev.search || s.family !== prev.family || ents !== prev.entities[layer.id];
    if (filterChanged) {
      const hit = layer.setFilter({ query: s.search, family: s.family });
      // Vuela a la primera coincidencia solo cuando cambia la busqueda (no en cada actualizacion de datos).
      if (hit && s.search !== prev.search && s.search.trim().length >= 3 && hit.id !== lastFocused) {
        lastFocused = hit.id;
        layer.focus(hit);
      }
    }
  }
});

mountPanel(document.getElementById("panel")!, store, layers);

api.health().then((h) => store.set({ mode: h.mode })).catch(() => store.set({ mode: null }));

new LiveConnection(
  (msg) => (msg.type === "snapshot" ? store.applySnapshot(msg.snapshot.status, msg.snapshot.entities) : store.applyStatus(msg.status)),
  (connection) => store.set({ connection }),
).start();

// Para depurar desde la consola del navegador.
Object.assign(window, { argos: { map, store, layers, L } });
