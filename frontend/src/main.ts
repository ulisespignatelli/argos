import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "./styles.css";
import { api, LiveConnection } from "./api/client";
import { createLayers } from "./layers/registry";
import { createMap } from "./map/mapView";
import { store } from "./state/store";
import { mountInvestigation } from "./ui/investigation";
import { mountPanel } from "./ui/panel";
import { createToaster } from "./ui/toast";

const map = createMap(document.getElementById("map")!);
const layers = createLayers((kind, value) => store.investigate(kind, value));
layers.forEach((l) => l.mount(map));

// Estado -> capas: cada capa se redibuja solo cuando cambia lo que le importa.
store.subscribe((s, prev) => {
  const focusIds = s.trail.length && s.pivot ? new Set(s.pivot.entities.map((e) => e.id)) : null;
  for (const layer of layers) {
    const ents = s.entities[layer.id];
    if (ents && (ents !== prev.entities[layer.id] || s === prev)) layer.update(ents);
    if (s.visible[layer.id] !== prev.visible[layer.id]) layer.setVisible(s.visible[layer.id] ?? true);
    const changed = s.search !== prev.search || s.pivot !== prev.pivot || s.trail !== prev.trail || ents !== prev.entities[layer.id];
    if (changed) layer.setFilter({ query: s.search, focusIds });
  }
});

mountPanel(document.getElementById("panel")!, store);
mountInvestigation(document.getElementById("investigation")!, store, map, (e) => layers.find((l) => l.id === e.layer)?.focus(e));
const toast = createToaster(document.getElementById("toasts")!, store);

api.health().then((h) => store.set({ mode: h.mode })).catch(() => store.set({ mode: null }));

new LiveConnection(
  (msg) => {
    switch (msg.type) {
      case "snapshot": return store.applySnapshot(msg.snapshot.status, msg.snapshot.entities);
      case "status": return store.applyStatus(msg.status);
      case "alerts": return store.addAlerts(msg.alerts);
      case "alert":
        store.addAlerts([msg.alert]);
        return toast(msg.alert);
    }
  },
  (connection) => store.set({ connection }),
).start();

// Para depurar desde la consola del navegador.
Object.assign(window, { argos: { map, store, layers, L } });
