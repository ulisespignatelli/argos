import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "./styles.css";
import { api, LiveConnection } from "./api/client";
import { HeatLayer } from "./layers/heatLayer";
import { createLayers, LAYER_CATEGORY } from "./layers/registry";
import { createMap } from "./map/mapView";
import { on, visibleEvents, visibleIncidents, WINDOWS } from "./state/selectors";
import { store } from "./state/store";
import { mountHighlights } from "./ui/highlights";
import { mountInvestigation } from "./ui/investigation";
import { mountOverlays } from "./ui/overlays";
import { mountPanel } from "./ui/panel";
import { createToaster } from "./ui/toast";
import { mountTopbar } from "./ui/topbar";

const map = createMap(document.getElementById("map")!);
const layers = createLayers((kind, value, fresh, label) => store.investigate(kind, value, fresh, label), (e) => store.select(e));
layers.forEach((l) => l.mount(map));
const focusEntity = (e: { layer: string } & Parameters<(typeof layers)[number]["focus"]>[0]) =>
  layers.find((l) => l.id === e.layer)?.focus(e);

const LATAM_BOUNDS = L.latLngBounds([-56, -118], [33, -32]);

const heat = new HeatLayer();
heat.addTo(map);

// Estado -> capas: cada capa se redibuja solo cuando cambia lo que le importa.
store.subscribe((s, prev) => {
  const focusIds = s.trail.length && s.pivot ? new Set(s.pivot.entities.map((e) => e.id)) : null;
  const windowChanged = s === prev || s.history !== prev.history || s.timeWindow !== prev.timeWindow;
  // Ataques y eventos salen de la ventana de tiempo (actual + historial); los eventos, ademas, de su tipo.
  const incidentsChanged = windowChanged || s.entities.incidents !== prev.entities.incidents || s.sector !== prev.sector;
  const eventsChanged = windowChanged || s.entities.events !== prev.entities.events || s.visible !== prev.visible;
  for (const layer of layers) {
    const id = layer.id;
    const ents = id === "incidents" ? (incidentsChanged ? visibleIncidents(s) : undefined)
      : id === "events" ? (eventsChanged ? visibleEvents(s) : undefined)
        : (s.entities[id] !== prev.entities[id] || s === prev ? s.entities[id] : undefined);
    if (ents) layer.update(ents);
    const cat = LAYER_CATEGORY[id];
    if (cat && (s === prev || on(s, cat) !== on(prev, cat))) layer.setVisible(on(s, cat));
    const changed = s.search !== prev.search || s.pivot !== prev.pivot || s.trail !== prev.trail || s.selected !== prev.selected
      || ents !== undefined;
    const ids = focusIds ?? (s.selected ? new Set([s.selected.id]) : null);
    if (changed) layer.setFilter({ query: s.search, focusIds: ids });
  }
  // Mapa de calor: todo lo que esta encendido y tiene ubicacion.
  if (s.heat !== prev.heat || s === prev || incidentsChanged || eventsChanged || s.visible !== prev.visible
      || s.entities.c2 !== prev.entities.c2 || s.entities.urls !== prev.entities.urls) {
    const pts = s.heat === "off" ? [] : [
      ...(on(s, "ransomware") ? visibleIncidents(s) : []), ...visibleEvents(s),
      ...(on(s, "c2") ? s.entities.c2 ?? [] : []), ...(on(s, "urls") ? s.entities.urls ?? [] : [])];
    heat.set(pts, s.heat);
    document.body.classList.toggle("heat-on", s.heat !== "off");
  }
  if (s.region !== prev.region) {
    if (s.region === "latam") map.flyToBounds(LATAM_BOUNDS, { duration: 0.9, paddingTopLeft: [360, 90] });
    else map.flyTo([25, 10], 2, { duration: 0.9 });
  }
});

mountTopbar(document.getElementById("topbar")!, store);
mountPanel(document.getElementById("panel")!, store, focusEntity);
mountInvestigation(document.getElementById("investigation")!, store, map, focusEntity);
mountOverlays(document.getElementById("overlay")!, store);
const toast = createToaster(document.getElementById("toasts")!, store);
mountHighlights(document.getElementById("highlights")!, document.getElementById("legend")!, store);

// Historial para las ventanas de tiempo: se pide al cambiar la ventana y cada 5 minutos.
async function loadHistory(): Promise<void> {
  const hours = Math.round(WINDOWS[store.get().timeWindow].ms / 3600000);
  try {
    const [incidents, kev, events] = await Promise.all(
      [api.history("incidents", hours), api.history("kev", hours), api.history("events", hours)]);
    store.set({ history: { incidents, kev, events } });
  } catch {
    /* sin historial: se muestra solo lo actual */
  }
}
store.subscribe((s, prev) => {
  if (s.timeWindow !== prev.timeWindow) void loadHistory();
});
void loadHistory();
window.setInterval(() => void loadHistory(), 300000);

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
Object.assign(window, { argos: { map, store, layers, heat, L } });
