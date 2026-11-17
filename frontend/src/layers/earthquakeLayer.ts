import L from "leaflet";
import type { Entity } from "../api/types";
import { popup } from "../map/mapView";
import type { MapLayer } from "./types";

const colorFor = (mag: number) => (mag >= 6 ? "#f56565" : mag >= 4.5 ? "#ed8936" : "#f6ad55");

export class EarthquakeLayer implements MapLayer {
  readonly id = "earthquakes";
  readonly title = "Terremotos (24 h)";
  readonly color = "#f6ad55";
  private group = L.layerGroup();
  private markers = new Map<string, L.CircleMarker>();
  private map!: L.Map;

  mount(map: L.Map): void {
    this.map = map;
    this.group.addTo(map);
  }

  setVisible(on: boolean): void {
    on ? this.group.addTo(this.map) : this.group.remove();
  }

  update(entities: Entity[]): void {
    this.group.clearLayers();
    this.markers.clear();
    for (const e of entities) {
      const mag = typeof e.attrs.mag === "number" ? e.attrs.mag : 0;
      const depth = typeof e.attrs.depth_km === "number" ? `${Math.round(e.attrs.depth_km)} km` : "—";
      const m = L.circleMarker([e.lat, e.lon], {
        radius: Math.max(3, mag * 2.2), color: colorFor(mag), weight: 1, fillColor: colorFor(mag), fillOpacity: 0.3,
      }).bindPopup(() => popup(`Terremoto M ${mag.toFixed(1)}`, [
        ["Lugar", String(e.attrs.place ?? "—")],
        ["Hora", new Date(e.observed_at).toLocaleString("es-AR", { hour12: false })],
        ["Profundidad", depth],
      ]));
      m.addTo(this.group);
      this.markers.set(e.id, m);
    }
  }

  highlight(): Entity | null {
    return null;
  }

  focus(entity: Entity): void {
    const m = this.markers.get(entity.id);
    if (!m) return;
    this.map.flyTo(m.getLatLng(), Math.max(this.map.getZoom(), 6), { duration: 0.8 });
    m.openPopup();
  }
}
