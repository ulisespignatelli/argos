import L from "leaflet";
import type { Entity } from "../api/types";
import { popup } from "../map/mapView";
import type { MapLayer } from "./types";

const EMERGENCY = new Set(["7500", "7600", "7700"]);
const num = (v: unknown) => (typeof v === "number" ? v : null);

function icon(track: number | null, color: string): L.DivIcon {
  return L.divIcon({
    className: "plane",
    iconSize: [16, 16],
    iconAnchor: [8, 8],
    html: `<svg width="16" height="16" viewBox="0 0 16 16" style="transform:rotate(${track ?? 0}deg)"><path d="M8 1 L13 14 L8 11 L3 14 Z" fill="${color}"/></svg>`,
  });
}

export class AircraftLayer implements MapLayer {
  readonly id = "aircraft";
  readonly title = "Aviones";
  readonly color = "#4fd1c5";
  private group = L.layerGroup();
  private markers = new Map<string, { marker: L.Marker; entity: Entity }>();
  private map!: L.Map;
  private query = "";

  mount(map: L.Map): void {
    this.map = map;
    this.group.addTo(map);
  }

  setVisible(on: boolean): void {
    on ? this.group.addTo(this.map) : this.group.remove();
  }

  private colorFor(e: Entity): string {
    if (EMERGENCY.has(String(e.attrs.squawk ?? ""))) return "#fc5c4c";
    if (this.query && e.label.toUpperCase().includes(this.query)) return "#ffffff";
    return this.color;
  }

  update(entities: Entity[]): void {
    const seen = new Set<string>();
    for (const e of entities) {
      seen.add(e.id);
      const track = num(e.attrs.track_deg);
      const existing = this.markers.get(e.id);
      if (existing) {
        existing.entity = e;
        existing.marker.setLatLng([e.lat, e.lon]).setIcon(icon(track, this.colorFor(e)));
      } else {
        const entry = { marker: L.marker([e.lat, e.lon], { icon: icon(track, this.colorFor(e)), keyboard: false }), entity: e };
        entry.marker.bindPopup(() => this.popupFor(entry.entity));
        entry.marker.addTo(this.group);
        this.markers.set(e.id, entry);
      }
    }
    for (const [id, { marker }] of this.markers) {
      if (!seen.has(id)) {
        marker.remove();
        this.markers.delete(id);
      }
    }
  }

  private popupFor(e: Entity): HTMLElement {
    const alt = num(e.attrs.altitude_m), spd = num(e.attrs.speed_ms), trk = num(e.attrs.track_deg);
    const squawk = String(e.attrs.squawk ?? "");
    return popup(e.label, [
      ["ICAO24", String(e.attrs.icao24 ?? "—")],
      ["País", String(e.attrs.country ?? "—")],
      ["Altitud", e.attrs.on_ground ? "en tierra" : alt != null ? `${Math.round(alt).toLocaleString("es-AR")} m` : "—"],
      ["Velocidad", spd != null ? `${Math.round(spd * 3.6)} km/h` : "—"],
      ["Rumbo", trk != null ? `${Math.round(trk)}°` : "—"],
      ["Squawk", squawk ? (EMERGENCY.has(squawk) ? `${squawk} (emergencia)` : squawk) : "—"],
    ]);
  }

  highlight(query: string): Entity | null {
    this.query = query.trim().toUpperCase();
    let first: Entity | null = null;
    for (const { marker, entity } of this.markers.values()) {
      const hit = !!this.query && entity.label.toUpperCase().includes(this.query);
      marker.setIcon(icon(num(entity.attrs.track_deg), this.colorFor(entity))).setZIndexOffset(hit ? 1000 : 0);
      if (hit && !first) first = entity;
    }
    return first;
  }

  focus(entity: Entity): void {
    const entry = this.markers.get(entity.id);
    if (!entry) return;
    this.map.flyTo(entry.marker.getLatLng(), Math.max(this.map.getZoom(), 6), { duration: 0.8 });
    entry.marker.openPopup();
  }
}
