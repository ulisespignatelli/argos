import L from "leaflet";
import { num, str, type Entity } from "../api/types";
import { popup } from "../map/mapView";
import { defang, familyColor, safeLink, shortDate } from "../util/format";
import type { MapLayer } from "./types";

/** Servidores de comando y control: un punto por IP, coloreado por familia de malware. */
export class C2Layer implements MapLayer {
  readonly id = "c2";
  readonly title = "Servidores C2";
  readonly color = "#fc5c65";
  private group = L.layerGroup();
  private markers = new Map<string, { marker: L.CircleMarker; entity: Entity }>();
  private map!: L.Map;
  private query = "";
  private family: string | null = null;

  mount(map: L.Map): void {
    this.map = map;
    this.group.addTo(map);
  }

  setVisible(on: boolean): void {
    on ? this.group.addTo(this.map) : this.group.remove();
  }

  private matches(e: Entity): boolean {
    if (!this.query) return false;
    const hay = [e.attrs.ip, e.attrs.malware, e.attrs.country, e.attrs.org, e.attrs.asn].map(str).join(" ").toLowerCase();
    return hay.includes(this.query);
  }

  private style(e: Entity): L.CircleMarkerOptions {
    const color = familyColor(str(e.attrs.malware));
    const hidden = this.family !== null && str(e.attrs.malware) !== this.family;
    const hit = this.matches(e);
    return {
      radius: hit ? 8 : 5, color: hit ? "#ffffff" : color, weight: hit ? 2 : 1,
      fillColor: color, fillOpacity: hidden ? 0 : 0.75, opacity: hidden ? 0 : 1,
    };
  }

  update(entities: Entity[]): void {
    const seen = new Set<string>();
    for (const e of entities) {
      if (e.lat == null || e.lon == null) continue; // sin geolocalizar: solo aparece en el panel
      seen.add(e.id);
      const existing = this.markers.get(e.id);
      if (existing) {
        existing.entity = e;
        existing.marker.setLatLng([e.lat, e.lon]).setStyle(this.style(e));
      } else {
        const entry = { marker: L.circleMarker([e.lat, e.lon], this.style(e)), entity: e };
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
    const a = e.attrs;
    const port = num(a.port);
    const conf = num(a.confidence);
    const place = [str(a.city), str(a.country)].filter(Boolean).join(", ");
    const net = [str(a.asn), str(a.org)].filter(Boolean).join(" · ");
    const tags = Array.isArray(a.tags) ? a.tags.map(str).filter(Boolean).join(", ") : "";
    const first = str(a.first_seen);
    return popup(str(a.malware) || "Servidor C2", [
      ["IOC", defang(str(a.ip)) + (port != null ? `:${port}` : "")],
      ["Tipo", str(a.threat_type) || "—"],
      ["Confianza", conf != null ? `${conf}%` : "—"],
      ["Ubicación", place || "—"],
      ["Red", net || "—"],
      ["Primera vez", first ? shortDate(first) : "—"],
      ["Reportó", str(a.reporter) || "—"],
      ["Etiquetas", tags || "—"],
    ], safeLink(str(a.source_url), "Ver en ThreatFox"));
  }

  setFilter(filter: { query: string; family: string | null }): Entity | null {
    this.query = filter.query.trim().toLowerCase();
    this.family = filter.family;
    let first: Entity | null = null;
    for (const { marker, entity } of this.markers.values()) {
      marker.setStyle(this.style(entity));
      if (this.matches(entity)) {
        marker.bringToFront();
        if (!first) first = entity;
      }
    }
    return first;
  }

  focus(entity: Entity): void {
    const entry = this.markers.get(entity.id);
    if (!entry) return;
    this.map.flyTo(entry.marker.getLatLng(), Math.max(this.map.getZoom(), 5), { duration: 0.8 });
    entry.marker.openPopup();
  }
}
