import L from "leaflet";
import type { Entity } from "../api/types";
import type { LayerFilter, MapLayer } from "./types";

/**
 * Base comun de las capas de puntos: alta, baja y actualizacion de marcadores, filtro y foco.
 * Cada capa concreta solo define como se ve un punto y que muestra su ficha.
 */
export abstract class PointLayer implements MapLayer {
  abstract readonly id: string;
  abstract readonly title: string;
  abstract readonly color: string;
  protected group = L.layerGroup();
  protected markers = new Map<string, { marker: L.CircleMarker; entity: Entity }>();
  protected map!: L.Map;
  protected filter: LayerFilter = { query: "", focusIds: null };

  protected abstract baseStyle(e: Entity): L.CircleMarkerOptions;
  protected abstract searchText(e: Entity): string;
  protected abstract popupFor(e: Entity): HTMLElement;

  /** Que pasa al hacer clic en un punto: por defecto, una ficha emergente. */
  protected bindMarker(entry: { marker: L.CircleMarker; entity: Entity }): void {
    entry.marker.bindPopup(() => this.popupFor(entry.entity), { maxWidth: 340 });
  }

  mount(map: L.Map): void {
    this.map = map;
    this.group.addTo(map);
  }

  setVisible(on: boolean): void {
    on ? this.group.addTo(this.map) : this.group.remove();
  }

  protected matches(e: Entity): boolean {
    const q = this.filter.query.trim().toLowerCase();
    return q.length > 0 && this.searchText(e).toLowerCase().includes(q);
  }

  private style(e: Entity): L.CircleMarkerOptions {
    const base = this.baseStyle(e);
    const focus = this.filter.focusIds;
    const dimmed = focus !== null && !focus.has(e.id);
    const hit = this.matches(e) || (focus !== null && focus.has(e.id));
    return {
      ...base,
      ...(hit ? { color: "#ffffff", weight: 2, radius: (base.radius ?? 5) + 3 } : {}),
      ...(dimmed ? { fillOpacity: 0.08, opacity: 0.15 } : {}),
    };
  }

  update(entities: Entity[]): void {
    const seen = new Set<string>();
    for (const e of entities) {
      if (e.lat == null || e.lon == null) continue; // sin ubicacion: solo aparece en los paneles
      seen.add(e.id);
      const existing = this.markers.get(e.id);
      if (existing) {
        existing.entity = e;
        existing.marker.setLatLng([e.lat, e.lon]).setStyle(this.style(e));
      } else {
        const entry = { marker: L.circleMarker([e.lat, e.lon], this.style(e)), entity: e };
        this.bindMarker(entry);
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

  setFilter(filter: LayerFilter): Entity | null {
    this.filter = filter;
    let first: Entity | null = null;
    for (const { marker, entity } of this.markers.values()) {
      marker.setStyle(this.style(entity));
      const hit = this.matches(entity) || (filter.focusIds?.has(entity.id) ?? false);
      if (hit) {
        marker.bringToFront();
        if (!first && this.matches(entity)) first = entity;
      }
    }
    return first;
  }

  focus(entity: Entity): void {
    const entry = this.markers.get(entity.id);
    if (!entry) return;
    this.map.flyTo(entry.marker.getLatLng(), Math.max(this.map.getZoom(), 5), { duration: 0.8 });
    if (entry.marker.getPopup()) entry.marker.openPopup();
  }
}

/** Fila de botones "Investigar ..." para las fichas del mapa. */
export function actions(buttons: [string, () => void][], link?: HTMLElement | null): HTMLElement {
  const box = document.createElement("div");
  box.className = "actions";
  for (const [text, fn] of buttons) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = text;
    b.addEventListener("click", fn);
    box.append(b);
  }
  if (link) box.append(link);
  return box;
}
