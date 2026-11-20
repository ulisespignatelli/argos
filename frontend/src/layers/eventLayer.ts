import L from "leaflet";
import { eventAttrs, type Entity } from "../api/types";
import { CATEGORY } from "../state/selectors";
import { popup } from "../map/mapView";
import { arc } from "./incidentLayer";
import { PointLayer } from "./pointLayer";

/**
 * Eventos de avisos y noticias, ubicados en el pais afectado. Borde lleno = verificado; punteado = 1 fuente.
 * Los eventos sin pais (globales) no van al mapa: aparecen en la franja de destacados y en la pestaña Eventos.
 */
export class EventLayer extends PointLayer {
  readonly id = "events";
  readonly title = "Eventos";
  readonly color = "#ffffff";
  private arcs = L.layerGroup();

  constructor(private onSelect: (e: Entity) => void) {
    super();
  }

  mount(map: L.Map): void {
    super.mount(map);
    this.arcs.addTo(map);
  }

  protected bindMarker(entry: { marker: L.CircleMarker; entity: Entity }): void {
    entry.marker.on("click", () => this.onSelect(entry.entity));
    entry.marker.bindTooltip(() => eventAttrs(entry.entity).title, { direction: "top", offset: [0, -8], className: "ev-tip" });
  }

  protected baseStyle(e: Entity): L.CircleMarkerOptions {
    const a = eventAttrs(e);
    const color = CATEGORY[a.kind]?.color ?? "#ffffff";
    const ok = a.status === "verificado";
    return { radius: ok ? 8 : 6.5, color, weight: 2.5, opacity: 1, dashArray: ok ? undefined : "3 3",
      fillColor: "#0b1218", fillOpacity: 0.85 };
  }

  protected searchText(e: Entity): string {
    const a = eventAttrs(e);
    return [a.title, a.kind_label, ...a.cves.map((c) => c.id), ...a.actors.map((x) => x.name),
      ...a.malware.map((x) => x.name), ...a.countries.map((c) => c.name)].join(" ");
  }

  update(entities: Entity[]): void {
    super.update(entities);
    this.arcs.clearLayers();
    for (const e of entities) {
      const o = eventAttrs(e).origin;
      if (!o || e.lat == null || e.lon == null) continue;
      L.polyline(arc([o.lat, o.lon], [e.lat, e.lon]), { color: CATEGORY[eventAttrs(e).kind]?.color ?? "#ff9ff3",
        weight: 1.2, opacity: 0.5, dashArray: "2 6", interactive: false }).addTo(this.arcs);
    }
  }

  setVisible(on: boolean): void {
    super.setVisible(on);
    on ? this.arcs.addTo(this.map) : this.arcs.remove();
  }

  protected popupFor(e: Entity): HTMLElement {
    const a = eventAttrs(e);
    return popup(a.title, [["Tipo", a.kind_label]]);
  }
}
