import L from "leaflet";
import { str, type Entity } from "../api/types";
import { popup } from "../map/mapView";
import { ageDays } from "../state/selectors";
import { safeLink, shortDate, timeAgo } from "../util/format";
import { actions, PointLayer } from "./pointLayer";
import type { Investigate } from "./types";

const RED = "#ff4757";
/** Color por antigüedad: hasta 30 días, de 31 a 120, y más viejo (contexto). */
export const AGE = [{ max: 30, color: "#ff4757", label: "≤ 30 días" }, { max: 120, color: "#ffa502", label: "31–120 días" },
  { max: Infinity, color: "#dfe6e9", label: "> 120 días" }];
const ageColor = (iso: string) => AGE.find((a) => ageDays(iso) <= a.max)!.color;

/** Curva entre dos puntos (bezier cuadratica), por el lado corto del planeta. */
export function arc(a: [number, number], b: [number, number]): [number, number][] {
  const [lat2, lon2] = b;
  const [lat1, lon1] = a;
  // Sin dar la vuelta al antimeridiano: el arco termina siempre sobre el marcador visible.
  const mx = (lat1 + lat2) / 2, my = (lon1 + lon2) / 2;
  const dx = lat2 - lat1, dy = lon2 - lon1;
  const bend = 0.22; // cuanto se curva el arco
  const cx = mx - dy * bend, cy = my + dx * bend;
  const pts: [number, number][] = [];
  for (let i = 0; i <= 40; i++) {
    const t = i / 40;
    pts.push([(1 - t) ** 2 * lat1 + 2 * (1 - t) * t * cx + t * t * lat2, (1 - t) ** 2 * lon1 + 2 * (1 - t) * t * cy + t * t * lon2]);
  }
  return pts;
}

/**
 * Victimas de ransomware reivindicadas por los grupos. Se dibujan con un halo segun lo reciente.
 * Si el grupo tiene un pais atribuido (MISP), se traza un arco desde ese origen: nunca se inventa uno.
 */
export class IncidentLayer extends PointLayer {
  readonly id = "incidents";
  readonly title = "Ataques reivindicados";
  readonly color = RED;
  private arcs = L.layerGroup();

  constructor(private investigate: Investigate, private onSelect: (e: Entity) => void) {
    super();
  }

  mount(map: L.Map): void {
    super.mount(map);
    this.arcs.addTo(map);
  }

  /** Los ataques no abren una ficha emergente: abren la ficha completa en el panel derecho. */
  protected bindMarker(entry: { marker: L.CircleMarker; entity: Entity }): void {
    entry.marker.on("click", () => this.onSelect(entry.entity));
  }

  setVisible(on: boolean): void {
    super.setVisible(on);
    on ? this.arcs.addTo(this.map) : this.arcs.remove();
  }

  protected baseStyle(e: Entity): L.CircleMarkerOptions {
    const days = ageDays(e.observed_at);
    const color = ageColor(e.observed_at);
    // Halo ancho y translucido para lo de las ultimas 72 horas.
    const fresh = days <= 3;
    return { radius: fresh ? 7 : days <= 30 ? 5.5 : 4, color, weight: fresh ? 7 : 1, opacity: fresh ? 0.28 : 0.7,
      fillColor: color, fillOpacity: fresh ? 0.95 : days <= 120 ? 0.75 : 0.55 };
  }

  protected searchText(e: Entity): string {
    return [e.attrs.victim, e.attrs.group, e.attrs.country, e.attrs.sector, ...(e.attrs.actor_names as string[] ?? [])].map(str).join(" ");
  }

  update(entities: Entity[]): void {
    super.update(entities);
    this.arcs.clearLayers();
    for (const e of entities) {
      const o = e.attrs.origin as { lat: number; lon: number; name: string } | undefined;
      if (!o || e.lat == null || e.lon == null) continue;
      L.polyline(arc([o.lat, o.lon], [e.lat, e.lon]), { color: RED, weight: 1.3, opacity: 0.55, dashArray: "4 6", interactive: false })
        .addTo(this.arcs);
      L.circleMarker([o.lat, o.lon], { radius: 4, color: "#ff9ff3", weight: 1.5, fillColor: "#ff9ff3", fillOpacity: 0.35, interactive: false })
        .addTo(this.arcs);
    }
  }

  protected popupFor(e: Entity): HTMLElement {
    const a = e.attrs;
    const group = str(a.group);
    const actors = (a.actors as string[] | undefined) ?? [];
    const names = (a.actor_names as string[] | undefined) ?? [];
    const origin = a.origin as { name: string } | undefined;
    const buttons: [string, () => void][] = [[`Investigar ${group}`, () => this.investigate("malware", group)]];
    if (actors[0]) buttons.push([`Perfil de ${names[0] ?? actors[0]}`, () => this.investigate("actor", actors[0], false, names[0])]);
    return popup(str(a.victim) || "Víctima", [
      ["Grupo", group || "—"],
      ["Estado", "Reivindicado por el grupo · sin confirmar"],
      ["Sector", str(a.sector) || "—"],
      ["País", str(a.country) || str(a.country_code) || "—"],
      ["Publicado", `${shortDate(e.observed_at)} (${timeAgo(e.observed_at)})`],
      ["Origen", origin ? `${origin.name} (atribución según MISP)` : "Sin atribución de país"],
      ["ATT&CK", names.length ? names.slice(0, 3).join(", ") : "Sin perfil en MITRE ATT&CK"],
      ["Fuente", str(a.source) || "ransomware.live"],
    ], actions(buttons, safeLink(str(a.source_url), "ransomware.live ↗")));
  }
}
