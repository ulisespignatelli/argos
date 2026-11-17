import type L from "leaflet";
import { str, type Entity } from "../api/types";
import { popup } from "../map/mapView";
import { defang, safeLink, shortDate } from "../util/format";
import { actions, PointLayer } from "./pointLayer";
import type { Investigate } from "./types";

/** URLs de descarga de malware alojadas directamente en una IP (las de dominio van al panel). */
export class UrlLayer extends PointLayer {
  readonly id = "urls";
  readonly title = "URLs de malware";
  readonly color = "#fed330";

  constructor(private investigate: Investigate) {
    super();
  }

  protected baseStyle(e: Entity): L.CircleMarkerOptions {
    const online = str(e.attrs.status) === "online";
    return { radius: 3.5, color: "#fed330", weight: 1, fillColor: "#fed330", fillOpacity: online ? 0.9 : 0.25,
      opacity: online ? 1 : 0.5, dashArray: online ? undefined : "2 2" };
  }

  protected searchText(e: Entity): string {
    return [e.attrs.url, e.attrs.host, e.attrs.country, e.attrs.org, e.attrs.asn].map(str).join(" ");
  }

  protected popupFor(e: Entity): HTMLElement {
    const a = e.attrs;
    const ip = str(a.ip), asn = str(a.asn);
    const tags = Array.isArray(a.tags) ? a.tags.map(str).filter(Boolean).join(", ") : "";
    const buttons: [string, () => void][] = [["Investigar IP", () => this.investigate("ip", ip)]];
    if (asn) buttons.push(["Investigar red", () => this.investigate("asn", asn)]);
    return popup("URL de malware", [
      ["URL", defang(str(a.url))],
      ["Estado", str(a.status) === "online" ? "activa" : "caída"],
      ["Ubicación", [str(a.city), str(a.country)].filter(Boolean).join(", ") || "—"],
      ["Red", [asn, str(a.org)].filter(Boolean).join(" · ") || "—"],
      ["Agregada", shortDate(e.observed_at)],
      ["Etiquetas", tags || "—"],
    ], actions(buttons, safeLink(str(a.source_url), "URLhaus ↗")));
  }
}
