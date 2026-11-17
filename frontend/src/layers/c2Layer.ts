import type L from "leaflet";
import { num, str, type Entity } from "../api/types";
import { popup } from "../map/mapView";
import { defang, familyColor, safeLink, shortDate } from "../util/format";
import { actions, PointLayer } from "./pointLayer";
import type { Investigate } from "./types";

/** Servidores de comando y control: un punto por indicador, coloreado por familia de malware. */
export class C2Layer extends PointLayer {
  readonly id = "c2";
  readonly title = "Servidores C2";
  readonly color = "#fc5c65";

  constructor(private investigate: Investigate) {
    super();
  }

  protected baseStyle(e: Entity): L.CircleMarkerOptions {
    const color = familyColor(str(e.attrs.malware));
    return { radius: 5, color, weight: 1, fillColor: color, fillOpacity: 0.75, opacity: 1 };
  }

  protected searchText(e: Entity): string {
    return [e.attrs.ip, e.attrs.malware, e.attrs.country, e.attrs.org, e.attrs.asn].map(str).join(" ");
  }

  protected popupFor(e: Entity): HTMLElement {
    const a = e.attrs;
    const port = num(a.port);
    const conf = num(a.confidence);
    const ip = str(a.ip), asn = str(a.asn), fam = str(a.malware);
    const tags = Array.isArray(a.tags) ? a.tags.map(str).filter(Boolean).join(", ") : "";
    const first = str(a.first_seen);
    const buttons: [string, () => void][] = [["Investigar IP", () => this.investigate("ip", ip)]];
    if (asn) buttons.push(["Investigar red", () => this.investigate("asn", asn)]);
    if (fam) buttons.push([`Investigar ${fam}`, () => this.investigate("malware", fam)]);
    return popup(fam || "Servidor C2", [
      ["IOC", defang(ip) + (port != null ? `:${port}` : "")],
      ["Tipo", str(a.threat_type) || "—"],
      ["Confianza", conf != null ? `${conf}%` : "—"],
      ["Ubicación", [str(a.city), str(a.country)].filter(Boolean).join(", ") || "—"],
      ["Red", [asn, str(a.org)].filter(Boolean).join(" · ") || "—"],
      ["Primera vez", first ? shortDate(first) : "—"],
      ["Reportó", str(a.reporter) || "—"],
      ["Etiquetas", tags || "—"],
    ], actions(buttons, safeLink(str(a.source_url), "ThreatFox ↗")));
  }
}
