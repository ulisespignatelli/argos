import L from "leaflet";

/**
 * Proveedores de mapa base. Se elige con VITE_MAP_TILES en frontend/.env (por defecto "osm-dark").
 * CARTO ahora pide clave; OpenStreetMap y Esri funcionan sin clave para uso personal y de desarrollo.
 */
const OSM_ATTR = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>';

const PROVIDERS: Record<string, { url: string; options: L.TileLayerOptions; dark?: boolean }> = {
  // OpenStreetMap estandar, oscurecido con un filtro CSS (clase .tiles-dark en styles.css).
  "osm-dark": {
    url: "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    options: { maxZoom: 12, attribution: OSM_ATTR },
    dark: true,
  },
  "osm": {
    url: "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    options: { maxZoom: 12, attribution: OSM_ATTR },
  },
  // Esri: gris oscuro nativo.
  "esri-dark": {
    url: "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
    options: { maxZoom: 12, attribution: "Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ" },
  },
};

export function createBaseLayer(): L.TileLayer {
  const name = import.meta.env.VITE_MAP_TILES ?? "osm-dark";
  const p = PROVIDERS[name] ?? PROVIDERS["osm-dark"];
    // OpenStreetMap exige saber desde qué sitio se piden los mapas (cabecera Referer): sin ella, bloquea.
  return L.tileLayer(p.url, {
    minZoom: 2, ...p.options, className: p.dark ? "tiles-dark" : "", referrerPolicy: "strict-origin-when-cross-origin",
  });
}
