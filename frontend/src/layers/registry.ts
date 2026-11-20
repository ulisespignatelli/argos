import { C2Layer } from "./c2Layer";
import { EventLayer } from "./eventLayer";
import { IncidentLayer } from "./incidentLayer";
import type { Entity } from "../api/types";
import type { Investigate, MapLayer } from "./types";
import { UrlLayer } from "./urlLayer";

/** Unico lugar donde se listan las capas del mapa. Sumar una capa = crear su clase y agregarla aca. */
export function createLayers(investigate: Investigate, onSelect: (e: Entity) => void): MapLayer[] {
  return [new UrlLayer(investigate), new C2Layer(investigate), new IncidentLayer(investigate, onSelect), new EventLayer(onSelect)];
}

/** Que capa de tipo de ataque prende o apaga cada capa del mapa (los eventos se filtran por tipo). */
export const LAYER_CATEGORY: Record<string, string | null> = { urls: "urls", c2: "c2", incidents: "ransomware", events: null };
