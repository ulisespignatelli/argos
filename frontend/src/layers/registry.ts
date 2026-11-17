import { C2Layer } from "./c2Layer";
import type { Investigate, MapLayer } from "./types";
import { UrlLayer } from "./urlLayer";

/** Unico lugar donde se listan las capas del mapa. Sumar una capa = crear su clase y agregarla aca. */
export function createLayers(investigate: Investigate): MapLayer[] {
  return [new UrlLayer(investigate), new C2Layer(investigate)];
}
