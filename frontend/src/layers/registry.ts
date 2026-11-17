import { C2Layer } from "./c2Layer";
import type { MapLayer } from "./types";

/** Unico lugar donde se listan las capas del mapa. Sumar una capa = crear su clase y agregarla aca. */
export function createLayers(): MapLayer[] {
  return [new C2Layer()];
}
