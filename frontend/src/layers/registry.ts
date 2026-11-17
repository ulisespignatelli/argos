import { AircraftLayer } from "./aircraftLayer";
import { EarthquakeLayer } from "./earthquakeLayer";
import type { MapLayer } from "./types";

/** Unico lugar donde se listan las capas. Sumar una capa = crear su clase y agregarla aca. */
export function createLayers(): MapLayer[] {
  return [new AircraftLayer(), new EarthquakeLayer()];
}
