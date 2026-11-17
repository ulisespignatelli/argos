import type L from "leaflet";
import type { Entity } from "../api/types";

/** Contrato de toda capa del mapa. El mapa no sabe que capas existen: solo las monta. */
export interface MapLayer {
  readonly id: string; // igual al "layer" del backend
  readonly title: string;
  readonly color: string;
  mount(map: L.Map): void;
  setVisible(on: boolean): void;
  update(entities: Entity[]): void;
  setFilter(filter: { query: string; family: string | null }): Entity | null; // devuelve la primera coincidencia
  focus(entity: Entity): void;
}
