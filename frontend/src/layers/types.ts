import type L from "leaflet";
import type { Entity, PivotKind } from "../api/types";

export interface LayerFilter {
  query: string;
  focusIds: Set<string> | null; // investigacion activa: se resaltan estas entidades y se atenuan las demas
}

export type Investigate = (kind: PivotKind, value: string, fresh?: boolean, label?: string) => void;

/** Contrato de toda capa del mapa. El mapa no sabe que capas existen: solo las monta. */
export interface MapLayer {
  readonly id: string; // igual al "layer" del backend
  readonly title: string;
  readonly color: string;
  mount(map: L.Map): void;
  setVisible(on: boolean): void;
  update(entities: Entity[]): void;
  setFilter(filter: LayerFilter): Entity | null; // devuelve la primera coincidencia de la busqueda
  focus(entity: Entity): void;
}
