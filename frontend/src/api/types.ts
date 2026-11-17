// Contrato con el backend (app/domain/models.py). Si cambia alla, cambia aca.
export interface Entity {
  id: string;
  layer: string;
  lat: number | null; // null: sin ubicacion (p. ej. vulnerabilidades, o IP todavia no geolocalizada)
  lon: number | null;
  label: string;
  observed_at: string;
  attrs: Record<string, unknown>;
}

export interface LayerStatus {
  layer: string;
  source: string;
  updated_at: string | null;
  count: number;
  error: string | null;
}

export interface Snapshot {
  status: LayerStatus;
  entities: Entity[];
}

export type ServerMessage =
  | { type: "snapshot"; snapshot: Snapshot }
  | { type: "status"; status: LayerStatus };

/** Lectura segura de atributos: los datos vienen de fuentes externas. */
export const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));
export const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
