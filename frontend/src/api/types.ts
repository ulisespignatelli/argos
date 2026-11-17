// Contrato con el backend (app/domain/models.py). Si cambia alla, cambia aca.
export interface Entity {
  id: string;
  layer: string;
  lat: number;
  lon: number;
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
