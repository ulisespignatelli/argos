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

export type Severity = "alta" | "media" | "baja";

export interface Alert {
  id: string;
  at: string;
  severity: Severity;
  rule: string;
  title: string;
  detail: string;
  pivot_kind: PivotKind | "event" | null; // "event": abre la ficha del evento
  pivot_value: string | null;
}

export type PivotKind = "ip" | "asn" | "country" | "malware" | "host" | "actor";

export interface Pivot {
  kind: PivotKind;
  value: string;
  total: number;
  groups: { kind: PivotKind; label: string; items: { value: string; count: number; label?: string | null }[] }[];
  entities: Entity[];
}

export type ServerMessage =
  | { type: "snapshot"; snapshot: Snapshot }
  | { type: "status"; status: LayerStatus }
  | { type: "alert"; alert: Alert }
  | { type: "alerts"; alerts: Alert[] };

/** Lectura segura de atributos: los datos vienen de fuentes externas. */
export const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));
export const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export interface ActorSummary {
  id: string;
  name: string;
  aliases: string[];
  country: string | null;
  country_name: string | null;
  sponsor: string | null;
  url: string;
  active: { c2: number; urls: number; incidents: number };
  direct: number;        // indicadores atribuidos directamente al grupo
  via_software: number;  // indicadores de software que el grupo usa (inferido)
  relevance: number;     // ponderada por exclusividad del software
  activity: number;
  techniques: number;
}

export interface ActorProfile extends Omit<ActorSummary, "activity" | "techniques" | "via_software" | "relevance"> {
  description: string;
  techniques: { id: string; name: string; tactics: string[] }[];
  software: { id: string; name: string; type: string; active: number }[];
  incidents: Entity[];
}

export interface MatrixData {
  scope: string;
  label: string;
  max: number;
  attack_version: string;
  tactics: { id: string; short: string; name: string; name_es: string; used: number;
    techniques: { id: string; name: string; score: number; top: string[] }[] }[];
}

/** Evento armado a partir de avisos y noticias (layer "events"). */
export interface EventSource { name: string; url: string; title: string; published: string; official: boolean }
export interface EventCve { id: string; kev: boolean; registry: "publicado" | "sin_registro" | "rechazado" | null }
export interface EventAttrs {
  kind: string; kind_label: string; types: string[]; title: string; sources: EventSource[]; n_sources: number;
  status: "verificado" | "una_fuente"; status_reason: string; cves: EventCve[]; exploited: boolean;
  actors: { id: string; name: string }[]; malware: { id: string; name: string }[];
  countries: { code: string; name: string }[]; country_code: string | null;
  origin: { country: string; name: string; lat: number; lon: number; actor: string | null } | null;
  reasons: string[]; global: boolean; source_url: string;
}
export const eventAttrs = (e: Entity): EventAttrs => e.attrs as unknown as EventAttrs;
