import type { ActorProfile, ActorSummary, Entity, LayerStatus, MatrixData, Pivot, PivotKind, ServerMessage } from "./types";

export async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`HTTP ${res.status} en ${path}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => getJSON<{ status: string; mode: string }>("/api/health"),
  layers: () => getJSON<LayerStatus[]>("/api/layers"),
  history: (layer: string, hours = 24) => getJSON<Entity[]>(`/api/history/${layer}?hours=${hours}&limit=10000`),
  pivot: (kind: PivotKind, value: string) =>
    getJSON<Pivot>(`/api/pivot?${new URLSearchParams({ kind, value })}`),
  actors: (activeOnly = false) => getJSON<ActorSummary[]>(`/api/actors?active_only=${activeOnly}`),
  actor: (id: string) => getJSON<ActorProfile>(`/api/actors/${encodeURIComponent(id)}`),
  matrix: (scope: string) => getJSON<MatrixData>(`/api/attack/matrix?scope=${encodeURIComponent(scope)}`),
  reportUrl: "/api/report/weekly.md",
  exportUrl: (format: "c2.csv" | "blocklist.txt" | "stix.json", filter: { malware?: string; country?: string } = {}) => {
    const q = new URLSearchParams(Object.entries(filter).filter(([, v]) => v) as [string, string][]).toString();
    return `/api/export/${format}${q ? `?${q}` : ""}`;
  },
};

export type ConnectionState = "connecting" | "open" | "closed";

/** WebSocket con reconexion automatica (espera creciente, hasta 30 s). */
export class LiveConnection {
  private ws: WebSocket | null = null;
  private retry = 0;
  private pingTimer: number | undefined;
  private stopped = false;

  constructor(
    private onMessage: (msg: ServerMessage) => void,
    private onState: (s: ConnectionState) => void,
  ) {}

  start(): void {
    this.stopped = false;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    this.onState("connecting");
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    this.ws = ws;
    ws.onopen = () => {
      this.retry = 0;
      this.onState("open");
      this.pingTimer = window.setInterval(() => ws.readyState === WebSocket.OPEN && ws.send("ping"), 25000);
    };
    ws.onmessage = (ev) => {
      try {
        this.onMessage(JSON.parse(ev.data) as ServerMessage);
      } catch (err) {
        console.warn("mensaje invalido", err);
      }
    };
    ws.onclose = () => {
      window.clearInterval(this.pingTimer);
      this.onState("closed");
      if (this.stopped) return;
      const wait = Math.min(30000, 1000 * 2 ** this.retry++);
      window.setTimeout(() => this.start(), wait);
    };
  }

  stop(): void {
    this.stopped = true;
    this.ws?.close();
  }
}
