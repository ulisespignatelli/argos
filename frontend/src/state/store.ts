import type { Alert, Entity, LayerStatus, Pivot, PivotKind } from "../api/types";
import type { ConnectionState } from "../api/client";

export interface Investigation {
  kind: PivotKind;
  value: string;
}

export interface State {
  connection: ConnectionState;
  mode: string | null;
  statuses: Record<string, LayerStatus>;
  entities: Record<string, Entity[]>;
  visible: Record<string, boolean>;
  search: string;
  alerts: Alert[];
  trail: Investigation[]; // recorrido de la investigacion; el ultimo es el actual
  pivot: Pivot | null;
  pivotError: string | null;
}

type Listener = (s: State, prev: State) => void;

/** Estado global minimo: inmutable, con suscripcion. Las vistas solo leen y piden cambios. */
export class Store {
  private state: State = {
    connection: "connecting", mode: null, statuses: {}, entities: {}, visible: {}, search: "",
    alerts: [], trail: [], pivot: null, pivotError: null,
  };
  private listeners = new Set<Listener>();

  get(): State {
    return this.state;
  }

  set(patch: Partial<State>): void {
    const prev = this.state;
    this.state = { ...prev, ...patch };
    this.listeners.forEach((l) => l(this.state, prev));
  }

  subscribe(l: Listener): () => void {
    this.listeners.add(l);
    l(this.state, this.state);
    return () => this.listeners.delete(l);
  }

  applySnapshot(status: LayerStatus, entities: Entity[]): void {
    const s = this.state;
    this.set({
      statuses: { ...s.statuses, [status.layer]: status },
      entities: { ...s.entities, [status.layer]: entities },
      visible: status.layer in s.visible ? s.visible : { ...s.visible, [status.layer]: true },
    });
  }

  applyStatus(status: LayerStatus): void {
    this.set({ statuses: { ...this.state.statuses, [status.layer]: status } });
  }

  addAlerts(alerts: Alert[]): void {
    const known = new Set(this.state.alerts.map((a) => a.id));
    const fresh = alerts.filter((a) => !known.has(a.id));
    if (fresh.length) this.set({ alerts: [...fresh, ...this.state.alerts].sort((a, b) => b.at.localeCompare(a.at)).slice(0, 200) });
  }

  toggle(layer: string, on: boolean): void {
    this.set({ visible: { ...this.state.visible, [layer]: on } });
  }

  /** Abre una investigacion. `fresh` reinicia el recorrido; si no, se agrega como un paso mas. */
  investigate(kind: PivotKind, value: string, fresh = false): void {
    const cur = this.state.trail.at(-1);
    if (!fresh && cur && cur.kind === kind && cur.value === value) return;
    this.set({ trail: fresh ? [{ kind, value }] : [...this.state.trail, { kind, value }].slice(-12), pivotError: null });
  }

  back(steps = 1): void {
    this.set({ trail: this.state.trail.slice(0, Math.max(0, this.state.trail.length - steps)), pivotError: null });
  }

  closeInvestigation(): void {
    this.set({ trail: [], pivot: null, pivotError: null });
  }
}

export const store = new Store();
