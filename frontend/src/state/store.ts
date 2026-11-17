import type { Entity, LayerStatus } from "../api/types";
import type { ConnectionState } from "../api/client";

export interface State {
  connection: ConnectionState;
  mode: string | null;
  statuses: Record<string, LayerStatus>;
  entities: Record<string, Entity[]>;
  visible: Record<string, boolean>;
  search: string;
  family: string | null; // filtro por familia de malware
}

type Listener = (s: State, prev: State) => void;

/** Estado global minimo: inmutable, con suscripcion. Las vistas solo leen y piden cambios. */
export class Store {
  private state: State = {
    connection: "connecting", mode: null, statuses: {}, entities: {}, visible: {}, search: "", family: null,
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

  toggle(layer: string, on: boolean): void {
    this.set({ visible: { ...this.state.visible, [layer]: on } });
  }
}

export const store = new Store();
