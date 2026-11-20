import L from "leaflet";
import { str, type Entity } from "../api/types";
import type { HeatMode } from "../state/store";

const R = 20; // radio del hexagono, en pixeles de pantalla

/** Rampa de color: de azul oscuro (poco) a rojo y amarillo (mucho). */
function ramp(t: number): string {
  const stops: [number, [number, number, number]][] = [[0, [40, 70, 120]], [0.45, [200, 50, 80]], [0.8, [255, 120, 60]],
    [1, [255, 220, 90]]];
  let i = 0;
  while (i < stops.length - 2 && t > stops[i + 1][0]) i++;
  const [t0, c0] = stops[i], [t1, c1] = stops[i + 1];
  const k = Math.min(1, Math.max(0, (t - t0) / (t1 - t0)));
  return `rgb(${c0.map((v, j) => Math.round(v + (c1[j] - v) * k)).join(",")})`;
}

/**
 * Mapa de calor propio, sin dependencias: agrupa en hexagonos de tamaño fijo en pantalla (se recalcula al
 * mover o hacer zoom) o en burbujas por pais. La escala es logaritmica para que un pais con miles de C2 no
 * borre a todos los demas.
 */
export class HeatLayer extends L.Layer {
  private canvas = document.createElement("canvas");
  private points: Entity[] = [];
  private mode: HeatMode = "off";
  private lmap?: L.Map;

  onAdd(map: L.Map): this {
    this.lmap = map;
    this.canvas.className = "heat-canvas";
    map.getPanes().overlayPane.appendChild(this.canvas);
    map.on("moveend zoomend resize viewreset", this.draw, this);
    this.draw();
    return this;
  }

  onRemove(map: L.Map): this {
    map.off("moveend zoomend resize viewreset", this.draw, this);
    this.canvas.remove();
    return this;
  }

  set(points: Entity[], mode: HeatMode): void {
    this.points = points.filter((e) => e.lat != null && e.lon != null);
    this.mode = mode;
    this.draw();
  }

  private draw(): void {
    const map = this.lmap;
    if (!map) return;
    const size = map.getSize();
    const ratio = window.devicePixelRatio || 1;
    this.canvas.width = size.x * ratio;
    this.canvas.height = size.y * ratio;
    this.canvas.style.width = `${size.x}px`;
    this.canvas.style.height = `${size.y}px`;
    L.DomUtil.setPosition(this.canvas, map.containerPointToLayerPoint([0, 0]));
    const ctx = this.canvas.getContext("2d")!;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, size.x, size.y);
    if (this.mode === "hex") this.hex(ctx, map);
    else if (this.mode === "country") this.countries(ctx, map);
  }

  private hex(ctx: CanvasRenderingContext2D, map: L.Map): void {
    const w = Math.sqrt(3) * R;
    const bins = new Map<string, { x: number; y: number; n: number }>();
    for (const e of this.points) {
      const p = map.latLngToContainerPoint([e.lat!, e.lon!]);
      // Coordenadas axiales del hexagono que contiene al punto (orientacion "punta arriba").
      const q = ((Math.sqrt(3) / 3) * p.x - p.y / 3) / R, r = ((2 / 3) * p.y) / R;
      let rx = Math.round(q), rz = Math.round(r), ry = Math.round(-q - r);
      const dx = Math.abs(rx - q), dz = Math.abs(rz - r), dy = Math.abs(ry + q + r);
      if (dx > dy && dx > dz) rx = -ry - rz;
      else if (dy <= dz) rz = -rx - ry;
      const key = `${rx},${rz}`;
      const b = bins.get(key) ?? { x: w * (rx + rz / 2), y: 1.5 * R * rz, n: 0 };
      b.n++;
      bins.set(key, b);
    }
    const max = Math.log1p(Math.max(1, ...[...bins.values()].map((b) => b.n)));
    for (const b of bins.values()) {
      const t = Math.log1p(b.n) / max;
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const ang = (Math.PI / 3) * i - Math.PI / 6;
        const x = b.x + (R - 1) * Math.cos(ang), y = b.y + (R - 1) * Math.sin(ang);
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      }
      ctx.closePath();
      ctx.fillStyle = ramp(t);
      ctx.globalAlpha = 0.25 + 0.5 * t;
      ctx.fill();
      ctx.globalAlpha = 0.6;
      ctx.strokeStyle = "#0b1218";
      ctx.stroke();
      if (b.n > 1 && R >= 16) {
        ctx.globalAlpha = 0.95;
        ctx.fillStyle = "#fff";
        ctx.font = "10px ui-monospace, monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(String(b.n), b.x, b.y);
      }
    }
    ctx.globalAlpha = 1;
  }

  private countries(ctx: CanvasRenderingContext2D, map: L.Map): void {
    const by = new Map<string, { lat: number; lon: number; n: number }>();
    for (const e of this.points) {
      const cc = str(e.attrs.country_code) || "??";
      const b = by.get(cc) ?? { lat: 0, lon: 0, n: 0 };
      b.lat += e.lat!;
      b.lon += e.lon!;
      b.n++;
      by.set(cc, b);
    }
    const max = Math.max(1, ...[...by.values()].map((b) => b.n));
    const rows = [...by].filter(([cc]) => cc !== "??").sort((a, b) => a[1].n - b[1].n);
    for (const [cc, b] of rows) {
      const p = map.latLngToContainerPoint([b.lat / b.n, b.lon / b.n]);
      const t = Math.log1p(b.n) / Math.log1p(max);
      const r = 6 + 28 * Math.sqrt(b.n / max);
      ctx.beginPath();
      ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fillStyle = ramp(t);
      ctx.globalAlpha = 0.35 + 0.35 * t;
      ctx.fill();
      ctx.globalAlpha = 0.9;
      ctx.lineWidth = 1;
      ctx.strokeStyle = ramp(t);
      ctx.stroke();
      if (r > 11) {
        ctx.fillStyle = "#fff";
        ctx.font = "bold 10px ui-monospace, monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(`${cc} ${b.n}`, p.x, p.y);
      }
    }
    ctx.globalAlpha = 1;
  }
}
