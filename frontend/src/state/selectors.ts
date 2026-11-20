import { str, type Entity } from "../api/types";
import type { State, TimeWindow } from "./store";

const H = 3600000;
export const WINDOWS: Record<TimeWindow, { label: string; long: string; ms: number }> = {
  "7d": { label: "7D", long: "7 días", ms: 7 * 24 * H },
  "30d": { label: "30D", long: "30 días", ms: 30 * 24 * H },
  "90d": { label: "90D", long: "90 días", ms: 90 * 24 * H },
  "1y": { label: "1A", long: "1 año", ms: 365 * 24 * H },
  all: { label: "Todo", long: "todo el historial", ms: 10 * 365 * 24 * H },
};

/** Sectores tal como los nombra ransomware.live, en castellano. */
const SECTORS_ES: Record<string, string> = {
  "healthcare": "Salud", "manufacturing": "Manufactura", "financial services": "Finanzas", "technology": "Tecnología",
  "professional services": "Servicios profesionales", "retail & e-commerce": "Comercio", "education": "Educación",
  "public sector": "Gobierno", "government": "Gobierno", "energy & utilities": "Energía", "energy": "Energía",
  "transportation & logistics": "Transporte", "construction": "Construcción", "hospitality": "Turismo y hotelería",
  "telecommunication": "Telecomunicaciones", "telecommunications": "Telecomunicaciones", "agriculture": "Agro",
  "business services": "Servicios", "consumer services": "Servicios", "real estate": "Inmobiliario",
  "media & entertainment": "Medios", "legal": "Legal", "other": "Otros", "not found": "Sin sector",
  "government & defense": "Gobierno y defensa", "defense": "Gobierno y defensa", "financial": "Finanzas",
  "finance": "Finanzas", "banking": "Finanzas", "insurance": "Finanzas", "health": "Salud",
  "retail": "Comercio", "e-commerce": "Comercio", "logistics": "Transporte", "transportation": "Transporte",
  "hospitality & tourism": "Turismo y hotelería", "food & beverage": "Alimentación", "chemicals": "Química",
  "automotive": "Automotriz", "aerospace": "Aeroespacial", "non-profit": "ONG", "nonprofit": "ONG",
  "pharmaceutical": "Salud", "pharmaceuticals": "Salud", "utilities": "Energía", "information technology": "Tecnología",
};
export const sectorEs = (v: unknown): string => {
  const s = str(v).trim();
  return SECTORS_ES[s.toLowerCase()] ?? (s || "Sin sector");
};

/** Sectores que suelen considerarse infraestructura critica. */
export const CRITICAL = new Set(["Salud", "Energía", "Gobierno", "Transporte", "Telecomunicaciones", "Agua", "Finanzas"]);

/** Entidades de una capa dentro de la ventana de tiempo: lo actual mas lo guardado en el historial, sin duplicar. */
export function windowed(s: State, layer: "incidents" | "kev" | "events"): Entity[] {
  const cut = Date.now() - WINDOWS[s.timeWindow].ms;
  const byId = new Map<string, Entity>();
  for (const e of s.history[layer] ?? []) byId.set(e.id, e);
  for (const e of s.entities[layer] ?? []) byId.set(e.id, e);
  return [...byId.values()].filter((e) => Date.parse(e.observed_at) >= cut);
}

/** Ataques visibles: ventana de tiempo + filtro de sector. */
export function visibleIncidents(s: State): Entity[] {
  const all = windowed(s, "incidents");
  return s.sector ? all.filter((e) => sectorEs(e.attrs.sector) === s.sector) : all;
}

export const ageDays = (iso: string) => (Date.now() - Date.parse(iso)) / (24 * H);

/** Capas por tipo de ataque. Los eventos salen de avisos y noticias; ransomware suma tambien las reivindicaciones. */
export interface Category { id: string; label: string; color: string; hint: string }
export const CATEGORIES: Category[] = [
  { id: "ransomware", label: "Ransomware", color: "#ff4757", hint: "Reivindicaciones de los grupos + noticias" },
  { id: "vulnerabilidad", label: "Vulnerabilidad crítica", color: "#4fd1c5", hint: "Avisos y noticias con CVE" },
  { id: "estado_nacion", label: "Estado-nación", color: "#ff9ff3", hint: "Grupos con país atribuido o patrocinio estatal" },
  { id: "ot", label: "Sabotaje OT / ICS", color: "#ff7f50", hint: "Sistemas industriales y de control" },
  { id: "cripto", label: "Robo de criptoactivos", color: "#f7b731", hint: "Robos a exchanges, billeteras y DeFi" },
  { id: "fuga", label: "Intrusión / fuga de datos", color: "#a55eea", hint: "Brechas y datos expuestos" },
  { id: "ddos", label: "Denegación de servicio", color: "#45aaf2", hint: "Ataques DDoS" },
  { id: "policial", label: "Operación policial", color: "#26de81", hint: "Detenciones, desmantelamientos, incautaciones" },
  { id: "malware", label: "Malware / botnet", color: "#fd9644", hint: "Campañas y familias de malware" },
  { id: "caida", label: "Caída de servicio", color: "#d1d8e0", hint: "Interrupciones reportadas" },
  { id: "c2", label: "Infraestructura C2", color: "#fc5c65", hint: "Servidores de comando y control (ThreatFox)" },
  { id: "urls", label: "Distribución de malware", color: "#fed330", hint: "URLs que sirven malware (URLhaus)" },
];
export const CATEGORY = Object.fromEntries(CATEGORIES.map((c) => [c.id, c])) as Record<string, Category>;
export const on = (s: State, id: string) => s.visible[id] !== false;

/** Eventos de la ventana de tiempo cuyo tipo esta encendido. */
export function visibleEvents(s: State): Entity[] {
  return windowed(s, "events").filter((e) => on(s, str(e.attrs.kind)));
}

export function categoryCounts(s: State): Record<string, number> {
  const out: Record<string, number> = Object.fromEntries(CATEGORIES.map((c) => [c.id, 0]));
  for (const e of windowed(s, "events")) out[str(e.attrs.kind)] = (out[str(e.attrs.kind)] ?? 0) + 1;
  out.ransomware += visibleIncidents(s).length;
  out.c2 = new Set((s.entities.c2 ?? []).map((e) => str(e.attrs.ip))).size;
  out.urls = (s.entities.urls ?? []).length;
  return out;
}
