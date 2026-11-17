/** Desactiva un indicador para que no se pueda abrir por error (convencion de los analistas). */
export const defang = (ioc: string): string => ioc.replace(/\./g, "[.]").replace(/^http/i, "hxxp");

export const shortDate = (iso: string): string =>
  new Date(iso).toLocaleString("es-AR", { hour12: false, day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });

export const dayDate = (iso: string): string =>
  new Date(iso).toLocaleDateString("es-AR", { day: "2-digit", month: "2-digit", year: "numeric", timeZone: "UTC" });

/** Solo enlaces http(s): nunca javascript: ni otros esquemas que vengan de una fuente externa. */
export function safeLink(url: string, text: string): HTMLAnchorElement | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    const a = document.createElement("a");
    a.href = u.href;
    a.textContent = text;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    return a;
  } catch {
    return null;
  }
}

const PALETTE = ["#fc5c65", "#fd9644", "#fed330", "#26de81", "#2bcbba", "#45aaf2", "#a55eea", "#f78fb3", "#d1d8e0", "#4b7bec"];
const FIXED: Record<string, string> = { "Cobalt Strike": "#fc5c65", "AsyncRAT": "#fd9644", "Remcos": "#a55eea", "Sliver": "#2bcbba" };

/** Color estable por familia de malware: la misma familia siempre tiene el mismo color. */
export function familyColor(name: string): string {
  if (FIXED[name]) return FIXED[name];
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return PALETTE[h % PALETTE.length];
}
