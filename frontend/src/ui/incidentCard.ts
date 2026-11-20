import { str, type Entity } from "../api/types";
import { CRITICAL, sectorEs } from "../state/selectors";
import type { Store } from "../state/store";
import { safeLink, shortDate, timeAgo } from "../util/format";
import { el } from "./dom";

/**
 * Ficha completa de un ataque reivindicado. El texto se arma solo con lo que dicen las fuentes:
 * no se inventa impacto ni se presenta la reivindicacion como un hecho confirmado.
 */
export function incidentCard(e: Entity, store: Store): HTMLElement {
  const a = e.attrs;
  const sector = sectorEs(a.sector);
  const group = str(a.group);
  const country = str(a.country) || "país desconocido";
  const actors = (a.actors as string[] | undefined) ?? [];
  const names = (a.actor_names as string[] | undefined) ?? [];
  const origin = a.origin as { name: string } | undefined;

  const card = el("div", "inc-card");
  const close = el("button", "close", "×");
  close.type = "button";
  close.title = "Cerrar";
  close.addEventListener("click", () => store.select(null));
  const tags = el("div", "inc-tags");
  tags.append(el("span", "tag t-red", "Ransomware"), el("span", "tag", "Reivindicado · sin confirmar"));
  if (str(a.sector)) tags.append(el("span", CRITICAL.has(sector) ? "tag t-amber" : "tag t-blue",
    CRITICAL.has(sector) ? `${sector} · infraestructura crítica` : sector));
  const head = el("div", "inc-head");
  head.append(tags, close);

  const when = el("div", "inc-when", `${shortDate(e.observed_at)} (${timeAgo(e.observed_at)}) · ${country}`);
  const summary = el("p", "inc-sum",
    `El grupo ${group} publicó a ${str(a.victim)} en su sitio de filtración${str(a.sector) ? `, en el sector ${sector.toLowerCase()}` : ""}. `
    + "Los grupos de ransomware publican a sus víctimas para presionar el pago; la reivindicación puede ser cierta, "
    + "exagerada o falsa hasta que la víctima o una autoridad la confirme.");

  const dl = el("dl", "inc-dl");
  const row = (k: string, v: string | HTMLElement) => {
    const dd = el("dd");
    typeof v === "string" ? (dd.textContent = v) : dd.append(v);
    dl.append(el("dt", "", k), dd);
  };
  row("Grupo", group || "—");
  row("Atribución", origin ? `${origin.name} (según MISP)` : "Sin atribución de país en fuentes abiertas");
  row("MITRE ATT&CK", names.length ? names.slice(0, 4).join(", ") : "El grupo no tiene ficha en ATT&CK");
  if (str(a.attack_date)) row("Fecha del ataque", shortDate(str(a.attack_date)));
  if (str(a.website)) row("Sitio de la víctima", str(a.website));
  row("Fuente", str(a.source) || "ransomware.live");
  const link = safeLink(str(a.source_url), "Ver la publicación en ransomware.live ↗");
  if (link) row("Detalle", link);

  const acts = el("div", "actions");
  const b = (text: string, fn: () => void) => {
    const x = el("button", "", text);
    x.type = "button";
    x.addEventListener("click", fn);
    acts.append(x);
  };
  b(`Investigar ${group}`, () => store.investigate("malware", group, true));
  if (actors[0]) b(`Perfil de ${names[0] ?? actors[0]}`, () => store.investigate("actor", actors[0], true, names[0]));
  if (str(a.software_id)) b("Técnicas en la matriz", () => store.openMatrix(`software:${str(a.software_id)}`));

  card.append(head, el("h3", "inc-title", str(a.victim) || "Víctima"), when, summary, dl, acts);
  return card;
}
