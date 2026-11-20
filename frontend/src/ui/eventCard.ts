import { eventAttrs, type Entity } from "../api/types";
import { CATEGORY } from "../state/selectors";
import type { Store } from "../state/store";
import { safeLink, shortDate, timeAgo } from "../util/format";
import { el } from "./dom";

const REGISTRY: Record<string, string> = {
  publicado: "registro publicado en cve.org", sin_registro: "sin registro público en cve.org (reservado o inexistente)",
  rechazado: "rechazado por el programa CVE",
};

/**
 * Ficha de un evento armado con avisos y noticias. Muestra solo lo que dicen las fuentes (titulo y enlace),
 * los datos extraidos y POR QUE se clasifico asi: la clasificacion es automatica y puede equivocarse.
 */
export function eventCard(e: Entity, store: Store): HTMLElement {
  const a = eventAttrs(e);
  const color = CATEGORY[a.kind]?.color ?? "#fff";
  const card = el("div", "inc-card evt-card");
  card.style.setProperty("--c", color);
  const close = el("button", "close", "×");
  close.type = "button";
  close.title = "Cerrar";
  close.addEventListener("click", () => store.select(null));
  const tags = el("div", "inc-tags");
  const kind = el("span", "tag t-kind", a.kind_label);
  tags.append(kind, el("span", a.status === "verificado" ? "tag t-green" : "tag t-amber",
    a.status === "verificado" ? "Verificado" : "1 fuente · sin confirmar"));
  if (a.exploited) tags.append(el("span", "tag t-red", "Explotación activa"));
  for (const t of a.types.slice(1, 3)) tags.append(el("span", "tag", CATEGORY[t]?.label ?? t));
  const head = el("div", "inc-head");
  head.append(tags, close);

  const where = a.countries.length ? a.countries.map((c) => c.name).join(", ") : "alcance global o sin país en la nota";
  const when = el("div", "inc-when", `${shortDate(e.observed_at)} (${timeAgo(e.observed_at)}) · ${where}`);
  const summary = el("p", "inc-sum", `Reportado por ${a.n_sources} fuente(s). ${a.status_reason[0].toUpperCase()}${a.status_reason.slice(1)}.`
    + " Clasificación automática por reglas: revisá la fuente original antes de citarlo.");

  const dl = el("dl", "inc-dl");
  const row = (k: string, v: string | HTMLElement) => {
    const dd = el("dd");
    typeof v === "string" ? (dd.textContent = v) : dd.append(v);
    dl.append(el("dt", "", k), dd);
  };
  const why = el("ul", "why");
  for (const r of a.reasons) why.append(el("li", r.startsWith("atención") ? "warn" : "", r));
  row("Por qué", why);
  if (a.cves.length) {
    const box = el("div", "cves");
    for (const c of a.cves) {
      const line = el("div", "cve-line");
      const link = safeLink(`https://nvd.nist.gov/vuln/detail/${c.id}`, c.id);
      line.append(link ?? el("span", "", c.id));
      if (c.kev) line.append(el("span", "tag t-red", "KEV"));
      if (c.registry) line.append(el("span", c.registry === "publicado" ? "cve-reg" : "cve-reg warn", REGISTRY[c.registry]));
      box.append(line);
    }
    row("CVE", box);
  }
  if (a.origin) row("Origen atribuido", `${a.origin.name} (${a.actors.length ? "grupo con país según MISP" : "según la nota"})`);

  const acts = el("div", "actions");
  const b = (text: string, fn: () => void) => {
    const x = el("button", "", text);
    x.type = "button";
    x.addEventListener("click", fn);
    acts.append(x);
  };
  for (const g of a.actors.slice(0, 3)) b(`Perfil de ${g.name}`, () => store.investigate("actor", g.id, true, g.name));
  for (const m of a.malware.slice(0, 2)) b(`Investigar ${m.name}`, () => store.investigate("malware", m.name, true));
  for (const c of a.countries.slice(0, 2)) b(`Todo en ${c.name}`, () => store.investigate("country", c.code, true, c.name));

  const src = el("div", "evt-sources");
  src.append(el("h3", "", `Fuentes (${a.sources.length})`));
  for (const s of a.sources) {
    const it = el("div", "evt-src");
    const top = el("div", "row");
    top.append(el("b", "", s.name), s.official ? el("span", "tag t-green", "oficial") : el("span"), el("span", "s", shortDate(s.published)));
    it.append(top, safeLink(s.url, `${s.title} ↗`) ?? el("span", "", s.title));
    src.append(it);
  }

  card.append(head, el("h3", "inc-title", a.title), when, summary, dl, acts, src);
  return card;
}
