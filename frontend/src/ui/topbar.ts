import { api } from "../api/client";
import { eventAttrs, str } from "../api/types";
import { visibleIncidents, WINDOWS, windowed } from "../state/selectors";
import type { Store } from "../state/store";
import { LATAM } from "../util/format";
import { el } from "./dom";

const CONNECTION_LABEL = { connecting: "conectando…", open: "en vivo", closed: "sin conexión" } as const;

/**
 * Barra superior: tres contadores separados a proposito. Mezclar avisos con ataques infla las cifras;
 * aca cada cosa se cuenta en su lugar.
 */
export function mountTopbar(root: HTMLElement, store: Store): void {
  const brand = el("div", "tb-brand");
  const logo = el("div", "tb-logo");
  logo.append(document.createTextNode("AR"), el("span", "", "G"), document.createTextNode("OS"));
  brand.append(logo, el("div", "tb-sub", "Inteligencia de amenazas · fuentes abiertas"));

  const card = (cls: string, label: string) => {
    const c = el("div", `tb-card ${cls}`);
    const v = el("b", "", "—"), s = el("small", "", "");
    c.append(v, el("span", "", label), s);
    return { c, v, s };
  };
  const attacks = card("k-attacks", "Ataques reivindicados");
  const vulns = card("k-vulns", "CVE explotadas");
  const infra = card("k-infra", "Infraestructura activa");
  const events = card("k-events", "Eventos");
  const counters = el("div", "tb-counters");
  counters.append(attacks.c, vulns.c, infra.c, events.c);

  const conn = el("span", "conn");
  const actorsBtn = el("button", "tb-btn", "Actores");
  const matrixBtn = el("button", "tb-btn", "Matriz ATT&CK");
  const report = el("a", "tb-btn", "Informe semanal");
  for (const b of [actorsBtn, matrixBtn]) b.type = "button";
  report.href = api.reportUrl;
  report.setAttribute("download", "");
  actorsBtn.addEventListener("click", () => store.set({ overlay: "actors" }));
  matrixBtn.addEventListener("click", () => store.openMatrix("active"));
  const right = el("div", "tb-right");
  right.append(conn, actorsBtn, matrixBtn, report);

  root.append(brand, counters, right);

  store.subscribe((s) => {
    conn.textContent = CONNECTION_LABEL[s.connection];
    conn.dataset.state = s.connection;
    const w = WINDOWS[s.timeWindow].long;
    const inc = visibleIncidents(s);
    const latam = inc.filter((e) => LATAM.has(str(e.attrs.country_code))).length;
    attacks.v.textContent = String(inc.length);
    attacks.s.textContent = `${w}${s.sector ? ` · ${s.sector}` : ""} · ${latam} en LATAM`;
    const kev = windowed(s, "kev");
    vulns.v.textContent = String(kev.length);
    vulns.s.textContent = `${w} · ${kev.filter((e) => e.attrs.ransomware === true).length} usadas por ransomware`;
    const ips = new Set((s.entities.c2 ?? []).map((e) => str(e.attrs.ip)));
    const urls = (s.entities.urls ?? []).filter((e) => e.attrs.status === "online").length;
    infra.v.textContent = String(ips.size + urls);
    infra.s.textContent = `${ips.size} servidores C2 · ${urls} URLs de malware`;
    const ev = windowed(s, "events");
    events.v.textContent = String(ev.length);
    events.s.textContent = `${w} · ${ev.filter((e) => eventAttrs(e).status === "verificado").length} verificados`;
  });
}
