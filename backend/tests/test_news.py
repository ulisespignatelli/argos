from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.collectors.news import CveRegistry, Feed, KevIndex, NewsEvents, build_events, parse_feed_list
from app.knowledge.kb import KnowledgeBase
from app.services.news_extract import Extractor, NewsItem, cluster, parse_feed

NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Akira ransomware gang claims attack on Chilean port operator</title>
<link>https://news.example/a</link><pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate>
<description>&lt;p&gt;The group posted the victim in Chile.&lt;/p&gt;</description></item>
<item><title>How to pick a password manager</title><link>https://news.example/b</link>
<pubDate>Wed, 18 Nov 2026 11:00:00 GMT</pubDate></item>
<item><title>Sin fecha</title><link>https://news.example/c</link></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Hackers exploit CVE-2099-1234 zero-day in Demo VPN</title>
<link rel="alternate" href="https://other.example/x"/><updated>2026-11-18T12:00:00Z</updated>
<summary>Actively exploited in the wild.</summary></entry></feed>"""


@pytest.fixture(scope="module")
def kb():
    return KnowledgeBase()


@pytest.fixture(scope="module")
def ex(kb):
    return Extractor(kb)


def item(title, src="Medio", hours=1, official=False, url=None):
    return NewsItem(title=title, url=url or f"https://{src.lower().replace(' ', '')}.example/{hash(title)}",
                    published=NOW - timedelta(hours=hours), source=src, official=official)


def test_parse_rss_and_atom():
    rss = parse_feed(RSS, "Medio", now=NOW)
    assert [i.title for i in rss][:1] == ["Akira ransomware gang claims attack on Chilean port operator"]
    assert len(rss) == 2 and "victim in Chile" in rss[0].summary and "<p>" not in rss[0].summary
    atom = parse_feed(ATOM, "Otro", now=NOW)
    assert atom[0].url == "https://other.example/x" and atom[0].published.tzinfo


def test_xml_bomb_is_rejected():
    bomb = (b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]>'
            b"<rss><channel>&b;</channel></rss>")
    with pytest.raises(Exception):  # noqa: B017 (defusedxml rechaza entidades)
        parse_feed(bomb, "x")


@pytest.mark.parametrize(("title", "kind"), [
    ("Akira ransomware gang claims attack on Chilean port operator", "ransomware"),
    ("Police arrest 4 in takedown of Lumma Stealer botnet", "policial"),
    ("Bybit hack: $1.5 billion in crypto stolen by North Korea's Lazarus", "cripto"),
    ("Volt Typhoon targets US water utilities", "ot"),
    ("Chinese hackers exploit CVE-2099-0001 zero-day in VPNs", "estado_nacion"),
    ("Fortinet warns of critical FortiWeb flaw under active exploitation", "vulnerabilidad"),
    ("DDoS attack disrupts government portals in Argentina", "ddos"),
    ("Data breach at retailer exposes customer records", "fuga"),
    ("Detenido en Madrid un joven por ataques DDoS", "policial"),
])
def test_classification(ex, title, kind):
    assert ex.extract(item(title)).primary == kind


def test_same_cve_merges_even_weeks_apart(ex, kb):
    items = [item("Use-after-free CVE-2099-0505 in Vendor A product", "CERT", 24 * 9, official=True),
             item("CVE-2099-0505 also affects Vendor B gateway", "CERT", 1, official=True)]
    events = build_events(ex, kb, items, frozenset(), now=NOW)
    assert len(events) == 1 and len(events[0].attrs["sources"]) == 2


def test_cryptomining_is_not_crypto_theft(ex):
    assert ex.extract(item("Hackers exploit flaw to deploy cryptomining malware")).primary != "cripto"


def test_not_events(ex):
    for t in ("How to choose a password manager", "Spark Capital raises new fund", "Snake game is back on Play"):
        assert ex.extract(item(t)).primary is None


def test_entities_and_places(ex, kb):
    e = ex.extract(item("Bybit hack: crypto stolen by North Korea's Lazarus"))
    assert [kb.groups[g]["name"] for g in e.actors] == ["Lazarus Group"] and e.origins == ["KP"] and not e.victims
    e = ex.extract(item("Hackers rusos atacan a ministerios de Ucrania con un nuevo wiper"))
    assert e.origins == ["RU"] and e.victims == ["UA"]
    e = ex.extract(item("Play ransomware gang claims attack on Argentine airline"))
    assert e.victims == ["AR"] and any("grupo" in r or "malware" in r for r in e.reasons)


def test_cluster_and_status(ex, kb):
    items = [item("Hackers exploit CVE-2099-0101 zero-day in Demo Gateway", "Medio A", 5),
             item("CVE-2099-0101 actively exploited, patch now", "Medio B", 3),
             item("Akira ransomware hits Chilean logistics firm", "Medio A", 2)]
    groups = cluster([ex.extract(i) for i in items])
    assert sorted(len(g) for g in groups) == [1, 2]
    events = build_events(ex, kb, items, frozenset(), now=NOW)
    vuln = next(e for e in events if e.attrs["cves"])
    assert vuln.attrs["status"] == "verificado" and vuln.attrs["n_sources"] == 2 and vuln.attrs["exploited"]
    ransom = next(e for e in events if e.attrs["kind"] == "ransomware")
    assert ransom.attrs["status"] == "una_fuente" and ransom.attrs["country_code"] == "CL" and ransom.lat is not None
    # Un CVE del catalogo KEV verifica aunque haya una sola fuente.
    one = build_events(ex, kb, items[1:2], frozenset({"CVE-2099-0101"}), now=NOW)[0]
    assert one.attrs["status"] == "verificado" and one.attrs["cves"][0]["kev"]


def test_vulnerability_advisories_are_not_placed(ex, kb):
    items = [item("Critical vulnerability CVE-2099-0303 in German vendor's PLC, Germany", "CERT", 2, official=True),
             item("Patch now: CVE-2099-0404 flaw in Canada-based software", "Medio", 1)]
    for e in build_events(ex, kb, items, frozenset(), now=NOW):
        assert e.lat is None and e.attrs["global"]


def test_event_id_is_stable(ex, kb):
    a = build_events(ex, kb, [item("CVE-2099-0101 exploited", "Medio A", 5)], frozenset(), now=NOW)[0]
    b = build_events(ex, kb, [item("CVE-2099-0101 exploited", "Medio A", 5),
                              item("Patch CVE-2099-0101 now", "Medio B", 1)], frozenset(), now=NOW)[0]
    assert a.id == b.id


def test_feed_list_env():
    feeds = parse_feed_list("Mi CERT|https://cert.example/rss|oficial;Blog|https://b.example/feed;malo|ftp://x")
    assert [(f.name, f.official) for f in feeds] == [("Mi CERT", True), ("Blog", False)]


async def test_collector_tolerates_failed_feeds(kb):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "ok.example":
            return httpx.Response(200, content=ATOM.replace(b"2026-11-18", datetime.now(UTC).strftime("%Y-%m-%d")
                                                            .encode()))
        if req.url.host == "cveawg.mitre.org":
            return httpx.Response(404)
        return httpx.Response(500)

    kev = KevIndex()
    col = NewsEvents(kb, kev, (Feed("Bueno", "https://ok.example/feed"), Feed("Caido", "https://down.example/f")),
                     registry=CveRegistry())
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        events = await col.fetch(client)
    assert col.last_failed == ["Caido"] and len(events) == 1
    cve = events[0].attrs["cves"][0]
    assert cve["registry"] == "sin_registro" and any("sin registro" in r for r in events[0].attrs["reasons"])
