import json

import httpx
import pytest

from app.collectors import cisa_kev, threatfox
from app.collectors.base import CollectorError
from app.collectors.demo import DemoC2, DemoKev

TF_SAMPLE = {"query_status": "ok", "data": [
    {"id": "1500123", "ioc": "45.9.148.10:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
     "threat_type_desc": "Botnet C&C", "malware": "win.cobalt_strike", "malware_printable": "Cobalt Strike",
     "confidence_level": 100, "first_seen": "2026-11-17 10:12:13 UTC", "last_seen": None,
     "reporter": "abuse_ch", "tags": ["CobaltStrike"], "reference": "https://example.org/r"},
    {"id": "1500124", "ioc": "evil.example.com", "ioc_type": "domain", "malware_printable": "Lumma"},
    {"id": "1500125", "ioc": "bad", "ioc_type": "ip:port"},
]}
KEV_SAMPLE = {"vulnerabilities": [
    {"cveID": "CVE-2026-1111", "vendorProject": "Acme", "product": "VPN", "vulnerabilityName": "Acme VPN RCE",
     "dateAdded": "2026-11-10", "shortDescription": "d", "requiredAction": "a", "dueDate": "2026-12-01",
     "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-78"]},
    {"cveID": "CVE-2026-2222", "vendorProject": "Globex", "product": "Mail", "dateAdded": "2026-11-15",
     "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-3333", "dateAdded": "no-es-fecha"},
]}


def mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_threatfox_sends_key_and_keeps_only_ip_port():
    seen = {}

    def handler(req):
        seen["key"], seen["body"] = req.headers.get("Auth-Key"), json.loads(req.content)
        return httpx.Response(200, json=TF_SAMPLE)

    async with mock_client(handler) as c:
        items = await threatfox.ThreatFoxC2("k123", days=2).fetch(c)
    assert seen == {"key": "k123", "body": {"query": "get_iocs", "days": 2}}
    assert len(items) == 1
    e = items[0]
    assert e.id == "threatfox:1500123" and e.lat is None
    assert e.attrs["ip"] == "45.9.148.10" and e.attrs["port"] == 443 and e.attrs["malware"] == "Cobalt Strike"


async def test_threatfox_without_key_or_rejected():
    with pytest.raises(CollectorError, match="ARGOS_THREATFOX_KEY"):
        await threatfox.ThreatFoxC2("").fetch(None)
    async with mock_client(lambda r: httpx.Response(401)) as c:
        with pytest.raises(CollectorError, match="rechazo"):
            await threatfox.ThreatFoxC2("x").fetch(c)
    async with mock_client(lambda r: httpx.Response(200, json={"query_status": "no_result"})) as c:
        assert await threatfox.ThreatFoxC2("x").fetch(c) == []


async def test_kev_parse_sorted_and_flags_ransomware():
    async with mock_client(lambda r: httpx.Response(200, json=KEV_SAMPLE)) as c:
        items = await cisa_kev.CisaKev().fetch(c)
    assert [e.attrs["cve"] for e in items] == ["CVE-2026-2222", "CVE-2026-1111"]
    assert items[1].attrs["ransomware"] is True and items[0].attrs["ransomware"] is False
    assert all(e.lat is None for e in items)


async def test_demo_uses_only_documentation_ips():
    import ipaddress
    c2 = await DemoC2().fetch(None)
    assert len(c2) == 160
    docs = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    assert all(any(ipaddress.ip_address(e.attrs["ip"]) in n for n in docs) for e in c2)
    assert all(e.attrs["cve"].startswith("DEMO-") for e in await DemoKev().fetch(None))
