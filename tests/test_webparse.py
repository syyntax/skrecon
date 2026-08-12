"""Web-tool output parsers (spec §5.5, §5.7)."""

from __future__ import annotations

from skrecon.webparse import nuclei_finding_type, parse_nuclei, parse_wafw00f, parse_whatweb


def test_parse_whatweb():
    data = [{"target": "http://x", "plugins": {
        "nginx": {"version": ["1.18.0"]},
        "HTTPServer": {"string": ["nginx/1.18.0"]},
        "Country": {"string": ["UNITED STATES"]},
    }}]
    techs = {t["name"]: t["version"] for t in parse_whatweb(data)}
    assert techs["nginx"] == "1.18.0"
    assert "HTTPServer" in techs


def test_parse_wafw00f():
    data = [{"url": "https://x", "detected": True, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]
    out = parse_wafw00f(data)
    assert out[0]["detected"] is True and out[0]["firewall"] == "Cloudflare"


def test_parse_nuclei_jsonl():
    text = (
        '{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"matched-at":"http://x"}\n'
        '{"template-id":"cve-2021-1","info":{"name":"RCE","severity":"critical"},"host":"http://x"}\n'
        'not json\n'
    )
    out = parse_nuclei(text)
    assert len(out) == 2
    assert out[1]["severity"] == "critical" and out[1]["template"] == "cve-2021-1"


def test_nuclei_finding_type_mapping():
    assert nuclei_finding_type("critical") == "nuclei.critical"
    assert nuclei_finding_type("bogus") == "nuclei.info"
