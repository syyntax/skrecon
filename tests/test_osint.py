"""Pure OSINT parsers (spec §4.5, §4.7, §4.9) — no network, no keys."""

from __future__ import annotations

from skrecon.osint import parse_certspotter, parse_crtsh, parse_shodan_host, summarize_dehashed


def test_parse_crtsh_filters_apex_and_strips_wildcards():
    rows = [
        {"name_value": "www.example.com\nexample.com", "common_name": "www.example.com",
         "issuer_name": "LE", "not_before": "2025-10-01", "not_after": "2026-01-01"},
        {"name_value": "*.api.example.com", "common_name": "*.api.example.com",
         "issuer_name": "LE", "not_before": "2025-11-01", "not_after": "2026-02-01"},
        {"name_value": "evil.notexample.com", "common_name": "evil.notexample.com",
         "issuer_name": "X", "not_before": "", "not_after": "2026-01-01"},
    ]
    names, certs = parse_crtsh(rows, "example.com")
    assert names == {"example.com", "www.example.com", "api.example.com"}
    assert "evil.notexample.com" not in names          # out-of-apex excluded
    assert len(certs) == 3                              # distinct certs kept


def test_parse_crtsh_dedups_identical_certs():
    row = {"name_value": "a.example.com", "common_name": "a.example.com",
           "issuer_name": "LE", "not_after": "2026-01-01"}
    _names, certs = parse_crtsh([row, dict(row)], "example.com")
    assert len(certs) == 1


def test_parse_certspotter():
    rows = [
        {"dns_names": ["example.com", "www.example.com", "*.dev.example.com"],
         "issuer": {"name": "Let's Encrypt"}, "not_before": "2025-10-01", "not_after": "2026-01-01"},
        {"dns_names": ["cdn.thirdparty.net"], "issuer": {"name": "X"}},
    ]
    names, certs = parse_certspotter(rows, "example.com")
    assert names == {"example.com", "www.example.com", "dev.example.com"}
    assert "cdn.thirdparty.net" not in names
    assert certs[0]["issuer"] == "Let's Encrypt"


def test_parse_shodan_host():
    data = {
        "ip_str": "203.0.113.5", "ports": [80, 443],
        "data": [{"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18"},
                 {"port": 443, "transport": "tcp"}],
        "vulns": ["CVE-2021-1111", "CVE-2020-2222"], "hostnames": ["h.example.com"],
        "org": "Example Hosting", "os": None,
    }
    p = parse_shodan_host(data)
    assert p["ip"] == "203.0.113.5"
    assert p["cves"] == ["CVE-2020-2222", "CVE-2021-1111"]   # sorted
    assert len(p["services"]) == 2 and p["services"][0]["product"] == "nginx"


def test_summarize_dehashed_counts_and_plaintext_flag():
    payload = {"total": 3, "entries": [
        {"database_name": "BreachA", "password": "hunter2"},
        {"database_name": "BreachA", "hashed_password": "abcd"},
        {"database_name": "BreachB"},
    ]}
    s = summarize_dehashed(payload)
    assert s["total"] == 3 and s["entry_count"] == 3
    assert s["by_source"]["BreachA"]["count"] == 2
    assert s["by_source"]["BreachA"]["plaintext"] is True
    assert s["by_source"]["BreachB"]["plaintext"] is False
    assert s["plaintext_any"] is True
