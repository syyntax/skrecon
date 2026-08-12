"""Registrable-domain derivation and the findings catalog."""

from __future__ import annotations

import pytest

from skrecon.findings import CATALOG, make_finding
from skrecon.model import Severity
from skrecon.scope import parse_scope_text
from skrecon.targets import registrable_domain, scope_domains


def test_registrable_domain():
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("www.example.com") == "example.com"
    assert registrable_domain("a.b.c.example.com") == "example.com"
    assert registrable_domain("EXAMPLE.COM.") == "example.com"
    assert registrable_domain("localhost") == "localhost"


def test_scope_domains_dedup_and_extra_roots():
    scope = parse_scope_text("example.com\nwww.example.com\napp.example.com\n").scope
    assert scope_domains(scope) == ["example.com"]
    assert scope_domains(scope, extra_roots=["brand.net"]) == ["brand.net", "example.com"]


def test_make_finding_fills_from_catalog():
    f = make_finding("mail.dmarc.missing", affected=["example.com"],
                     evidence=["no record"], source_module="mail",
                     title_ctx={"domain": "example.com"})
    assert f.severity == Severity.MEDIUM
    assert "example.com" in f.title
    assert f.remediation  # non-empty remediation from the catalog


def test_unknown_finding_type_raises():
    with pytest.raises(KeyError):
        make_finding("does.not.exist", affected=[], evidence=[], source_module="x")


def test_catalog_titles_have_no_stray_placeholders():
    # Every catalog title must render given the placeholders our modules pass.
    ctx = {"domain": "d", "date": "2026-01-01", "candidate": "c",
           "cve": "CVE-2024-0001", "ip": "203.0.113.5", "count": 3, "client": "acme"}
    for spec in CATALOG.values():
        spec.title.format(**ctx)  # must not raise KeyError
