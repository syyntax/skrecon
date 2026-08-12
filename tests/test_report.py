"""Report model + Markdown/HTML rendering (spec §7)."""

from __future__ import annotations

from skrecon.engagement import EngagementMeta
from skrecon.findings import make_finding
from skrecon.model import Exposure, ExposureFormat, HostIP, Service, ServiceSource
from skrecon.report import build_report_model, render_html, render_markdown
from skrecon.store import EngagementStore


def seed(tmp_path) -> EngagementStore:
    store = EngagementStore(tmp_path / "s.db")
    store.upsert_engagement(EngagementMeta.from_dict(
        {"id": "e1", "client": "Example Corp", "auth_ref": "T-1", "tester": "alice"}))
    store.persist(make_finding("mail.dmarc.missing", affected=["example.com"],
                               evidence=["no v=DMARC1 TXT"], source_module="mail",
                               title_ctx={"domain": "example.com"}))
    store.persist(make_finding("tls.cert.expired", affected=["https://203.0.113.5:443"],
                               evidence=["expired 2026-01-01"], source_module="tls",
                               title_ctx={"url": "https://203.0.113.5:443"}))
    store.persist(HostIP(ip="203.0.113.5", version=4, in_scope=True))
    store.persist(Service(host_ip="203.0.113.5", port=443, proto="tcp",
                          product="nginx", source=ServiceSource.NMAP))
    store.persist(Exposure(client_id="example.com", breach_source="BreachA",
                           record_count=5, fmt=ExposureFormat.HASHED, vault_ref="vault:breach"))
    return store


def test_report_model(tmp_path):
    model = build_report_model(seed(tmp_path))
    assert model["severity_counts"]["medium"] >= 1
    assert model["severity_counts"]["high"] >= 1
    assert "mail" in model["findings_by_category"]
    assert "tls" in model["findings_by_category"]
    assert model["counts"]["service"] == 1


def test_markdown_render(tmp_path):
    md = render_markdown(build_report_model(seed(tmp_path)))
    assert "# Reconnaissance Report — Example Corp" in md
    assert "## Executive Summary" in md
    assert "## Findings" in md
    assert "No DMARC record for example.com" in md
    assert "BreachA" in md
    # Exposure is counts-only; the vault note must be present.
    assert "encrypted vault" in md


def test_html_render_is_escaped_and_structured(tmp_path):
    store = seed(tmp_path)
    store.persist(make_finding("http.header.csp.missing",
                               affected=["https://x/<script>"], evidence=["<b>evidence</b>"],
                               source_module="headers", title_ctx={"url": "https://x/<script>"}))
    html = render_html(build_report_model(store))
    assert "<!doctype html>" in html
    assert "Reconnaissance Report" in html
    assert "nginx" in html
    # user/tool-derived content must be HTML-escaped, not raw
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
