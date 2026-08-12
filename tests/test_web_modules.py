"""Web-module glue: fake GuardedHttp -> evaluator -> findings/records.

No live requests — a fake HTTP/TLS client returns canned responses, exercising the
headers and tls modules end-to-end."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from skrecon.audit import AuditLog
from skrecon.config import Settings
from skrecon.guard import HttpResult, TlsResult
from skrecon.model import Certificate, DomainName, Finding, Service, ServiceSource
from skrecon.modules.http_headers import HeadersModule
from skrecon.modules.tls_scan import TlsModule
from skrecon.scope import parse_scope_text
from skrecon.store import EngagementStore


def make_ctx(tmp_path, http):
    store = EngagementStore(tmp_path / "s.db")
    store.persist(Service(host_ip="203.0.113.5", port=443, proto="tcp",
                          state="open", source=ServiceSource.NMAP))
    return SimpleNamespace(
        store=store, http=http,
        scope=parse_scope_text("203.0.113.0/28\nexample.com\n").scope,
        settings=Settings(), audit=AuditLog(path=None), raw_dir=tmp_path / "raw",
    )


class FakeHeadersHttp:
    def get(self, url, *, module, **kw):
        return HttpResult(url=url, status=200, headers={"Content-Type": "text/html"},
                          set_cookies=["sid=abc; Path=/"])


class FakeTlsHttp:
    def probe_tls(self, host, port, *, module, **kw):
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        return TlsResult(host=host, port=port, protocols=["TLSv1", "TLSv1.2"], cert={
            "not_after": expired, "issuer": "CN=self", "subject": "CN=self",
            "self_signed": True, "sans": ["a.example.com", "*.example.com"]})


def test_headers_module_flags_missing_and_cookies(tmp_path):
    records = list(HeadersModule().run(make_ctx(tmp_path, FakeHeadersHttp())))
    fts = {r.finding_type for r in records if isinstance(r, Finding)}
    assert "http.header.hsts.missing" in fts
    assert "http.header.csp.missing" in fts
    assert "http.cookie.insecure" in fts


def test_tls_module_findings_and_san_harvest(tmp_path):
    records = list(TlsModule().run(make_ctx(tmp_path, FakeTlsHttp())))
    fts = {r.finding_type for r in records if isinstance(r, Finding)}
    assert {"tls.protocol.legacy", "tls.cert.expired", "tls.cert.self_signed"} <= fts
    # SANs become discovered domains, and a Certificate is recorded.
    assert any(isinstance(r, DomainName) and r.fqdn == "a.example.com" for r in records)
    assert any(isinstance(r, Certificate) for r in records)
