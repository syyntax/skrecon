"""Pure header + TLS evaluators (spec §5.3, §5.4)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from skrecon.headers import evaluate_headers
from skrecon.tlscheck import evaluate_tls

NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def ftypes(pairs):
    return {ft for ft, _ in pairs}


# --- headers --- #
def test_all_security_headers_missing():
    out = ftypes(evaluate_headers({"Content-Type": "text/html"}))
    assert "http.header.hsts.missing" in out
    assert "http.header.csp.missing" in out
    assert "http.header.xfo.missing" in out
    assert "http.header.xcto.missing" in out


def test_present_headers_not_flagged():
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    assert evaluate_headers(headers) == []


def test_xcto_present_but_wrong_value():
    assert "http.header.xcto.missing" in ftypes(evaluate_headers({"X-Content-Type-Options": "sniff"}))


def test_cookie_flags():
    out = evaluate_headers({}, cookies=["sid=abc; Path=/"])
    cookie_findings = [ev for ft, ev in out if ft == "http.cookie.insecure"]
    assert cookie_findings and "Secure" in cookie_findings[0]
    # A fully-flagged cookie is clean.
    out2 = evaluate_headers({}, cookies=["sid=abc; Secure; HttpOnly; SameSite=Strict"])
    assert not any(ft == "http.cookie.insecure" for ft, _ in out2)


# --- TLS --- #
def test_legacy_protocol_flagged():
    assert "tls.protocol.legacy" in ftypes(evaluate_tls(["TLSv1", "TLSv1.2"], None, now=NOW))
    assert "tls.protocol.legacy" not in ftypes(evaluate_tls(["TLSv1.2", "TLSv1.3"], None, now=NOW))


def test_cert_expired_and_expiring():
    expired = {"not_after": (NOW - timedelta(days=1)).isoformat()}
    assert "tls.cert.expired" in ftypes(evaluate_tls([], expired, now=NOW))
    soon = {"not_after": (NOW + timedelta(days=10)).isoformat()}
    assert "tls.cert.expiring" in ftypes(evaluate_tls([], soon, now=NOW, expiry_warn_days=30))


def test_self_signed():
    cert = {"not_after": (NOW + timedelta(days=365)).isoformat(),
            "self_signed": True, "issuer": "CN=self"}
    assert "tls.cert.self_signed" in ftypes(evaluate_tls(["TLSv1.3"], cert, now=NOW))
