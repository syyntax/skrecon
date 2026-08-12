"""RDAP parsing + expiry/lock findings (spec §4.3) — pure, no network."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from skrecon.rdap import evaluate_domain, parse_rdap_domain

NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def sample(expiration_iso: str, statuses):
    return {
        "events": [
            {"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": expiration_iso},
        ],
        "status": statuses,
        "secureDNS": {"delegationSigned": True},
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                     ["fn", {}, "text", "Test Registrar"]]],
        }],
    }


def test_parse_extracts_fields():
    p = parse_rdap_domain(sample("2027-01-01T00:00:00Z", ["client transfer prohibited"]))
    assert p.registrar == "Test Registrar"
    assert p.expiration == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert p.delegation_signed is True
    assert "client transfer prohibited" in p.statuses


def test_expired_domain():
    p = parse_rdap_domain(sample("2026-06-01T00:00:00Z", ["client transfer prohibited"]))
    fts = {ft for ft, _, _ in evaluate_domain(p, "example.com", now=NOW, warn_days=60)}
    assert "domain.expired" in fts


def test_expiring_soon():
    soon = (NOW + timedelta(days=30)).isoformat()
    p = parse_rdap_domain(sample(soon, ["client transfer prohibited"]))
    fts = {ft for ft, _, _ in evaluate_domain(p, "example.com", now=NOW, warn_days=60)}
    assert "domain.expiring_soon" in fts


def test_not_expiring_when_far_out():
    far = (NOW + timedelta(days=200)).isoformat()
    p = parse_rdap_domain(sample(far, ["client transfer prohibited"]))
    fts = {ft for ft, _, _ in evaluate_domain(p, "example.com", now=NOW, warn_days=60)}
    assert "domain.expiring_soon" not in fts and "domain.expired" not in fts


def test_missing_registrar_lock():
    p = parse_rdap_domain(sample("2027-01-01T00:00:00Z", ["active"]))
    fts = {ft for ft, _, _ in evaluate_domain(p, "example.com", now=NOW, warn_days=60)}
    assert "domain.no_registrar_lock" in fts


def test_lock_present_is_clean():
    p = parse_rdap_domain(sample("2027-01-01T00:00:00Z", ["client transfer prohibited"]))
    fts = {ft for ft, _, _ in evaluate_domain(p, "example.com", now=NOW, warn_days=60)}
    assert "domain.no_registrar_lock" not in fts
