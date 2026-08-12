"""Mail-security scoring (spec §4.2) — pure, exhaustive, no DNS."""

from __future__ import annotations

from skrecon.mailsec import count_spf_lookups, evaluate_dmarc, evaluate_spf, parse_tags


def types(pairs):
    return {ft for ft, _ in pairs}


def test_spf_missing():
    assert types(evaluate_spf(["some other txt"])) == {"mail.spf.missing"}


def test_spf_hardfail_is_clean():
    assert evaluate_spf(["v=spf1 include:_spf.example.com -all"]) == []


def test_spf_softfail_flagged():
    assert "mail.spf.softfail" in types(evaluate_spf(["v=spf1 ~all"]))


def test_spf_passall_is_high():
    assert "mail.spf.passall" in types(evaluate_spf(["v=spf1 +all"]))


def test_spf_lookup_budget():
    record = "v=spf1 " + " ".join(f"include:x{i}.com" for i in range(11)) + " -all"
    assert count_spf_lookups(record) == 11
    assert "mail.spf.lookups_high" in types(evaluate_spf([record]))
    # 'all' must not be miscounted as a lookup mechanism.
    assert count_spf_lookups("v=spf1 -all") == 0


def test_dmarc_missing():
    assert types(evaluate_dmarc([])) == {"mail.dmarc.missing"}


def test_dmarc_policy_none_and_no_rua():
    out = types(evaluate_dmarc(["v=DMARC1; p=none"]))
    assert "mail.dmarc.policy_none" in out
    assert "mail.dmarc.no_rua" in out


def test_dmarc_reject_with_rua_is_clean():
    assert evaluate_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"]) == []


def test_parse_tags():
    tags = parse_tags("v=DMARC1; p=quarantine; rua=mailto:a@b.c; pct=100")
    assert tags["p"] == "quarantine"
    assert tags["rua"] == "mailto:a@b.c"
    assert tags["pct"] == "100"
