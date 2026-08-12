"""Adversarial tests for the safety layer (spec §9): scope guard, auth gate,
blackout gate, and the guarded executor. This is the code the spec says to test
hardest — every assertion here is a way the tool could touch something it must not.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta

import pytest

from skrecon.audit import AuditLog
from skrecon.engagement import EngagementMeta
from skrecon.errors import BlackoutError, NotAuthorizedError, OutOfScopeError
from skrecon.guard import ActiveGate, GuardedExecutor, ScopeGuard
from skrecon.model import Phase, utcnow
from skrecon.scope import parse_scope_text

SCOPE_TEXT = "example.com\n203.0.113.0/28\n"


def make_audit():
    events: list[dict] = []
    audit = AuditLog(path=None, echo=lambda line: events.append(json.loads(line)))
    return audit, events


def make_guard(include_subdomains=False):
    audit, events = make_audit()
    scope = parse_scope_text(SCOPE_TEXT).scope
    return ScopeGuard(scope=scope, audit=audit, include_subdomains=include_subdomains), events


# --------------------------------------------------------------------------- #
# Scope guard
# --------------------------------------------------------------------------- #
def test_in_scope_host_and_ip_allowed():
    guard, _ = make_guard()
    assert guard.is_in_scope("example.com")
    assert guard.is_in_scope("203.0.113.5")
    assert guard.is_in_scope("https://example.com/path")   # scheme stripped
    assert guard.is_in_scope("203.0.113.5:443")            # port stripped


def test_out_of_scope_refused():
    guard, _ = make_guard()
    assert not guard.is_in_scope("evil.com")
    assert not guard.is_in_scope("8.8.8.8")
    assert not guard.is_in_scope("203.0.113.99")           # outside the /28
    assert not guard.is_in_scope("api.example.com")        # subdomain, feature off


def test_subdomain_only_when_enabled():
    guard_off, _ = make_guard(include_subdomains=False)
    guard_on, _ = make_guard(include_subdomains=True)
    assert not guard_off.is_in_scope("api.example.com")
    assert guard_on.is_in_scope("api.example.com")
    # Look-alike must never match even with subdomains enabled.
    assert not guard_on.is_in_scope("example.com.attacker.net")


def test_cidr_targets_for_active_scanning():
    # scope = example.com + 203.0.113.0/28
    guard, _ = make_guard()
    assert guard.is_in_scope("203.0.113.0/28")       # the authorized network itself
    assert guard.is_in_scope("203.0.113.0/29")       # a subnet within it
    assert not guard.is_in_scope("203.0.113.0/24")   # BROADER than authorized -> refused
    assert not guard.is_in_scope("10.0.0.0/8")       # unrelated range -> refused


def test_resolved_ip_rule():
    guard, _ = make_guard()
    # A non-listed host that resolves INTO an in-scope network is eligible...
    assert guard.is_in_scope("vhost.unknown.tld", resolved_ips=["203.0.113.9"])
    # ...but not if it resolves to an out-of-scope IP.
    assert not guard.is_in_scope("vhost.unknown.tld", resolved_ips=["8.8.8.8"])


def test_check_target_raises_and_logs_refusal():
    guard, events = make_guard()
    with pytest.raises(OutOfScopeError):
        guard.check_target("evil.com", module="nmap", phase=Phase.ACTIVE)
    assert any(e["outcome"] == "refused" and e["target"] == "evil.com" for e in events)


def test_filter_targets_splits_and_logs():
    guard, events = make_guard()
    allowed, refused = guard.filter_targets(
        ["203.0.113.5", "8.8.8.8", "example.com", "evil.com"],
        module="masscan", phase=Phase.ACTIVE,
    )
    assert set(allowed) == {"203.0.113.5", "example.com"}
    assert set(refused) == {"8.8.8.8", "evil.com"}
    assert sum(1 for e in events if e["outcome"] == "refused") == 2


# --------------------------------------------------------------------------- #
# Authorization + blackout gate
# --------------------------------------------------------------------------- #
def base_meta(**over):
    d = {"id": "e1", "client": "Example", "auth_ref": "T-1", "tester": "alice"}
    d.update(over)
    return EngagementMeta.from_dict(d)


def test_gate_refuses_without_authorization():
    audit, _ = make_audit()
    gate = ActiveGate(authorized=False, audit=audit, engagement=base_meta())
    with pytest.raises(NotAuthorizedError):
        gate.ensure_active_allowed()


def test_gate_allows_when_authorized_and_no_blackout():
    audit, _ = make_audit()
    gate = ActiveGate(authorized=True, audit=audit, engagement=base_meta())
    gate.ensure_active_allowed()  # must not raise


def test_gate_refuses_during_blackout():
    audit, _ = make_audit()
    now = utcnow()
    meta = base_meta(blackout=[{
        "start": (now - timedelta(hours=1)).isoformat(),
        "end": (now + timedelta(hours=1)).isoformat(),
    }])
    gate = ActiveGate(authorized=True, audit=audit, engagement=meta)
    with pytest.raises(BlackoutError):
        gate.ensure_active_allowed()


# --------------------------------------------------------------------------- #
# Guarded executor
# --------------------------------------------------------------------------- #
def test_executor_dry_run_plans_without_executing():
    guard, _ = make_guard()
    audit, _ = make_audit()
    gate = ActiveGate(authorized=True, audit=audit, engagement=base_meta())
    ex = GuardedExecutor(guard=guard, gate=gate, audit=audit, dry_run=True)
    res = ex.run("nmap", ["-sV"], ["203.0.113.5", "8.8.8.8"],
                 module="nmap", phase=Phase.ACTIVE)
    assert res.planned is True
    assert res.returncode is None
    assert res.allowed_targets == ["203.0.113.5"]
    assert res.refused_targets == ["8.8.8.8"]


def test_executor_refuses_active_execution_without_authorization():
    guard, _ = make_guard()
    audit, _ = make_audit()
    gate = ActiveGate(authorized=False, audit=audit, engagement=base_meta())
    ex = GuardedExecutor(guard=guard, gate=gate, audit=audit, dry_run=False)
    with pytest.raises(NotAuthorizedError):
        ex.run("nmap", ["-sV"], ["203.0.113.5"], module="nmap", phase=Phase.ACTIVE)


def test_executor_never_executes_out_of_scope_only():
    # If every target is out of scope, nothing runs even when authorized.
    guard, _ = make_guard()
    audit, _ = make_audit()
    gate = ActiveGate(authorized=True, audit=audit, engagement=base_meta())
    ex = GuardedExecutor(guard=guard, gate=gate, audit=audit, dry_run=False)
    res = ex.run("nmap", ["-sV"], ["8.8.8.8", "evil.com"], module="nmap", phase=Phase.ACTIVE)
    assert res.planned is True            # skipped-no-targets
    assert res.returncode is None
    assert set(res.refused_targets) == {"8.8.8.8", "evil.com"}


def test_executor_real_execution_passive():
    # Prove the subprocess path works end-to-end against an in-scope target.
    scope = parse_scope_text("localhost\n").scope
    audit, _ = make_audit()
    guard = ScopeGuard(scope=scope, audit=audit)
    gate = ActiveGate(authorized=True, audit=audit, engagement=base_meta())
    ex = GuardedExecutor(guard=guard, gate=gate, audit=audit, dry_run=False)
    res = ex.run(sys.executable, ["-c", "import sys; print('hi', sys.argv[1])"],
                 ["localhost"], module="demo", phase=Phase.PASSIVE)
    assert res.planned is False
    assert res.returncode == 0
    assert "hi localhost" in res.stdout
