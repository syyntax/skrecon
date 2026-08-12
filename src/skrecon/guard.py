"""The safety enforcement layer (spec §9): scope guard, authorization gate,
blackout gate, and the guarded subprocess executor.

This lives in the core so no module can bypass it. Modules never open sockets or
spawn scanners directly — they are handed a `ScopeGuard`, an `ActiveGate`, and a
`GuardedExecutor`, and those are the *only* routes to a target. Every target is
validated against `ResolvedScope` before any packet is sent; out-of-scope targets
are refused and logged, never contacted.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlsplit

from .audit import AuditLog
from .engagement import EngagementMeta
from .errors import BlackoutError, NotAuthorizedError, OutOfScopeError
from .model import Phase, utcnow
from .scope import ResolvedScope


def _extract_target_host(target: str) -> str:
    """Reduce a target string to the bare host/IP the guard should check."""
    t = target.strip()
    if "://" in t:
        host = urlsplit(t).hostname
        return host or t
    if t.startswith("["):
        m = re.match(r"^\[(?P<h>[^\]]+)\](?::\d+)?$", t)
        if m:
            return m.group("h")
    try:
        ipaddress.ip_address(t)
        return t                      # bare IP literal
    except ValueError:
        pass
    if t.count(":") == 1:             # host:port (not IPv6 — that has many colons)
        host, port = t.rsplit(":", 1)
        if port.isdigit():
            return host
    return t


# --------------------------------------------------------------------------- #
# Scope guard
# --------------------------------------------------------------------------- #
@dataclass
class ScopeGuard:
    scope: ResolvedScope
    audit: AuditLog
    include_subdomains: bool = False

    def is_in_scope(self, target: str, *, resolved_ips: Optional[list[str]] = None) -> bool:
        host = _extract_target_host(target)
        try:
            ipaddress.ip_address(host)
            return self.scope.contains_ip(host)
        except ValueError:
            pass
        # hostname path
        if self.scope.contains_host(host, include_subdomains=self.include_subdomains):
            return True
        # rule (3): a host that resolves to an in-scope IP is eligible
        if resolved_ips:
            return any(self.scope.contains_ip(ip) for ip in resolved_ips)
        return False

    def check_target(
        self,
        target: str,
        *,
        module: str,
        phase: Phase,
        resolved_ips: Optional[list[str]] = None,
    ) -> str:
        """Return the target if in scope; otherwise log + raise OutOfScopeError."""
        if self.is_in_scope(target, resolved_ips=resolved_ips):
            self.audit.allowed(module=module, target=target, phase=phase)
            return target
        self.audit.refused(module=module, target=target, reason="not in resolved scope", phase=phase)
        raise OutOfScopeError(target)

    def filter_targets(
        self,
        targets: list[str],
        *,
        module: str,
        phase: Phase,
        resolved_ips_map: Optional[dict[str, list[str]]] = None,
    ) -> tuple[list[str], list[str]]:
        """Split targets into (allowed, refused). Non-raising; logs every decision."""
        allowed: list[str] = []
        refused: list[str] = []
        rmap = resolved_ips_map or {}
        for t in targets:
            if self.is_in_scope(t, resolved_ips=rmap.get(t)):
                allowed.append(t)
                self.audit.allowed(module=module, target=t, phase=phase)
            else:
                refused.append(t)
                self.audit.refused(module=module, target=t, reason="not in resolved scope", phase=phase)
        return allowed, refused


# --------------------------------------------------------------------------- #
# Authorization + blackout gate for the ACTIVE phase
# --------------------------------------------------------------------------- #
@dataclass
class ActiveGate:
    authorized: bool
    audit: AuditLog
    engagement: Optional[EngagementMeta] = None
    clock: Callable[[], datetime] = utcnow

    def ensure_active_allowed(self) -> None:
        """Raise if the active phase must not proceed right now."""
        if not self.authorized:
            self.audit.record(module="core", action="auth-gate", outcome="refused",
                              phase=Phase.ACTIVE, detail="authorization not confirmed")
            raise NotAuthorizedError(
                "active phase requires explicit authorization confirmation "
                "(--i-am-authorized) plus recorded engagement metadata"
            )
        now = self.clock()
        if self.engagement is not None:
            window = self.engagement.is_blackout(now)
            if window is not None:
                self.audit.record(module="core", action="blackout-gate", outcome="refused",
                                  phase=Phase.ACTIVE, detail=window.label())
                raise BlackoutError(window.label())
        self.audit.record(module="core", action="active-gate", outcome="allowed", phase=Phase.ACTIVE)


# --------------------------------------------------------------------------- #
# Guarded executor
# --------------------------------------------------------------------------- #
@dataclass
class ExecResult:
    tool: str
    argv: list[str]
    planned: bool = False
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    refused_targets: list[str] = field(default_factory=list)
    allowed_targets: list[str] = field(default_factory=list)


@dataclass
class GuardedExecutor:
    """The only sanctioned way to run an external scanner against targets.

    Guarantees: (1) the active gate is satisfied before any active tool runs;
    (2) every target is scope-validated and out-of-scope ones are dropped + logged;
    (3) in dry-run nothing executes — the exact command is planned and audited.
    """
    guard: ScopeGuard
    gate: ActiveGate
    audit: AuditLog
    dry_run: bool = False

    def run(
        self,
        tool: str,
        args: list[str],
        targets: list[str],
        *,
        module: str,
        phase: Phase,
        resolved_ips_map: Optional[dict[str, list[str]]] = None,
        timeout: Optional[float] = None,
    ) -> ExecResult:
        # Scope is always validated — even a dry-run plan shows what is refused.
        allowed, refused = self.guard.filter_targets(
            targets, module=module, phase=phase, resolved_ips_map=resolved_ips_map
        )
        argv = [tool, *args, *allowed]
        cmd_str = " ".join(argv)

        will_execute = (not self.dry_run) and bool(allowed)

        # The gate blocks *execution* of active work, not planning. Dry-run may
        # preview an active plan without authorization; nothing is sent.
        if phase is Phase.ACTIVE and will_execute:
            self.gate.ensure_active_allowed()

        if not will_execute:
            outcome = "planned" if self.dry_run else "skipped-no-targets"
            self.audit.record(
                module=module, action="exec", outcome=outcome, phase=phase,
                command=cmd_str, detail=f"allowed={len(allowed)} refused={len(refused)}",
            )
            return ExecResult(tool=tool, argv=argv, planned=True,
                              refused_targets=refused, allowed_targets=allowed)

        self.audit.record(module=module, action="exec", outcome="started", phase=phase,
                          command=cmd_str, detail=f"allowed={len(allowed)} refused={len(refused)}")
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            self.audit.record(module=module, action="exec", outcome="error", phase=phase,
                              command=cmd_str, detail=str(exc))
            raise
        self.audit.record(module=module, action="exec", outcome="finished", phase=phase,
                          command=cmd_str, detail=f"rc={proc.returncode}")
        return ExecResult(
            tool=tool, argv=argv, planned=False, returncode=proc.returncode,
            stdout=proc.stdout, stderr=proc.stderr,
            refused_targets=refused, allowed_targets=allowed,
        )


@dataclass
class GuardedHttp:
    """Guarded entry point for target-directed HTTP (active web modules, Phase 4).

    `check_url` is the scope gate for a URL; the actual fetch implementation lands
    with the Phase-4 web modules. Passive third-party API calls do NOT go through
    here — they use an unguarded client since they never touch client targets.
    """
    guard: ScopeGuard
    audit: AuditLog
    dry_run: bool = False

    def check_url(
        self,
        url: str,
        *,
        module: str,
        phase: Phase = Phase.ACTIVE,
        resolved_ips: Optional[list[str]] = None,
    ) -> str:
        return self.guard.check_target(url, module=module, phase=phase, resolved_ips=resolved_ips)
