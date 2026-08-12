"""Passive subdomain aggregation + resolution (spec §4.6).

Aggregates subdomains discovered by `ct` (and subfinder, if the binary is present),
resolves them, and records which resolve — and which resolve to an in-scope IP,
making them eligible for the active phase (respecting scope). Resolution is capped
to keep the pass bounded on large certificate footprints.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable

from ..model import DomainName, HostIP, Observation, Phase, ResolutionEdge
from ..targets import scope_domains
from .base import REGISTRY, Action, Readiness

RESOLVE_CAP = 300   # max names resolved per run (passive but bounded)


class SubdomainsModule:
    name = "subdomains"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []       # subfinder is optional, not required
    requires_keys: list[str] = []
    depends_on = ["ct", "dns"]
    default_enabled = True

    def preflight(self, ctx) -> Readiness:
        if not ctx.resolver.available():
            return Readiness.skip("dnspython not installed (pip install '.[passive]')")
        return Readiness.ok()

    def _subfinder(self, apex: str) -> list[str]:
        exe = shutil.which("subfinder")
        if not exe:
            return []
        try:
            proc = subprocess.run([exe, "-d", apex, "-silent"],
                                  capture_output=True, text=True, timeout=180)
            return [ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip()]
        except (OSError, subprocess.SubprocessError):
            return []

    def plan(self, ctx) -> list[Action]:
        known = len(ctx.store.list_domains())
        extra = "subfinder + " if shutil.which("subfinder") else ""
        return [Action(
            description=f"aggregate ({extra}CT) and resolve up to {RESOLVE_CAP} subdomain(s) "
                        f"(~{known} known)",
            phase=Phase.PASSIVE)]

    def run(self, ctx) -> Iterable:
        known = {d["fqdn"] for d in ctx.store.list_domains()}

        # subfinder augmentation (optional external tool)
        for apex in scope_domains(ctx.scope, ctx.settings.client_root_domains):
            for name in self._subfinder(apex):
                if name not in known:
                    known.add(name)
                    yield DomainName(fqdn=name, registrable_domain=apex, is_scope=False)

        eligible = 0
        resolved = 0
        for name in sorted(known)[:RESOLVE_CAP]:
            ips = ctx.resolver.resolve_ips(name)
            if not ips:
                continue
            resolved += 1
            in_scope_ip = False
            for ip in ips:
                is_scope = ctx.scope.contains_ip(ip)
                in_scope_ip = in_scope_ip or is_scope
                yield HostIP(ip=ip, version=6 if ":" in ip else 4, in_scope=is_scope)
                yield ResolutionEdge(src=name, via=None, dst=ip)
            yield DomainName(fqdn=name, resolves=True, is_scope=name in ctx.scope.hostnames)
            if in_scope_ip:
                eligible += 1

        yield Observation(subject="subdomains", kind="summary", data={
            "known": len(known), "resolved": resolved, "active_eligible": eligible,
        })


REGISTRY.register(SubdomainsModule())
