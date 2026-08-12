"""Passive typosquatting / brand-abuse discovery (spec §4.4).

Wraps dnstwist to generate permutations of each in-scope registrable domain and
report those that are *registered*, flagging any with live MX as phishing-capable.
dnstwist resolves look-alike (third-party) domains, so this is passive w.r.t. the
client. Skips cleanly if dnstwist is not installed.
"""

from __future__ import annotations

from typing import Iterable

from ..findings import make_finding
from ..model import Phase
from ..targets import scope_domains
from .base import REGISTRY, Action, Readiness


class TyposquatModule:
    name = "typosquat"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on: list[str] = []
    default_enabled = True

    def _domains(self, ctx) -> list[str]:
        return scope_domains(ctx.scope, ctx.settings.client_root_domains)

    def _available(self) -> bool:
        try:
            import dnstwist  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False

    def preflight(self, ctx) -> Readiness:
        if not self._available():
            return Readiness.skip("dnstwist not installed (pip install '.[passive]')")
        if not self._domains(ctx):
            return Readiness.skip("no registrable domains in scope")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        domains = self._domains(ctx)
        return [Action(
            description=f"dnstwist permutations for {len(domains)} domain(s), report registered look-alikes",
            phase=Phase.PASSIVE, targets=domains,
        )]

    def run(self, ctx) -> Iterable:
        import dnstwist

        for d in self._domains(ctx):
            try:
                results = dnstwist.run(domain=d, registered=True, format="null")
            except TypeError:
                results = dnstwist.run(domain=d, format="null")
            except Exception as exc:  # noqa: BLE001 — one bad domain shouldn't kill the module
                ctx.audit.record(module=self.name, action="dnstwist", outcome="error",
                                 target=d, detail=str(exc))
                continue

            for r in results or []:
                cand = r.get("domain") or r.get("domain-name")
                if not cand or cand == d:
                    continue
                fuzzer = r.get("fuzzer", "?")
                yield make_finding("typosquat.registered", affected=[cand],
                                   evidence=[f"look-alike of {d} (fuzzer={fuzzer})"],
                                   source_module=self.name, title_ctx={"candidate": cand})
                mx = r.get("dns_mx") or r.get("dns-mx")
                if mx:
                    yield make_finding("typosquat.mx_present", affected=[cand],
                                       evidence=[f"MX: {mx}"], source_module=self.name,
                                       title_ctx={"candidate": cand})


REGISTRY.register(TyposquatModule())
