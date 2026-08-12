"""Passive mail-security posture (spec §4.2).

Evaluates SPF, DMARC, DKIM (guessed selectors), MTA-STS, TLS-RPT, and BIMI for each
in-scope registrable domain and flags missing/weak policies — these were called out
explicitly as mattering for phishing risk. Pure scoring lives in `skrecon.mailsec`;
this module does the DNS lookups and presence checks.
"""

from __future__ import annotations

from typing import Iterable

from ..findings import make_finding
from ..mailsec import evaluate_dmarc, evaluate_spf
from ..model import Observation, Phase
from ..targets import scope_domains
from .base import REGISTRY, Action, Readiness

# Common DKIM selectors to probe (passive TXT lookups).
COMMON_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2", "smtp"]


class MailModule:
    name = "mail"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on: list[str] = []
    default_enabled = True

    def _domains(self, ctx) -> list[str]:
        return scope_domains(ctx.scope, ctx.settings.client_root_domains)

    def preflight(self, ctx) -> Readiness:
        if not ctx.resolver.available():
            return Readiness.skip("dnspython not installed (pip install '.[passive]')")
        if not self._domains(ctx):
            return Readiness.skip("no registrable domains in scope")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        domains = self._domains(ctx)
        return [Action(
            description=f"evaluate SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI for {len(domains)} domain(s)",
            phase=Phase.PASSIVE, targets=domains,
        )]

    def run(self, ctx) -> Iterable:
        for d in self._domains(ctx):
            # SPF + DMARC (scored by the pure evaluators)
            for ft, ev in evaluate_spf(ctx.resolver.resolve(d, "TXT")):
                yield make_finding(ft, affected=[d], evidence=[ev],
                                   source_module=self.name, title_ctx={"domain": d})
            for ft, ev in evaluate_dmarc(ctx.resolver.resolve(f"_dmarc.{d}", "TXT")):
                yield make_finding(ft, affected=[d], evidence=[ev],
                                   source_module=self.name, title_ctx={"domain": d})

            # DKIM: probe common selectors
            found = [s for s in COMMON_SELECTORS if ctx.resolver.resolve(f"{s}._domainkey.{d}", "TXT")]
            if found:
                yield Observation(subject=d, kind="dkim", data={"selectors": found})
            else:
                yield make_finding("mail.dkim.none_found", affected=[d],
                                   evidence=[f"probed: {', '.join(COMMON_SELECTORS)}"],
                                   source_module=self.name, title_ctx={"domain": d})

            # Presence checks for the newer records
            for label, ft in (
                (f"_mta-sts.{d}", "mail.mta_sts.missing"),
                (f"_smtp._tls.{d}", "mail.tls_rpt.missing"),
                (f"default._bimi.{d}", "mail.bimi.missing"),
            ):
                if not ctx.resolver.resolve(label, "TXT"):
                    yield make_finding(ft, affected=[d], evidence=[f"no TXT at {label}"],
                                       source_module=self.name, title_ctx={"domain": d})


REGISTRY.register(MailModule())
