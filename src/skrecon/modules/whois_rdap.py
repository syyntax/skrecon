"""Passive WHOIS/RDAP for domains and IPs (spec §4.3).

Queries RDAP (structured JSON, via the rdap.org bootstrap) for each in-scope
registrable domain and derives expiry / registrar-lock findings. Also pulls
IP/ASN ownership for a capped set of discovered IPs for netblock footprinting.
Degrades to observations (found=false) when offline — never crashes the run.
"""

from __future__ import annotations

from typing import Iterable

from ..findings import make_finding
from ..model import Observation, Phase
from ..rdap import evaluate_domain, parse_rdap_domain
from ..targets import scope_domains
from .base import REGISTRY, Action, Readiness

IP_RDAP_CAP = 16   # bound rdap.org calls for IP/ASN lookups


class WhoisRdapModule:
    name = "whois-rdap"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on = ["dns"]           # so discovered IPs are available for IP/ASN lookups
    default_enabled = True

    def _domains(self, ctx) -> list[str]:
        return scope_domains(ctx.scope, ctx.settings.client_root_domains)

    def preflight(self, ctx) -> Readiness:
        if not self._domains(ctx):
            return Readiness.skip("no registrable domains in scope")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        domains = self._domains(ctx)
        return [Action(
            description=f"RDAP lookup for {len(domains)} domain(s) + up to {IP_RDAP_CAP} IP(s)",
            phase=Phase.PASSIVE, targets=domains,
            command="GET https://rdap.org/domain/<domain>",
        )]

    def run(self, ctx) -> Iterable:
        for domain in self._domains(ctx):
            status, data = ctx.http_passive.get_json(
                f"https://rdap.org/domain/{domain}",
                accept="application/rdap+json", module=self.name,
            )
            if not data:
                yield Observation(subject=domain, kind="rdap-domain",
                                  data={"found": False, "status": status})
                continue
            parsed = parse_rdap_domain(data)
            yield Observation(subject=domain, kind="rdap-domain", data={
                "found": True,
                "registrar": parsed.registrar,
                "expiration": parsed.expiration.isoformat() if parsed.expiration else None,
                "statuses": parsed.statuses,
                "delegation_signed": parsed.delegation_signed,
            })
            for ft, evidence, title_ctx in evaluate_domain(
                parsed, domain, warn_days=ctx.settings.expiry_warn_days
            ):
                yield make_finding(ft, affected=[domain], evidence=[evidence],
                                   source_module=self.name, title_ctx=title_ctx)

        # IP / ASN ownership for a bounded set of discovered IPs.
        for host in ctx.store.list_hosts()[:IP_RDAP_CAP]:
            ip = host["ip"]
            status, data = ctx.http_passive.get_json(
                f"https://rdap.org/ip/{ip}", accept="application/rdap+json", module=self.name)
            if data:
                yield Observation(subject=ip, kind="rdap-ip", data={
                    "org": data.get("name"),
                    "handle": data.get("handle"),
                    "start": data.get("startAddress"),
                    "end": data.get("endAddress"),
                })


REGISTRY.register(WhoisRdapModule())
