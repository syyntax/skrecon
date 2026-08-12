"""Passive forward DNS enumeration (spec §4.1).

Resolves the standard record set for every in-scope host, records the
domain -> CNAME -> IP resolution chain, marks which hosts resolve (and whether to
in-scope IPs), and flags missing DNSSEC at the registrable zone. No traffic to
client targets beyond recursive DNS queries.
"""

from __future__ import annotations

from typing import Iterable

from ..findings import make_finding
from ..model import DnsRecord, DomainName, HostIP, Phase, ResolutionEdge
from ..targets import registrable_domain
from .base import REGISTRY, Action, Readiness

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV"]


class DnsModule:
    name = "dns"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on: list[str] = []
    default_enabled = True

    def _hosts(self, ctx) -> list[str]:
        return sorted(ctx.scope.hostnames)

    def preflight(self, ctx) -> Readiness:
        if not ctx.resolver.available():
            return Readiness.skip("dnspython not installed (pip install '.[passive]')")
        if not self._hosts(ctx):
            return Readiness.skip("no in-scope hostnames to resolve")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        hosts = self._hosts(ctx)
        return [Action(
            description=f"resolve {len(hosts)} host(s) for {'/'.join(RECORD_TYPES)} + DNSSEC",
            phase=Phase.PASSIVE, targets=hosts,
        )]

    def run(self, ctx) -> Iterable:
        seen_zone: set[str] = set()
        for host in self._hosts(ctx):
            resolved = False
            for rtype in RECORD_TYPES:
                for value in ctx.resolver.resolve(host, rtype):
                    yield DnsRecord(domain=host, rtype=rtype, value=value)
                    if rtype in ("A", "AAAA"):
                        resolved = True
                        yield HostIP(ip=value, version=6 if ":" in value else 4,
                                     in_scope=ctx.scope.contains_ip(value))
                        yield ResolutionEdge(src=host, via=None, dst=value)
                    elif rtype == "CNAME":
                        yield ResolutionEdge(src=host, via=value.rstrip("."), dst=value.rstrip("."))

            yield DomainName(fqdn=host, registrable_domain=registrable_domain(host),
                             is_scope=True, resolves=resolved)
            if not resolved:
                yield make_finding("dns.no_resolution", affected=[host],
                                   evidence=["no A/AAAA records"], source_module=self.name,
                                   title_ctx={"domain": host})

            # DNSSEC is a zone-level property — check each registrable zone once.
            zone = registrable_domain(host)
            if zone not in seen_zone:
                seen_zone.add(zone)
                if not ctx.resolver.dnssec_present(zone):
                    yield make_finding("dns.dnssec.missing", affected=[zone],
                                       evidence=["no DNSKEY published at zone"],
                                       source_module=self.name, title_ctx={"domain": zone})


REGISTRY.register(DnsModule())
