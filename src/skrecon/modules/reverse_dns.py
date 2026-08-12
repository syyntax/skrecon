"""Passive reverse DNS / PTR lookups (spec §4.1).

Runs PTR for every explicitly-listed single IP plus every IP discovered by the
`dns` module (hence the dependency), and records the names back onto the host.
CIDR-wide PTR sweeps are deferred (they are enumeration-heavy); single IPs and
resolved IPs cover the correlation need.
"""

from __future__ import annotations

from typing import Iterable

from ..model import DnsRecord, HostIP, Observation, Phase
from .base import REGISTRY, Action, Readiness


class ReverseDnsModule:
    name = "reverse-dns"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys: list[str] = []
    depends_on = ["dns"]
    default_enabled = True

    def _ips(self, ctx) -> list[str]:
        ips: set[str] = {h["ip"] for h in ctx.store.list_hosts()}
        for net in ctx.scope.networks:
            if net.num_addresses == 1:                 # explicitly-listed single IP
                ips.add(str(net.network_address))
        return sorted(ips)

    def preflight(self, ctx) -> Readiness:
        if not ctx.resolver.available():
            return Readiness.skip("dnspython not installed (pip install '.[passive]')")
        if not self._ips(ctx):
            return Readiness.skip("no IPs to reverse-resolve yet")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        ips = self._ips(ctx)
        return [Action(description=f"PTR lookup for {len(ips)} IP(s)",
                       phase=Phase.PASSIVE, targets=ips)]

    def run(self, ctx) -> Iterable:
        for ip in self._ips(ctx):
            names = ctx.resolver.reverse(ip)
            for name in names:
                yield DnsRecord(domain=ip, rtype="PTR", value=name)
                yield Observation(subject=ip, kind="ptr", data={"name": name})
            if names:
                yield HostIP(ip=ip, version=6 if ":" in ip else 4,
                             ptr=names[0], in_scope=ctx.scope.contains_ip(ip))


REGISTRY.register(ReverseDnsModule())
