"""Shodan internet-exposure intelligence (spec §4.7).

Pulls Shodan's last-observed host data (ports, product/version banners, detected
CVEs) for scoped and discovered IPs. This is THIRD-PARTY-OBSERVED, not
tester-confirmed — services are tagged source=shodan and CVEs are MEDIUM findings
that must be validated. Passive: Shodan scanned, not us.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional

from ..findings import make_finding
from ..model import Observation, Phase, Service, ServiceSource
from ..osint import parse_shodan_host
from .base import REGISTRY, Action, Readiness

IP_CAP = 64   # bound Shodan API calls (and quota) per run


class ShodanModule:
    name = "shodan"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys = ["SHODAN_API_KEY"]
    depends_on = ["dns"]
    default_enabled = True

    def _key(self, ctx) -> Optional[str]:
        return os.environ.get("SHODAN_API_KEY")

    def _ips(self, ctx) -> list[str]:
        ips = {h["ip"] for h in ctx.store.list_hosts()}
        for net in ctx.scope.networks:
            if net.num_addresses == 1:
                ips.add(str(net.network_address))
        return sorted(ips)[:IP_CAP]

    def preflight(self, ctx) -> Readiness:
        if not self._key(ctx):
            return Readiness.skip("SHODAN_API_KEY not set")
        if not self._ips(ctx):
            return Readiness.skip("no IPs to query yet")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        ips = self._ips(ctx)
        return [Action(description=f"Shodan host lookup for {len(ips)} IP(s)",
                       phase=Phase.PASSIVE, targets=ips,
                       command="GET https://api.shodan.io/shodan/host/<ip>")]

    def run(self, ctx) -> Iterable:
        key = self._key(ctx)
        for ip in self._ips(ctx):
            # Key is a query param; the audit log redacts the literal key value, and
            # cache_key omits it so the key never reaches the cache filename input.
            status, data = ctx.http_passive.get_json(
                f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                module=self.name, cache_key=f"shodan:host:{ip}",
            )
            if not data:
                continue
            parsed = parse_shodan_host(data)
            for s in parsed["services"]:
                if s["port"] is None:
                    continue
                yield Service(host_ip=ip, port=int(s["port"]), proto=s["proto"] or "tcp",
                              product=s["product"], version=s["version"],
                              source=ServiceSource.SHODAN)
            for cve in parsed["cves"]:
                yield make_finding("shodan.vuln", affected=[ip], evidence=[cve],
                                   source_module=self.name, title_ctx={"cve": cve, "ip": ip})
            if parsed["services"]:
                yield make_finding("shodan.exposed_service", affected=[ip],
                                   evidence=[f"ports: {parsed['ports']}"], source_module=self.name,
                                   title_ctx={"count": len(parsed["services"]), "ip": ip})
                yield Observation(subject=ip, kind="shodan", data={
                    "ports": parsed["ports"], "org": parsed["org"],
                    "hostnames": parsed["hostnames"], "os": parsed["os"]})


REGISTRY.register(ShodanModule())
