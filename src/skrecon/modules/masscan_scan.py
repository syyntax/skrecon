"""Active port discovery via masscan (spec §5.1).

ACTIVE module (touches_targets=True): every target goes through the guarded
executor, which enforces the authorization gate and scope before a single packet
is sent. Rate is operator-controlled and conservative by default. Open ports feed
the nmap stage. masscan needs raw-socket privileges (run as root/admin).
"""

from __future__ import annotations

import shutil
from typing import Iterable

from ..model import Observation, Phase, Service, ServiceSource
from ..scanparse import parse_masscan_list
from .base import REGISTRY, Action, Readiness


class MasscanModule:
    name = "masscan"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools = ["masscan"]
    requires_keys: list[str] = []
    depends_on: list[str] = []
    default_enabled = True

    def _targets(self, ctx) -> list[str]:
        """In-scope networks (CIDR) + discovered IPs that are in scope. Membership is
        asked of the scope directly (which knows both listed networks and the IPs that
        listed hostnames resolved to), so a stale stored flag can't hide a target. The
        guarded executor re-validates each before running — defense-in-depth."""
        targets = [str(n) for n in ctx.scope.networks]
        targets += [h["ip"] for h in ctx.store.list_hosts() if ctx.scope.contains_ip(h["ip"])]
        seen: set[str] = set()
        out: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def preflight(self, ctx) -> Readiness:
        if not shutil.which("masscan"):
            return Readiness.skip("masscan not installed (provided by the Docker image)")
        if not self._targets(ctx):
            return Readiness.skip("no in-scope IP targets")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        targets = self._targets(ctx)
        ports = ctx.settings.masscan_ports
        pps = ctx.settings.rates.masscan_pps
        return [Action(
            description=f"masscan {len(targets)} target(s) at {pps} pps on {ports.count(',') + 1} ports",
            phase=Phase.ACTIVE, targets=targets,
            command=f"masscan --ports {ports} --rate {pps} -oL <raw>/masscan.list <targets>")]

    def run(self, ctx) -> Iterable:
        targets = self._targets(ctx)
        ports = ctx.settings.masscan_ports
        pps = ctx.settings.rates.masscan_pps

        out_dir = ctx.raw_dir / "masscan"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "masscan.list"

        res = ctx.executor.run(
            "masscan",
            ["--ports", ports, "--rate", str(pps), "--wait", "0", "-oL", str(out_file)],
            targets, module=self.name, phase=Phase.ACTIVE,
        )
        if res.planned or not out_file.exists():
            return

        parsed = parse_masscan_list(out_file.read_text(encoding="utf-8", errors="replace"))
        for ip, port_protos in parsed.items():
            for port, proto in port_protos:
                yield Service(host_ip=ip, port=port, proto=proto, state="open",
                              source=ServiceSource.MASSCAN)
        yield Observation(subject="masscan", kind="summary", data={
            "hosts": len(parsed),
            "open_ports": sum(len(v) for v in parsed.values()),
        })


REGISTRY.register(MasscanModule())
