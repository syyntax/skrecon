"""WAF detection via wafw00f (spec §5.7).

ACTIVE: detects a web application firewall so later findings are interpreted
correctly. Informational.
"""

from __future__ import annotations

import json
import shutil
from typing import Iterable

from ..findings import make_finding
from ..model import Observation, Phase
from ..webparse import parse_wafw00f
from ..webtargets import safe_name, web_targets
from .base import REGISTRY, Action, Readiness


class WafModule:
    name = "waf"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools = ["wafw00f"]
    requires_keys: list[str] = []
    depends_on = ["nmap"]
    default_enabled = True

    def preflight(self, ctx) -> Readiness:
        if not shutil.which("wafw00f"):
            return Readiness.skip("wafw00f not installed (provided by the Docker image)")
        if not web_targets(ctx):
            return Readiness.skip("no web services discovered")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        targets = web_targets(ctx)
        return [Action(description=f"wafw00f detect WAF on {len(targets)} web service(s)",
                       phase=Phase.ACTIVE, targets=[t["url"] for t in targets],
                       command="wafw00f -a -f json -o <out> <url>")]

    def run(self, ctx) -> Iterable:
        out_dir = ctx.raw_dir / "wafw00f"
        out_dir.mkdir(parents=True, exist_ok=True)
        for t in web_targets(ctx):
            out_file = out_dir / f"{safe_name(t['url'])}.json"
            res = ctx.executor.run("wafw00f", ["-a", "-f", "json", "-o", str(out_file)],
                                   [t["url"]], module=self.name, phase=Phase.ACTIVE)
            if res.planned or not out_file.exists():
                continue
            try:
                data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            for w in parse_wafw00f(data):
                yield Observation(subject=t["url"], kind="waf", data=w)
                if w["detected"]:
                    yield make_finding("waf.detected", affected=[t["url"]],
                                       evidence=[w.get("firewall") or "detected"],
                                       source_module=self.name, phase=Phase.ACTIVE,
                                       title_ctx={"url": t["url"], "firewall": w.get("firewall") or "unknown"})


REGISTRY.register(WafModule())
