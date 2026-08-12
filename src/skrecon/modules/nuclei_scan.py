"""Templated vulnerability scanning via nuclei (spec §5.7) — OPT-IN, off by default.

ACTIVE and the noisiest module, so `default_enabled=False`. When enabled it runs a
conservative set: standard severities but excluding dos/intrusive/fuzzing template
tags, rate-limited. Matches are recorded as findings at the template's severity;
they must be validated before reporting.
"""

from __future__ import annotations

import shutil
from typing import Iterable

from ..findings import make_finding
from ..model import Phase
from ..webparse import nuclei_finding_type, parse_nuclei
from ..webtargets import safe_name, web_targets
from .base import REGISTRY, Action, Readiness

EXCLUDE_TAGS = "dos,intrusive,fuzzing"
SEVERITIES = "low,medium,high,critical"
RATE_LIMIT = "150"


class NucleiModule:
    name = "nuclei"
    phase = Phase.ACTIVE
    touches_targets = True
    requires_tools = ["nuclei"]
    requires_keys: list[str] = []
    depends_on = ["nmap"]
    default_enabled = False        # opt-in: enable via [modules] nuclei = true

    def preflight(self, ctx) -> Readiness:
        if not shutil.which("nuclei"):
            return Readiness.skip("nuclei not installed (provided by the Docker image)")
        if not web_targets(ctx):
            return Readiness.skip("no web services discovered")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        targets = web_targets(ctx)
        return [Action(
            description=f"nuclei ({SEVERITIES}; exclude {EXCLUDE_TAGS}) on {len(targets)} web service(s)",
            phase=Phase.ACTIVE, targets=[t["url"] for t in targets],
            command=f"nuclei -jsonl -severity {SEVERITIES} -etags {EXCLUDE_TAGS} "
                    f"-rate-limit {RATE_LIMIT} -o <out> -u <url>")]

    def run(self, ctx) -> Iterable:
        out_dir = ctx.raw_dir / "nuclei"
        out_dir.mkdir(parents=True, exist_ok=True)
        for t in web_targets(ctx):
            out_file = out_dir / f"{safe_name(t['url'])}.jsonl"
            res = ctx.executor.run(
                "nuclei",
                ["-silent", "-jsonl", "-severity", SEVERITIES, "-etags", EXCLUDE_TAGS,
                 "-rate-limit", RATE_LIMIT, "-o", str(out_file), "-u"],
                [t["url"]], module=self.name, phase=Phase.ACTIVE,
            )
            if res.planned or not out_file.exists():
                continue
            for f in parse_nuclei(out_file.read_text(encoding="utf-8", errors="replace")):
                yield make_finding(
                    nuclei_finding_type(f["severity"]), affected=[t["url"]],
                    evidence=[f"{f['template']} @ {f['matched']}"], source_module=self.name,
                    phase=Phase.ACTIVE, title_ctx={"url": t["url"], "name": f["name"] or f["template"]})


REGISTRY.register(NucleiModule())
