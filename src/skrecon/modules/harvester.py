"""Email & persona harvesting via theHarvester (spec §4.8).

Collects public emails/hosts for each in-scope domain. Personas are privacy-
implicating PII: raw emails go to the ENCRYPTED VAULT, and only the count + the
derived email-address format surface in the report. Best-effort wrapper around the
theHarvester CLI; skips cleanly if the tool (or the vault) is unavailable.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Iterable, Optional

from ..model import DomainName, Observation, Phase
from ..targets import registrable_domain, scope_domains
from .base import REGISTRY, Action, Readiness

SOURCES = "bing,duckduckgo,crtsh,rapiddns"


def _email_format(emails: list[str], domain: str) -> Optional[str]:
    """Guess the address format (e.g. first.last@) from harvested locals."""
    for e in emails:
        local = e.split("@", 1)[0]
        if "." in local:
            return "first.last@" + domain
        if local.isalpha() and len(local) > 1:
            return "flast@ or first@ " + domain
    return None


class HarvesterModule:
    name = "harvester"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools = ["theHarvester"]
    requires_keys: list[str] = []
    depends_on: list[str] = []
    default_enabled = True

    def _bin(self) -> Optional[str]:
        return shutil.which("theHarvester") or shutil.which("theharvester")

    def _domains(self, ctx) -> list[str]:
        return scope_domains(ctx.scope, ctx.settings.client_root_domains)

    def preflight(self, ctx) -> Readiness:
        if not self._bin():
            return Readiness.skip("theHarvester not installed")
        reason = ctx.vault.unavailable_reason()
        if reason:
            return Readiness.skip(reason)
        if not self._domains(ctx):
            return Readiness.skip("no registrable domains in scope")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        domains = self._domains(ctx)
        return [Action(
            description=f"theHarvester ({SOURCES}) for {len(domains)} domain(s); emails -> vault",
            phase=Phase.PASSIVE, targets=domains)]

    def run(self, ctx) -> Iterable:
        exe = self._bin()
        for domain in self._domains(ctx):
            data = self._harvest(exe, domain)
            if data is None:
                continue
            emails = sorted({str(e).lower() for e in (data.get("emails") or [])})
            hosts = sorted({str(h).split(":")[0].lower() for h in (data.get("hosts") or [])})

            if emails:
                ctx.vault.add_many("persona", [{"domain": domain, "email": e} for e in emails])
                ctx.audit.record(module=self.name, action="vault-store", outcome="stored",
                                 target=domain, detail=f"{len(emails)} email(s) encrypted")
                yield Observation(subject=domain, kind="persona-summary", data={
                    "emails": len(emails),
                    "email_format": _email_format(emails, domain),
                    "vault_ref": f"vault:persona ({len(emails)})",
                })
            for h in hosts:
                if h.endswith(domain):
                    yield DomainName(fqdn=h, registrable_domain=registrable_domain(h),
                                     is_scope=h in ctx.scope.hostnames)

    def _harvest(self, exe: str, domain: str) -> Optional[dict]:
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "harvest")
            try:
                subprocess.run([exe, "-d", domain, "-b", SOURCES, "-f", out],
                               capture_output=True, text=True, timeout=300)
            except (OSError, subprocess.SubprocessError):
                return None
            # theHarvester writes <out>.json in recent versions.
            for candidate in (out + ".json", out):
                if os.path.exists(candidate):
                    try:
                        with open(candidate, encoding="utf-8") as fh:
                            return json.load(fh)
                    except (OSError, json.JSONDecodeError):
                        return None
        return None


REGISTRY.register(HarvesterModule())
