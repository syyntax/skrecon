"""DeHashed breach & credential exposure (spec §4.9).

Queries DeHashed for the client's domains and stores raw records in the ENCRYPTED
VAULT only. Reports and the main store carry aggregate counts (per breach source,
plaintext vs. hashed) — never plaintext secrets. Runs on CLIENT scope. Refuses to
fetch if the vault is unavailable, so PII is never written unencrypted.
"""

from __future__ import annotations

import base64
import os
from typing import Iterable, Optional

from ..findings import make_finding
from ..model import Exposure, ExposureFormat, Phase
from ..osint import summarize_dehashed
from ..targets import scope_domains
from .base import REGISTRY, Action, Readiness


class DehashedModule:
    name = "dehashed"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools: list[str] = []
    requires_keys = ["DEHASHED_API_KEY", "DEHASHED_EMAIL"]
    depends_on: list[str] = []
    default_enabled = True

    def _creds(self, ctx) -> tuple[Optional[str], Optional[str]]:
        return os.environ.get("DEHASHED_API_KEY"), os.environ.get("DEHASHED_EMAIL")

    def _domains(self, ctx) -> list[str]:
        return scope_domains(ctx.scope, ctx.settings.client_root_domains)

    def preflight(self, ctx) -> Readiness:
        key, email = self._creds(ctx)
        if not key or not email:
            return Readiness.skip("DEHASHED_API_KEY / DEHASHED_EMAIL not set")
        # Never fetch PII we cannot store encrypted.
        reason = ctx.vault.unavailable_reason()
        if reason:
            return Readiness.skip(reason)
        if not self._domains(ctx):
            return Readiness.skip("no registrable domains in scope")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        domains = self._domains(ctx)
        return [Action(
            description=f"DeHashed search for {len(domains)} domain(s); raw -> encrypted vault, counts -> report",
            phase=Phase.PASSIVE, targets=domains,
            command="GET https://api.dehashed.com/search?query=domain:<domain>")]

    def run(self, ctx) -> Iterable:
        key, email = self._creds(ctx)
        token = base64.b64encode(f"{email}:{key}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}

        for domain in self._domains(ctx):
            status, data = ctx.http_passive.get_json(
                f"https://api.dehashed.com/search?query=domain:{domain}&size=10000",
                module=self.name, headers=headers, no_cache=True,   # PII must not be cached
            )
            if not data:
                continue

            entries = data.get("entries") or []
            summary = summarize_dehashed(data)

            vault_ref = None
            if entries:
                ctx.vault.add_many("breach", [{"domain": domain, **e} for e in entries])
                vault_ref = f"vault:breach ({len(entries)} record(s))"
                ctx.audit.record(module=self.name, action="vault-store", outcome="stored",
                                 target=domain, detail=f"{len(entries)} record(s) encrypted")

            for src, info in summary["by_source"].items():
                yield Exposure(
                    client_id=domain, breach_source=src, record_count=info["count"],
                    fmt=ExposureFormat.PLAINTEXT if info["plaintext"] else ExposureFormat.HASHED,
                    vault_ref=vault_ref,
                )

            if summary["total"]:
                yield make_finding(
                    "exposure.credentials", affected=[domain],
                    evidence=[f"{summary['total']} record(s) across {len(summary['by_source'])} source(s)"],
                    source_module=self.name, title_ctx={"client": domain, "count": summary["total"]})
            if summary["plaintext_any"]:
                yield make_finding(
                    "exposure.plaintext", affected=[domain],
                    evidence=["plaintext password(s) present in breach data"],
                    source_module=self.name, title_ctx={"client": domain})


REGISTRY.register(DehashedModule())
