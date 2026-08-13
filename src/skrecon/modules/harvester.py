"""Email & persona harvesting via theHarvester (spec §4.8).

Collects public emails/hosts for each in-scope registrable domain and each client
root domain. Harvested emails surface in the report (client request) when
`report_emails` is enabled; when a vault passphrase is set they are ALSO written to
the encrypted vault for retention hygiene. Best-effort wrapper around the
theHarvester CLI: it persists raw output for diagnosis and skips cleanly if the
tool is unavailable.
"""

from __future__ import annotations

import json
import re
import subprocess
import shutil
import sys
from pathlib import Path
from typing import Iterable, Optional

from ..model import DomainName, Observation, Phase
from ..targets import registrable_domain, scope_domains
from .base import REGISTRY, Action, Readiness

_TIMEOUT = 300
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9.\-]+", "_", value.lower()).strip("_") or "domain"


def _email_format(emails: list[str], domain: str) -> Optional[str]:
    """Guess the address format (e.g. first.last@) from harvested locals."""
    for e in emails:
        local = e.split("@", 1)[0]
        if "." in local:
            return "first.last@" + domain
        if local.isalpha() and len(local) > 1:
            return "flast@ or first@ " + domain
    return None


def _emails_for_domain(candidates: Iterable[str], domain: str) -> list[str]:
    """Keep addresses whose host is the domain or a subdomain of it."""
    out: set[str] = set()
    for raw in candidates:
        e = str(raw).strip().lower()
        if "@" not in e:
            continue
        host = e.rsplit("@", 1)[1]
        if host == domain or host.endswith("." + domain):
            out.add(e)
    return sorted(out)


class HarvesterModule:
    name = "harvester"
    phase = Phase.PASSIVE
    touches_targets = False
    requires_tools = ["theHarvester"]
    requires_keys: list[str] = []
    depends_on: list[str] = []
    default_enabled = True

    def _bin(self) -> Optional[list[str]]:
        exe = shutil.which("theHarvester") or shutil.which("theharvester")
        if exe:
            return [exe]
        # Fall back to the importable module if only the package (not a console
        # script) is installed.
        try:
            import theHarvester  # noqa: F401
            return [sys.executable, "-m", "theHarvester"]
        except Exception:  # noqa: BLE001
            return None

    def _domains(self, ctx) -> list[str]:
        return scope_domains(ctx.scope, ctx.settings.client_root_domains)

    def _scope_registrable(self, ctx) -> set[str]:
        return {registrable_domain(h) for h in ctx.scope.hostnames}

    def preflight(self, ctx) -> Readiness:
        if not self._bin():
            return Readiness.skip("theHarvester not installed")
        if not self._domains(ctx):
            return Readiness.skip("no registrable domains in scope")
        return Readiness.ok()

    def plan(self, ctx) -> list[Action]:
        domains = self._domains(ctx)
        sources = ctx.settings.harvester_sources
        return [Action(
            description=f"theHarvester ({sources}) for {len(domains)} domain(s)",
            phase=Phase.PASSIVE, targets=domains)]

    def run(self, ctx) -> Iterable:
        cmd = self._bin()
        scope_regs = self._scope_registrable(ctx)
        vault_ok = ctx.vault.available()
        for domain in self._domains(ctx):
            data = self._harvest(ctx, cmd, domain)
            if data is None:
                continue
            emails = _emails_for_domain(data.get("emails") or [], domain)
            hosts = sorted({str(h).split(":")[0].lower() for h in (data.get("hosts") or [])})
            in_scope = domain in scope_regs

            if emails:
                # Encrypted-at-rest copy when a passphrase is configured.
                if vault_ok:
                    ctx.vault.add_many("persona", [{"domain": domain, "email": e} for e in emails])
                    ctx.audit.record(module=self.name, action="vault-store", outcome="stored",
                                     target=domain, detail=f"{len(emails)} email(s) encrypted")
                # Report-visible addresses (operator opt-in, on by default).
                if ctx.settings.report_emails:
                    for e in emails:
                        yield Observation(subject=domain, kind="email",
                                          data={"email": e, "domain": domain, "in_scope": in_scope})
                yield Observation(subject=domain, kind="persona-summary", data={
                    "emails": len(emails),
                    "email_format": _email_format(emails, domain),
                    "in_scope": in_scope,
                    "vault_ref": f"vault:persona ({len(emails)})" if vault_ok else None,
                })
            for h in hosts:
                if h.endswith(domain):
                    yield DomainName(fqdn=h, registrable_domain=registrable_domain(h),
                                     is_scope=h in ctx.scope.hostnames)

    def _harvest(self, ctx, cmd: list[str], domain: str) -> Optional[dict]:
        raw_root = ctx.raw_dir / "harvester"
        raw_root.mkdir(parents=True, exist_ok=True)
        base = raw_root / _safe_name(domain)
        sources = ctx.settings.harvester_sources
        argv = [*cmd, "-d", domain, "-b", sources, "-f", str(base)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as exc:
            ctx.audit.record(module=self.name, action="harvest", outcome="error",
                             target=domain, detail=str(exc)[:200])
            return None

        # Persist stdout/stderr so a "found nothing" run is diagnosable.
        try:
            (raw_root / f"{_safe_name(domain)}.log").write_text(
                f"$ {' '.join(argv)}\nrc={proc.returncode}\n\n"
                f"--- stdout ---\n{proc.stdout or ''}\n--- stderr ---\n{proc.stderr or ''}",
                encoding="utf-8")
        except OSError:
            pass

        data = self._load_json(base, raw_root)
        if data is None:
            # Some versions/sources fail to write JSON; scrape emails from stdout.
            data = {"emails": _EMAIL_RE.findall(proc.stdout or ""), "hosts": []}

        found = len(_emails_for_domain(data.get("emails") or [], domain))
        ctx.audit.record(module=self.name, action="harvest",
                         outcome="ok" if found else "empty",
                         target=domain, detail=f"emails={found} rc={proc.returncode}")
        return data

    @staticmethod
    def _load_json(base: Path, raw_root: Path) -> Optional[dict]:
        """theHarvester JSON filename varies by version; try the obvious names, then
        fall back to the newest *.json produced in the output dir."""
        candidates = [Path(f"{base}.json"), base,
                      *sorted(raw_root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)]
        for cand in candidates:
            if cand.exists() and cand.is_file():
                try:
                    with open(cand, encoding="utf-8") as fh:
                        obj = json.load(fh)
                    if isinstance(obj, dict):
                        return obj
                except (OSError, json.JSONDecodeError):
                    continue
        return None


REGISTRY.register(HarvesterModule())
