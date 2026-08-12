"""Finding catalog (spec §7 findings model).

A stable, centralized registry of finding types. Each entry fixes the title,
default severity, and a remediation recommendation so findings stay consistent
across runs and make run-diffs meaningful. Modules create findings via
`make_finding(finding_type, ...)` rather than hand-building them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .model import Finding, Phase, Severity


@dataclass(frozen=True)
class FindingSpec:
    finding_type: str
    title: str                      # may contain {placeholders} filled from title_ctx
    severity: Severity
    remediation: str


def _spec(ft: str, title: str, sev: Severity, rem: str) -> tuple[str, FindingSpec]:
    return ft, FindingSpec(ft, title, sev, rem)


CATALOG: dict[str, FindingSpec] = dict(
    [
        # --- DNS / DNSSEC ---
        _spec("dns.dnssec.missing", "DNSSEC not enabled for {domain}", Severity.LOW,
              "Enable DNSSEC signing at the zone and publish a DS record at the registrar."),
        _spec("dns.no_resolution", "{domain} does not resolve", Severity.INFO,
              "Confirm the host is expected to be live; stale scope entries add noise."),

        # --- WHOIS / RDAP ---
        _spec("domain.expired", "Domain {domain} has EXPIRED (on {date})", Severity.HIGH,
              "Renew the domain immediately to prevent hijacking and mail/service loss."),
        _spec("domain.expiring_soon", "Domain {domain} expires soon (on {date})", Severity.MEDIUM,
              "Renew before expiry and enable auto-renew to avoid takeover risk."),
        _spec("domain.no_registrar_lock", "Domain {domain} lacks a registrar transfer lock", Severity.LOW,
              "Set clientTransferProhibited (registrar lock) to prevent unauthorized transfers."),
        _spec("domain.privacy_disabled", "WHOIS privacy not enabled for {domain}", Severity.INFO,
              "Consider registrar privacy/proxy to reduce exposure of registrant PII."),

        # --- Mail security posture ---
        _spec("mail.spf.missing", "No SPF record for {domain}", Severity.MEDIUM,
              "Publish an SPF TXT record ending in -all listing only authorized senders."),
        _spec("mail.spf.softfail", "SPF for {domain} uses ~all (softfail), not -all", Severity.LOW,
              "Tighten SPF to -all once authorized senders are confirmed."),
        _spec("mail.spf.passall", "SPF for {domain} is dangerously permissive (+all)", Severity.HIGH,
              "Replace +all with -all; +all authorizes the world to send as your domain."),
        _spec("mail.spf.lookups_high", "SPF for {domain} exceeds 10 DNS lookups", Severity.LOW,
              "Flatten includes; SPF over 10 lookups fails validation (permerror)."),
        _spec("mail.dmarc.missing", "No DMARC record for {domain}", Severity.MEDIUM,
              "Publish a DMARC record; start at p=none with rua, then move to quarantine/reject."),
        _spec("mail.dmarc.policy_none", "DMARC for {domain} is p=none (monitor only)", Severity.LOW,
              "Advance the DMARC policy to quarantine or reject after monitoring."),
        _spec("mail.dmarc.no_rua", "DMARC for {domain} has no aggregate reporting (rua)", Severity.INFO,
              "Add a rua= address to receive aggregate reports and observe sources."),
        _spec("mail.dkim.none_found", "No DKIM selectors found for {domain}", Severity.INFO,
              "Publish DKIM keys and sign outbound mail; verify common selectors are present."),
        _spec("mail.mta_sts.missing", "No MTA-STS policy for {domain}", Severity.INFO,
              "Publish an MTA-STS record and policy to enforce TLS for inbound SMTP."),
        _spec("mail.tls_rpt.missing", "No TLS-RPT record for {domain}", Severity.INFO,
              "Publish a TLS-RPT record to receive SMTP TLS failure reports."),
        _spec("mail.bimi.missing", "No BIMI record for {domain}", Severity.INFO,
              "Optional: publish BIMI once DMARC is at enforcement to display brand logos."),

        # --- Typosquatting / brand abuse ---
        _spec("typosquat.registered", "Look-alike domain registered: {candidate}", Severity.LOW,
              "Monitor or defensively register; watch for phishing/abuse."),
        _spec("typosquat.mx_present", "Look-alike {candidate} has live MX (possible phishing)", Severity.MEDIUM,
              "Investigate; a look-alike with mail records is a phishing-capable asset."),
    ]
)


def make_finding(
    finding_type: str,
    *,
    affected: list[str],
    evidence: list[str],
    source_module: str,
    phase: Phase = Phase.PASSIVE,
    title_ctx: Optional[dict[str, object]] = None,
) -> Finding:
    spec = CATALOG.get(finding_type)
    if spec is None:
        raise KeyError(f"unknown finding_type: {finding_type!r} (add it to findings.CATALOG)")
    title = spec.title.format(**(title_ctx or {}))
    return Finding(
        finding_type=finding_type,
        title=title,
        severity=spec.severity,
        source_module=source_module,
        affected=list(affected),
        evidence=list(evidence),
        remediation=spec.remediation,
        phase=phase,
    )
