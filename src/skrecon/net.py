"""Passive network helpers: a DNS resolver and a third-party HTTP client.

These are for PASSIVE recon only. They never touch client-owned active targets —
they query recursive DNS resolvers and public/OSINT HTTP endpoints — so they do not
route through the scope guard (which governs active, target-directed traffic). Both
are cached, audit-logged, and degrade gracefully when their backing library or the
network is unavailable (spec §2.7).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from .audit import AuditLog
from .cache import Cache


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
@dataclass
class PassiveResolver:
    """dnspython-backed resolver. `available()` is False if dnspython is absent,
    letting modules skip cleanly rather than crash."""
    audit: AuditLog
    cache: Cache
    timeout: float = 5.0
    nameservers: list[str] = field(default_factory=list)

    def available(self) -> bool:
        try:
            import dns.resolver  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False

    def _resolver(self):
        import dns.resolver
        r = dns.resolver.Resolver(configure=True)
        r.timeout = self.timeout
        r.lifetime = self.timeout
        if self.nameservers:
            r.nameservers = list(self.nameservers)
        return r

    def resolve(self, name: str, rtype: str) -> list[str]:
        """Return record values as strings; [] for NXDOMAIN / no answer / error."""
        key = f"dns:{rtype}:{name.lower()}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached

        import dns.resolver
        values: list[str] = []
        outcome = "ok"
        try:
            answer = self._resolver().resolve(name, rtype, raise_on_no_answer=False)
            if answer.rrset is not None:
                for rdata in answer:
                    if rtype == "MX":
                        values.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
                    else:
                        values.append(rdata.to_text().strip('"'))
        except dns.resolver.NXDOMAIN:
            outcome = "nxdomain"
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            outcome = "no-answer"
        except Exception as exc:  # noqa: BLE001 — timeouts, network, etc.
            outcome = f"error:{type(exc).__name__}"
        self.audit.record(module="dns", action="resolve", outcome=outcome,
                          target=name, detail=f"{rtype} -> {len(values)} record(s)")
        self.cache.set(key, values)
        return values

    def resolve_ips(self, name: str) -> list[str]:
        return self.resolve(name, "A") + self.resolve(name, "AAAA")

    def resolve_chain(self, name: str) -> tuple[list[str], list[str]]:
        """Follow CNAME(s) to terminal A/AAAA. Returns (cnames, ips)."""
        cnames = self.resolve(name, "CNAME")
        ips = self.resolve_ips(name)
        return [c.rstrip(".") for c in cnames], ips

    def reverse(self, ip: str) -> list[str]:
        key = f"dns:PTR:{ip}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        import dns.resolver
        import dns.reversename
        values: list[str] = []
        outcome = "ok"
        try:
            rev = dns.reversename.from_address(ip)
            answer = self._resolver().resolve(rev, "PTR", raise_on_no_answer=False)
            if answer.rrset is not None:
                values = [r.to_text().rstrip(".") for r in answer]
        except dns.resolver.NXDOMAIN:
            outcome = "nxdomain"
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            outcome = "no-answer"
        except Exception as exc:  # noqa: BLE001
            outcome = f"error:{type(exc).__name__}"
        self.audit.record(module="reverse-dns", action="ptr", outcome=outcome,
                          target=ip, detail=f"{len(values)} name(s)")
        self.cache.set(key, values)
        return values

    def dnssec_present(self, name: str) -> bool:
        """Presence check (not full validation): a published DNSKEY at the zone."""
        return bool(self.resolve(name, "DNSKEY"))


# --------------------------------------------------------------------------- #
# HTTP (third-party OSINT APIs, e.g. RDAP)
# --------------------------------------------------------------------------- #
@dataclass
class PassiveHttp:
    audit: AuditLog
    cache: Cache
    timeout: float = 15.0
    user_agent: str = "skrecon/0.1 (+authorized-recon)"

    def get_json(
        self,
        url: str,
        *,
        accept: str = "application/json",
        module: str = "http",
        cache_key: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        no_cache: bool = False,
    ) -> tuple[int, Optional[Any]]:
        """GET a URL and parse JSON. Returns (status, data|None). Never raises for
        network/HTTP errors — returns a status and None so callers degrade.

        `no_cache` bypasses the disk cache entirely — mandatory for PII responses
        (e.g. DeHashed), which must never be written to the plaintext cache.
        """
        key = cache_key or f"http:{url}"
        if not no_cache:
            cached = self.cache.get(key)
            if cached is not None:
                return 200, cached

        req_headers = {"User-Agent": self.user_agent, "Accept": accept}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers)
        status = 0
        data: Optional[Any] = None
        outcome = "ok"
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            status = exc.code
            outcome = f"http:{exc.code}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            outcome = f"error:{type(exc).__name__}"
        self.audit.record(module=module, action="http-get", outcome=outcome,
                          target=url, detail=f"status={status}")
        if data is not None and not no_cache:
            self.cache.set(key, data)
        return status, data
