"""The safety enforcement layer (spec §9): scope guard, authorization gate,
blackout gate, and the guarded subprocess executor.

This lives in the core so no module can bypass it. Modules never open sockets or
spawn scanners directly — they are handed a `ScopeGuard`, an `ActiveGate`, and a
`GuardedExecutor`, and those are the *only* routes to a target. Every target is
validated against `ResolvedScope` before any packet is sent; out-of-scope targets
are refused and logged, never contacted.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlsplit

from .audit import AuditLog
from .engagement import EngagementMeta
from .errors import BlackoutError, NotAuthorizedError, OutOfScopeError
from .model import Phase, utcnow
from .scope import ResolvedScope


def _extract_target_host(target: str) -> str:
    """Reduce a target string to the bare host/IP the guard should check."""
    t = target.strip()
    if "://" in t:
        host = urlsplit(t).hostname
        return host or t
    if t.startswith("["):
        m = re.match(r"^\[(?P<h>[^\]]+)\](?::\d+)?$", t)
        if m:
            return m.group("h")
    try:
        ipaddress.ip_address(t)
        return t                      # bare IP literal
    except ValueError:
        pass
    if t.count(":") == 1:             # host:port (not IPv6 — that has many colons)
        host, port = t.rsplit(":", 1)
        if port.isdigit():
            return host
    return t


# --------------------------------------------------------------------------- #
# Scope guard
# --------------------------------------------------------------------------- #
@dataclass
class ScopeGuard:
    scope: ResolvedScope
    audit: AuditLog
    include_subdomains: bool = False

    def is_in_scope(self, target: str, *, resolved_ips: Optional[list[str]] = None) -> bool:
        host = _extract_target_host(target)

        # 1) IP or CIDR range (masscan/nmap targets). A single address is a /32 or
        #    /128; a wider prefix is a range that must be fully within scope.
        try:
            netw = ipaddress.ip_network(host, strict=False)
        except ValueError:
            netw = None
        if netw is not None:
            if netw.prefixlen < netw.max_prefixlen:
                return self.scope.contains_network(netw)
            return self.scope.contains_ip(str(netw.network_address))

        # 2) hostname (exact, or subdomain when enabled)
        if self.scope.contains_host(host, include_subdomains=self.include_subdomains):
            return True
        # 3) a host that resolves to an in-scope IP is eligible
        if resolved_ips:
            return any(self.scope.contains_ip(ip) for ip in resolved_ips)
        return False

    def check_target(
        self,
        target: str,
        *,
        module: str,
        phase: Phase,
        resolved_ips: Optional[list[str]] = None,
    ) -> str:
        """Return the target if in scope; otherwise log + raise OutOfScopeError."""
        if self.is_in_scope(target, resolved_ips=resolved_ips):
            self.audit.allowed(module=module, target=target, phase=phase)
            return target
        self.audit.refused(module=module, target=target, reason="not in resolved scope", phase=phase)
        raise OutOfScopeError(target)

    def filter_targets(
        self,
        targets: list[str],
        *,
        module: str,
        phase: Phase,
        resolved_ips_map: Optional[dict[str, list[str]]] = None,
    ) -> tuple[list[str], list[str]]:
        """Split targets into (allowed, refused). Non-raising; logs every decision."""
        allowed: list[str] = []
        refused: list[str] = []
        rmap = resolved_ips_map or {}
        for t in targets:
            if self.is_in_scope(t, resolved_ips=rmap.get(t)):
                allowed.append(t)
                self.audit.allowed(module=module, target=t, phase=phase)
            else:
                refused.append(t)
                self.audit.refused(module=module, target=t, reason="not in resolved scope", phase=phase)
        return allowed, refused


# --------------------------------------------------------------------------- #
# Authorization + blackout gate for the ACTIVE phase
# --------------------------------------------------------------------------- #
@dataclass
class ActiveGate:
    authorized: bool
    audit: AuditLog
    engagement: Optional[EngagementMeta] = None
    clock: Callable[[], datetime] = utcnow

    def ensure_active_allowed(self) -> None:
        """Raise if the active phase must not proceed right now."""
        if not self.authorized:
            self.audit.record(module="core", action="auth-gate", outcome="refused",
                              phase=Phase.ACTIVE, detail="authorization not confirmed")
            raise NotAuthorizedError(
                "active phase requires explicit authorization confirmation "
                "(--i-am-authorized) plus recorded engagement metadata"
            )
        now = self.clock()
        if self.engagement is not None:
            window = self.engagement.is_blackout(now)
            if window is not None:
                self.audit.record(module="core", action="blackout-gate", outcome="refused",
                                  phase=Phase.ACTIVE, detail=window.label())
                raise BlackoutError(window.label())
        self.audit.record(module="core", action="active-gate", outcome="allowed", phase=Phase.ACTIVE)


# --------------------------------------------------------------------------- #
# Guarded executor
# --------------------------------------------------------------------------- #
@dataclass
class ExecResult:
    tool: str
    argv: list[str]
    planned: bool = False
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    refused_targets: list[str] = field(default_factory=list)
    allowed_targets: list[str] = field(default_factory=list)


@dataclass
class GuardedExecutor:
    """The only sanctioned way to run an external scanner against targets.

    Guarantees: (1) the active gate is satisfied before any active tool runs;
    (2) every target is scope-validated and out-of-scope ones are dropped + logged;
    (3) in dry-run nothing executes — the exact command is planned and audited.
    """
    guard: ScopeGuard
    gate: ActiveGate
    audit: AuditLog
    dry_run: bool = False

    def run(
        self,
        tool: str,
        args: list[str],
        targets: list[str],
        *,
        module: str,
        phase: Phase,
        resolved_ips_map: Optional[dict[str, list[str]]] = None,
        timeout: Optional[float] = None,
    ) -> ExecResult:
        # Scope is always validated — even a dry-run plan shows what is refused.
        allowed, refused = self.guard.filter_targets(
            targets, module=module, phase=phase, resolved_ips_map=resolved_ips_map
        )
        argv = [tool, *args, *allowed]
        cmd_str = " ".join(argv)

        will_execute = (not self.dry_run) and bool(allowed)

        # The gate blocks *execution* of active work, not planning. Dry-run may
        # preview an active plan without authorization; nothing is sent.
        if phase is Phase.ACTIVE and will_execute:
            self.gate.ensure_active_allowed()

        if not will_execute:
            outcome = "planned" if self.dry_run else "skipped-no-targets"
            self.audit.record(
                module=module, action="exec", outcome=outcome, phase=phase,
                command=cmd_str, detail=f"allowed={len(allowed)} refused={len(refused)}",
            )
            return ExecResult(tool=tool, argv=argv, planned=True,
                              refused_targets=refused, allowed_targets=allowed)

        self.audit.record(module=module, action="exec", outcome="started", phase=phase,
                          command=cmd_str, detail=f"allowed={len(allowed)} refused={len(refused)}")
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            self.audit.record(module=module, action="exec", outcome="error", phase=phase,
                              command=cmd_str, detail=str(exc))
            raise
        self.audit.record(module=module, action="exec", outcome="finished", phase=phase,
                          command=cmd_str, detail=f"rc={proc.returncode}")
        return ExecResult(
            tool=tool, argv=argv, planned=False, returncode=proc.returncode,
            stdout=proc.stdout, stderr=proc.stderr,
            refused_targets=refused, allowed_targets=allowed,
        )


_WEB_UA = "skrecon/0.1 (+authorized-recon)"
_MAX_BODY = 512 * 1024   # cap response body reads


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow redirects — a redirect could bounce us to an out-of-scope
    host, and for header/TLS analysis we want the actual response anyway."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


@dataclass
class HttpResult:
    url: str
    status: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)   # kept separate (dict collapses dups)
    body: str = ""
    planned: bool = False
    error: Optional[str] = None


@dataclass
class TlsResult:
    host: str
    port: int
    protocols: list[str] = field(default_factory=list)   # supported versions
    cert: Optional[dict] = None
    planned: bool = False
    error: Optional[str] = None


@dataclass
class GuardedHttp:
    """Guarded entry point for target-directed HTTP/TLS (active web modules).

    Every request is scope-validated and (for real runs) passes the active gate
    before any connection. Redirects are never auto-followed. Passive third-party
    API calls do NOT go through here — they use the unguarded client since they
    never touch client targets.
    """
    guard: ScopeGuard
    audit: AuditLog
    gate: Optional[ActiveGate] = None
    dry_run: bool = False

    def check_url(
        self,
        url: str,
        *,
        module: str,
        phase: Phase = Phase.ACTIVE,
        resolved_ips: Optional[list[str]] = None,
    ) -> str:
        return self.guard.check_target(url, module=module, phase=phase, resolved_ips=resolved_ips)

    def get(
        self,
        url: str,
        *,
        module: str,
        resolved_ips: Optional[list[str]] = None,
        timeout: float = 15.0,
    ) -> HttpResult:
        """Scope-checked, gated, non-redirect-following GET."""
        self.guard.check_target(url, module=module, phase=Phase.ACTIVE, resolved_ips=resolved_ips)
        if self.dry_run:
            self.audit.record(module=module, action="http-get", outcome="planned",
                              phase=Phase.ACTIVE, target=url)
            return HttpResult(url=url, planned=True)
        if self.gate is not None:
            self.gate.ensure_active_allowed()

        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, headers={"User-Agent": _WEB_UA}, method="GET")
        result = HttpResult(url=url)
        try:
            with opener.open(req, timeout=timeout) as resp:
                result.status = resp.status
                result.headers = {k: v for k, v in resp.headers.items()}
                result.set_cookies = resp.headers.get_all("Set-Cookie") or []
                result.body = resp.read(_MAX_BODY).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            # A 3xx/4xx still carries headers worth analyzing.
            result.status = exc.code
            result.headers = {k: v for k, v in (exc.headers or {}).items()}
            result.set_cookies = (exc.headers.get_all("Set-Cookie") if exc.headers else []) or []
            result.error = f"http:{exc.code}"
        except Exception as exc:  # noqa: BLE001 — network errors must not crash a run
            result.error = f"error:{type(exc).__name__}"
        self.audit.record(module=module, action="http-get",
                          outcome=str(result.status or result.error),
                          phase=Phase.ACTIVE, target=url)
        return result

    def probe_tls(
        self,
        host: str,
        port: int,
        *,
        module: str,
        resolved_ips: Optional[list[str]] = None,
        timeout: float = 10.0,
    ) -> TlsResult:
        """Scope-checked, gated TLS probe: which protocol versions are accepted and
        the presented certificate (parsed with cryptography when available)."""
        self.guard.check_target(host, module=module, phase=Phase.ACTIVE, resolved_ips=resolved_ips)
        if self.dry_run:
            self.audit.record(module=module, action="tls-probe", outcome="planned",
                              phase=Phase.ACTIVE, target=f"{host}:{port}")
            return TlsResult(host=host, port=port, planned=True)
        if self.gate is not None:
            self.gate.ensure_active_allowed()

        result = TlsResult(host=host, port=port)
        versions = [
            ("TLSv1", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
        for name, ver in versions:
            if self._tls_accepts(host, port, ver, timeout):
                result.protocols.append(name)
        result.cert = self._peer_cert(host, port, timeout)
        self.audit.record(module=module, action="tls-probe", outcome="ok",
                          phase=Phase.ACTIVE, target=f"{host}:{port}",
                          detail=f"protocols={','.join(result.protocols)}")
        return result

    @staticmethod
    def _tls_accepts(host: str, port: int, version, timeout: float) -> bool:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except ValueError:
            return False   # this Python/OpenSSL can't negotiate that version
        try:
            with socket.create_connection((host, port), timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _peer_cert(host: str, port: int, timeout: float) -> Optional[dict]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
        except Exception:  # noqa: BLE001
            return None
        if not der:
            return None
        try:
            from cryptography import x509
        except Exception:  # noqa: BLE001 — cert parsing is optional
            return None
        try:
            cert = x509.load_der_x509_certificate(der)
            sans: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = [n.value for n in ext.value]
            except Exception:  # noqa: BLE001
                pass
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            issuer = cert.issuer.rfc4514_string()
            subject = cert.subject.rfc4514_string()
            return {
                "not_after": not_after.isoformat(),
                "issuer": issuer,
                "subject": subject,
                "self_signed": issuer == subject,
                "sans": sans,
            }
        except Exception:  # noqa: BLE001
            return None
