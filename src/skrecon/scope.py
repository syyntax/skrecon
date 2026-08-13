"""scope.txt parsing, normalization, and the ResolvedScope membership authority.

This module is the single source of truth for "what is in scope" (spec §2.2, §3.1).
It does no network I/O. The scope guard (`skrecon.guard`) enforces membership using
`ResolvedScope`; nothing else is permitted to decide scope.

Membership semantics (deliberately conservative — see DESIGN.md §6):
  A hostname is in scope iff
    (1) it exactly matches a listed hostname, OR
    (2) include_subdomains is enabled AND it is a subdomain of a listed domain, OR
    (3) it resolves to an IP inside a listed network (checked via contains_ip at
        resolve time by the caller).
  An IP is in scope iff it falls within a listed network (a single IP is a /32 or /128).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Iterable, Optional, Union

from .errors import ScopeError

Network = Union[IPv4Network, IPv6Network]

DEFAULT_MAX_EXPANDED_HOSTS = 65536

# Hostname per RFC-1123-ish rules (labels 1–63 chars, total ≤253, underscores
# tolerated for service records). Trailing dot allowed and stripped.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*"
    r"\.?$"
)


@dataclass(frozen=True)
class ScopeEntry:
    """One normalized, validated scope.txt line."""
    raw: str
    line_no: int
    kind: str                       # "hostname" | "ip" | "cidr" | "url"
    hostname: Optional[str] = None  # set for hostname/url entries
    network: Optional[str] = None   # set for ip/cidr entries (and url with IP host)


@dataclass
class ResolvedScope:
    """The membership authority derived from scope.txt.

    The scope.txt-listed hostnames and networks are immutable. In addition, IPs
    that a listed HOSTNAME resolves to are registered at run time via
    `add_resolved_ip` and (when `resolve_ips_in_scope` is enabled) are treated as
    in-scope for active modules — so listing `example.com` authorizes scanning the
    IP it resolves to without also having to list that IP. This is deliberately the
    only way the in-scope IP set grows beyond scope.txt, and it is gated by policy.
    """
    hostnames: frozenset[str]
    parent_domains: frozenset[str]           # listed hostnames usable as subdomain parents
    networks: tuple[Network, ...]
    max_expanded_hosts: int = DEFAULT_MAX_EXPANDED_HOSTS
    # Policy: does a listed hostname's resolved IP become active-eligible?
    resolve_ips_in_scope: bool = True
    # IPs a listed hostname resolved to (populated at run time; not from scope.txt).
    _resolved_ips: set[str] = field(default_factory=set)

    # -- membership --------------------------------------------------------- #
    def contains_host(self, name: str, *, include_subdomains: bool = False) -> bool:
        norm = _norm_hostname(name)
        if norm is None:
            return False
        if norm in self.hostnames:
            return True
        if include_subdomains:
            for parent in self.parent_domains:
                if norm == parent or norm.endswith("." + parent):
                    return True
        return False

    def contains_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        # ip_network.__contains__ returns False on version mismatch — safe.
        if any(addr in net for net in self.networks):
            return True
        # An IP a listed hostname resolved to is in-scope only under the policy.
        return self.resolve_ips_in_scope and str(addr) in self._resolved_ips

    def add_resolved_ip(self, ip: str) -> bool:
        """Register an IP that a listed hostname resolved to. Returns True if it was
        newly added. A no-op (returns False) when the policy is disabled or the value
        is not a valid IP. Callers must only pass IPs of IN-SCOPE hostnames — this is
        the sole sanctioned way the active-eligible IP set grows past scope.txt."""
        if not self.resolve_ips_in_scope:
            return False
        try:
            norm = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return False
        if norm in self._resolved_ips:
            return False
        self._resolved_ips.add(norm)
        return True

    def resolved_ip_list(self) -> list[str]:
        """IPs currently in-scope by resolution (for reporting / operator review)."""
        return sorted(self._resolved_ips)

    def contains_network(self, net: Network) -> bool:
        """True only if `net` is fully contained within an in-scope network.

        A range broader than any authorized network is NOT in scope — so an
        active scanner can never be pointed at a wider range than the client
        authorized, even if it overlaps one.
        """
        return any(net.version == sn.version and net.subnet_of(sn) for sn in self.networks)

    def is_empty(self) -> bool:
        return not self.hostnames and not self.networks

    # -- enumeration -------------------------------------------------------- #
    def expanded_hosts(self, limit: Optional[int] = None) -> tuple[list[str], bool]:
        """Expand listed networks into individual host IPs (spec §3.1).

        Returns (hosts, truncated). Membership checks never use this — it only
        bounds per-host target enumeration for tools that want explicit IPs.
        """
        cap = self.max_expanded_hosts if limit is None else limit
        out: list[str] = []
        for net in self.networks:
            hosts_iter: Iterable = net.hosts()
            # /32 and /31 (and v6 equivalents) special-cased by ipaddress to
            # yield their address(es); fall back to network_address otherwise.
            produced = False
            for host in hosts_iter:
                produced = True
                if len(out) >= cap:
                    return out, True
                out.append(str(host))
            if not produced:
                if len(out) >= cap:
                    return out, True
                out.append(str(net.network_address))
        return out, False

    def summary(self) -> dict:
        return {
            "hostnames": sorted(self.hostnames),
            "networks": [str(n) for n in self.networks],
            "host_count": len(self.hostnames),
            "network_count": len(self.networks),
        }


@dataclass
class ScopeParseResult:
    entries: list[ScopeEntry] = field(default_factory=list)
    errors: list[tuple[int, str, str]] = field(default_factory=list)  # (line_no, raw, reason)
    scope: ResolvedScope = field(
        default_factory=lambda: ResolvedScope(frozenset(), frozenset(), ())
    )

    @property
    def ok(self) -> bool:
        return not self.errors


# --------------------------------------------------------------------------- #
# Normalization helpers
# --------------------------------------------------------------------------- #
def _norm_hostname(name: str) -> Optional[str]:
    name = name.strip().rstrip(".").lower()
    if not name or not _HOSTNAME_RE.match(name):
        return None
    return name


def _strip_inline_comment(line: str) -> str:
    idx = line.find("#")
    return line if idx == -1 else line[:idx]


def _split_host_port(token: str) -> tuple[str, Optional[str]]:
    """Split an optional :port. IPv6 literals are only split when bracketed."""
    if token.startswith("["):
        m = re.match(r"^\[(?P<h>[^\]]+)\](?::(?P<p>\d+))?$", token)
        if m:
            return m.group("h"), m.group("p")
    # Only split single-colon tokens so bare IPv6 (many colons) is left intact.
    if token.count(":") == 1:
        host, port = token.rsplit(":", 1)
        if port.isdigit():
            return host, port
    return token, None


def normalize_line(raw: str, line_no: int) -> tuple[Optional[ScopeEntry], Optional[str]]:
    """Normalize one line. Returns (entry, error). Blank/comment -> (None, None)."""
    token = _strip_inline_comment(raw).strip()
    if not token:
        return None, None

    # --- URL form (has a scheme) ---
    if "://" in token:
        from urllib.parse import urlsplit

        try:
            host = urlsplit(token).hostname
        except ValueError:
            return None, "malformed URL"
        if not host:
            return None, "URL has no host"
        # A URL host may itself be an IP literal.
        net = _try_network(host)
        if net is not None:
            return ScopeEntry(raw=token, line_no=line_no, kind="url", network=str(net)), None
        hn = _norm_hostname(host)
        if hn is None:
            return None, f"URL host is not a valid hostname: {host!r}"
        return ScopeEntry(raw=token, line_no=line_no, kind="url", hostname=hn), None

    # --- IP address or CIDR network ---
    net = _try_network(token)
    if net is not None:
        kind = "cidr" if "/" in token else "ip"
        return ScopeEntry(raw=token, line_no=line_no, kind=kind, network=str(net)), None

    # --- hostname (optionally host:port) ---
    host, _port = _split_host_port(token)
    # A bracketed/parsed IPv6 host may resurface here.
    net = _try_network(host)
    if net is not None:
        return ScopeEntry(raw=token, line_no=line_no, kind="ip", network=str(net)), None
    hn = _norm_hostname(host)
    if hn is None:
        return None, "not a valid hostname, IP, or CIDR"
    return ScopeEntry(raw=token, line_no=line_no, kind="hostname", hostname=hn), None


def _try_network(token: str) -> Optional[Network]:
    """Parse a single IP or CIDR into a network (single IP -> /32 or /128)."""
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #
def parse_scope_text(
    text: str,
    *,
    max_expanded_hosts: int = DEFAULT_MAX_EXPANDED_HOSTS,
) -> ScopeParseResult:
    result = ScopeParseResult()
    hostnames: set[str] = set()
    parents: set[str] = set()
    networks: dict[str, Network] = {}   # keyed by str for dedupe

    for i, raw in enumerate(text.splitlines(), start=1):
        entry, err = normalize_line(raw, i)
        if err is not None:
            result.errors.append((i, raw.strip(), err))
            continue
        if entry is None:
            continue
        result.entries.append(entry)
        if entry.hostname:
            hostnames.add(entry.hostname)
            parents.add(entry.hostname)
        if entry.network:
            net = ipaddress.ip_network(entry.network, strict=False)
            networks[str(net)] = net

    result.scope = ResolvedScope(
        hostnames=frozenset(hostnames),
        parent_domains=frozenset(parents),
        networks=tuple(networks.values()),
        max_expanded_hosts=max_expanded_hosts,
    )
    return result


def parse_scope_file(
    path: str | Path,
    *,
    max_expanded_hosts: int = DEFAULT_MAX_EXPANDED_HOSTS,
) -> ScopeParseResult:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScopeError(f"cannot read scope file {p}: {exc}") from exc
    return parse_scope_text(text, max_expanded_hosts=max_expanded_hosts)
