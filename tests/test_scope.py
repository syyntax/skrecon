"""Parser + normalizer + ResolvedScope membership (spec §3.1, §10)."""

from __future__ import annotations

from skrecon.scope import parse_scope_text

SCOPE = """
# Stormkeep sample scope
example.com
https://app.example.com/login       # URL -> host stripped
sub.example.com:8443                 # host:port
203.0.113.0/28                       # CIDR
198.51.100.7                         # single IPv4
2001:db8::/48                        # IPv6 CIDR
example.com                          # duplicate, deduped

not a hostname!!                     # malformed
http://                              # URL with no host
"""


def parse():
    return parse_scope_text(SCOPE, max_expanded_hosts=1000)


def test_classification_and_normalization():
    r = parse()
    kinds = {(e.hostname or e.network): e.kind for e in r.entries}
    assert kinds["example.com"] == "hostname"
    assert kinds["app.example.com"] == "url"
    assert kinds["sub.example.com"] == "hostname"          # port stripped
    assert kinds["203.0.113.0/28"] == "cidr"
    assert kinds["198.51.100.7/32"] == "ip"                # single IP -> /32
    assert kinds["2001:db8::/48"] == "cidr"


def test_comments_and_blanks_ignored():
    r = parse()
    # No entry should be a comment or blank line.
    assert all(e.hostname or e.network for e in r.entries)


def test_malformed_reported_not_dropped():
    r = parse()
    joined = " | ".join(f"{raw} :: {reason}" for _, raw, reason in r.errors)
    assert "not a hostname" in joined                       # bad hostname surfaced
    assert any("URL" in reason for _, _, reason in r.errors)  # http:// with no host
    assert not r.ok


def test_dedupe():
    r = parse()
    hosts = [e.hostname for e in r.entries if e.hostname == "example.com"]
    # Two "example.com" lines parse, but the resolved scope set is deduped.
    assert hosts.count("example.com") == 2
    assert sum(1 for h in r.scope.hostnames if h == "example.com") == 1


def test_ip_membership():
    s = parse().scope
    assert s.contains_ip("203.0.113.5")       # inside /28
    assert not s.contains_ip("203.0.113.20")  # outside /28 (.0-.15)
    assert s.contains_ip("198.51.100.7")      # single IP
    assert not s.contains_ip("198.51.100.8")
    assert s.contains_ip("2001:db8::1")        # inside v6 /48
    assert not s.contains_ip("2001:dead::1")


def test_ip_version_mismatch_is_safe():
    s = parse().scope
    # An IPv6 query against IPv4-only networks must not raise, just return False.
    assert not s.contains_ip("::1")
    # And a bogus string is False, never an exception.
    assert not s.contains_ip("garbage")


def test_host_membership_exact_and_subdomains():
    s = parse().scope
    assert s.contains_host("example.com")
    assert s.contains_host("EXAMPLE.COM")               # case-insensitive
    assert s.contains_host("example.com.")              # trailing dot
    assert not s.contains_host("api.example.com")       # subdomains OFF by default
    assert s.contains_host("api.example.com", include_subdomains=True)
    assert not s.contains_host("notexample.com", include_subdomains=True)
    assert not s.contains_host("example.com.evil.com", include_subdomains=True)


def test_cidr_expansion_and_cap():
    s = parse().scope
    hosts, truncated = s.expanded_hosts(limit=5)
    assert len(hosts) == 5
    assert truncated is True
    # A single IP expands to exactly itself.
    single = parse_scope_text("198.51.100.7\n").scope
    hosts2, trunc2 = single.expanded_hosts(limit=1000)
    assert hosts2 == ["198.51.100.7"] and trunc2 is False


def test_empty_scope():
    r = parse_scope_text("# only comments\n\n")
    assert r.scope.is_empty()
    assert r.ok  # comments/blanks are not errors
