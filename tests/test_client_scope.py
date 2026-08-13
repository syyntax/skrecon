"""CLIENT-scope passive recon (spec §3.2): a client root domain is collected
passively but is NEVER active-eligible.

Scenario: scope.txt actively scopes buyexample.com (203.0.113.0/28); the operator
also wants passive intel on the brand domain example.com via client_root_domains.
example.com must be resolved (passive) yet marked out-of-scope so no active module
can target it."""

from __future__ import annotations

from types import SimpleNamespace

from skrecon.config import Settings
from skrecon.model import DomainName, HostIP
from skrecon.modules.dns_enum import DnsModule
from skrecon.scope import parse_scope_text


class FakeResolver:
    _A = {"buyexample.com": ["203.0.113.5"], "example.com": ["93.184.216.34"]}

    def available(self):
        return True

    def resolve(self, name, rtype):
        return self._A.get(name, []) if rtype == "A" else []

    def dnssec_present(self, name):
        return True


def make_ctx():
    scope = parse_scope_text("203.0.113.0/28\nbuyexample.com\n").scope
    return SimpleNamespace(
        scope=scope,
        settings=Settings(client_root_domains=["example.com"]),
        resolver=FakeResolver(),
    )


def test_client_root_domain_is_resolved():
    ctx = make_ctx()
    assert "example.com" in DnsModule()._hosts(ctx)           # passively enumerated
    assert "buyexample.com" in DnsModule()._hosts(ctx)


def test_client_root_domain_is_passive_only():
    records = list(DnsModule().run(make_ctx()))
    domains = {d.fqdn: d for d in records if isinstance(d, DomainName)}
    hosts = {h.ip: h for h in records if isinstance(h, HostIP)}

    # example.com is collected but flagged out-of-scope (passive-only).
    assert domains["example.com"].is_scope is False
    assert hosts["93.184.216.34"].in_scope is False          # -> masscan/nmap skip it

    # buyexample.com (in scope.txt) is in-scope and active-eligible.
    assert domains["buyexample.com"].is_scope is True
    assert hosts["203.0.113.5"].in_scope is True
