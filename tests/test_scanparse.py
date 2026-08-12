"""Active-scanner output parsers (spec §5.1, §5.2) — pure, no subprocess."""

from __future__ import annotations

from skrecon.scanparse import parse_masscan_list, parse_nmap_xml

MASSCAN = """#masscan
open tcp 80 203.0.113.5 1730000000
open tcp 443 203.0.113.5 1730000000
open tcp 22 203.0.113.6 1730000000
open tcp 80 203.0.113.5 1730000000
# end
"""

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="203.0.113.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="95"/></os>
  </host>
</nmaprun>
"""


def test_parse_masscan_list():
    out = parse_masscan_list(MASSCAN)
    assert set(out) == {"203.0.113.5", "203.0.113.6"}
    assert (80, "tcp") in out["203.0.113.5"]
    assert (443, "tcp") in out["203.0.113.5"]
    assert out["203.0.113.5"].count((80, "tcp")) == 1     # deduped
    assert out["203.0.113.6"] == [(22, "tcp")]


def test_parse_masscan_list_ignores_noise():
    assert parse_masscan_list("garbage\n# comment\nclosed tcp 1 1.2.3.4 0\n") == {}


def test_parse_nmap_xml():
    hosts = parse_nmap_xml(NMAP_XML)
    assert len(hosts) == 1
    h = hosts[0]
    assert h["ip"] == "203.0.113.5"
    assert h["os"] == "Linux 5.X"
    ports = {s["port"]: s for s in h["services"]}
    assert ports[80]["product"] == "nginx" and ports[80]["version"] == "1.18.0"
    assert ports[22]["name"] == "ssh"


def test_parse_nmap_xml_malformed_is_empty():
    assert parse_nmap_xml("<not-valid") == []
