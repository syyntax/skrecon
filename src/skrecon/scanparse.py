"""Pure parsers for active-scanner output (spec §5.1, §5.2).

Kept free of subprocess/network so the parsing is unit-testable against captured
fixtures. The masscan/nmap modules invoke the tools (through the guarded executor)
and feed their output here.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any


def parse_masscan_list(text: str) -> dict[str, list[tuple[int, str]]]:
    """Parse masscan `-oL` (list) output -> {ip: [(port, proto), ...]}.

    Lines look like:  open tcp 80 203.0.113.5 1730000000
    """
    out: dict[str, list[tuple[int, str]]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "open":
            continue
        proto, port_s, ip = parts[1], parts[2], parts[3]
        try:
            port = int(port_s)
        except ValueError:
            continue
        out.setdefault(ip, [])
        if (port, proto) not in out[ip]:
            out[ip].append((port, proto))
    return out


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    """Parse nmap XML (`-oX`) -> [{ip, os, services:[{port,proto,state,name,product,version}]}]."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        services = []
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            svc = port.find("service")
            services.append({
                "port": int(port.get("portid")) if port.get("portid") else None,
                "proto": port.get("protocol", "tcp"),
                "state": state_el.get("state") if state_el is not None else None,
                "name": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })

        os_match = host.find("./os/osmatch")
        hosts.append({
            "ip": ip,
            "os": os_match.get("name") if os_match is not None else None,
            "services": services,
        })
    return hosts
