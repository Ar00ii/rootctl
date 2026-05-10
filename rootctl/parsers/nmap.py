"""Parser for nmap XML output (`nmap -oX`)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from rootctl.models import Finding


def parse(path: str | Path) -> list[Finding]:
    """Parse an nmap XML file and return one Finding per open port.

    Closed and filtered ports are skipped — only ports reported as `open`
    (or `open|filtered`) become findings.
    """
    tree = ET.parse(Path(path))
    root = tree.getroot()
    findings: list[Finding] = []

    for host in root.findall("host"):
        addr = _host_address(host)
        if addr is None:
            continue
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None:
                continue
            state = state_el.get("state", "")
            if not state.startswith("open"):
                continue
            findings.append(_finding_from_port(addr, port_el))

    return findings


def _host_address(host_el: ET.Element) -> str | None:
    """Pick the most useful address for a host element.

    nmap can attach several `<address>` elements per host (IPv4, IPv6, MAC).
    IPv4 wins when present, then IPv6, then MAC as a last resort.
    """
    pref = {"ipv4": 0, "ipv6": 1, "mac": 2}
    best: tuple[int, str] | None = None
    for addr in host_el.findall("address"):
        kind = addr.get("addrtype", "")
        rank = pref.get(kind)
        if rank is None:
            continue
        candidate = addr.get("addr", "")
        if not candidate:
            continue
        if best is None or rank < best[0]:
            best = (rank, candidate)
    return best[1] if best else None


def _finding_from_port(host: str, port_el: ET.Element) -> Finding:
    """Build a Finding from a `<port>` element."""
    port = int(port_el.get("portid", "0") or 0)
    protocol = port_el.get("protocol")

    service_el = port_el.find("service")
    service = product = version = banner = None
    extra: dict[str, str] = {}

    if service_el is not None:
        service = service_el.get("name") or None
        product = service_el.get("product") or None
        version = service_el.get("version") or None
        extrainfo = service_el.get("extrainfo") or ""
        # Reconstruct the human banner the way nmap prints it: "<product> <version> (<extrainfo>)"
        bits = [b for b in (product, version) if b]
        if extrainfo:
            bits.append(f"({extrainfo})")
        if bits:
            banner = " ".join(bits)
        for key in ("ostype", "hostname", "tunnel", "method"):
            val = service_el.get(key)
            if val:
                extra[key] = val

    # Capture script outputs (NSE) into extra so chains can match against them.
    for script in port_el.findall("script"):
        sid = script.get("id") or ""
        out = script.get("output") or ""
        if sid:
            extra[f"script:{sid}"] = out

    return Finding(
        tool="nmap",
        host=host,
        port=port,
        protocol=protocol,
        service=service,
        product=product,
        version=version,
        banner=banner,
        extra=extra,
    )
