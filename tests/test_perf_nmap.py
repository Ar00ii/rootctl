"""Performance budget for the nmap parser.

Hard rule: 'Parsing nmap output for 100 hosts must complete in under
2 seconds.' This test enforces that contract.
"""

from __future__ import annotations

import time
from pathlib import Path

from rootctl.parsers import nmap as nmap_parser


def _build_100_host_xml() -> str:
    head = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
"""
    tail = """  <runstats><finished time="0" exit="success"/></runstats>
</nmaprun>
"""
    body = []
    for i in range(100):
        body.append(f"""  <host>
    <status state="up"/>
    <address addr="10.10.{i // 256}.{i % 256}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Samba" version="4.6"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Werkzeug httpd" version="2.1.2"/></port>
    </ports>
  </host>""")
    return head + "\n".join(body) + "\n" + tail


def test_100_hosts_under_2_seconds(tmp_path: Path) -> None:
    xml = _build_100_host_xml()
    p = tmp_path / "big.xml"
    p.write_text(xml, encoding="utf-8")

    t0 = time.perf_counter()
    findings = nmap_parser.parse(p)
    elapsed = time.perf_counter() - t0

    assert len(findings) == 500, f"expected 500 findings (100 hosts × 5 ports), got {len(findings)}"
    assert elapsed < 2.0, f"100-host parse took {elapsed:.3f}s, budget is 2.0s"
