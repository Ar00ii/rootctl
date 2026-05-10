"""Parser-level checks for the nmap XML reader."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import nmap as nmap_parser


def test_parse_werkzeug_example(examples_dir: Path) -> None:
    findings = nmap_parser.parse(examples_dir / "test_werkzeug.xml")

    assert len(findings) == 2
    by_port = {f.port: f for f in findings}
    assert set(by_port) == {22, 8080}

    ssh = by_port[22]
    assert ssh.host == "10.10.11.42"
    assert ssh.tool == "nmap"
    assert ssh.protocol == "tcp"
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version is not None and ssh.version.startswith("9.2p1")

    web = by_port[8080]
    assert web.service == "http"
    assert web.product == "Werkzeug httpd"
    assert web.version == "2.1.2"
    assert web.banner is not None
    assert "Werkzeug" in web.banner
    assert "Python 3.10.6" in web.banner
    assert web.extra.get("script:http-title", "").startswith("Did not follow")


def test_parser_skips_closed_ports(tmp_path: Path) -> None:
    xml = """<?xml version="1.0"?>
<nmaprun><host>
  <address addr="1.2.3.4" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22"><state state="closed"/></port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx" version="1.24"/>
    </port>
  </ports>
</host></nmaprun>"""
    p = tmp_path / "scan.xml"
    p.write_text(xml, encoding="utf-8")

    findings = nmap_parser.parse(p)
    assert [f.port for f in findings] == [80]
