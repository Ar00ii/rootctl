"""Parser for nikto plain text output (`nikto -o report.txt`).

Each `+ /path: description` line becomes a Finding with the same surface
as gobuster (host/port/path/url) so existing web chains fire on nikto
hits without any chain edits. Lines that are pure metadata (start time,
target hostname, server header) are ignored.
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


# Header values from the report block.
_TARGET_IP = re.compile(r"^\+ Target IP:\s+(?P<ip>\S+)", re.MULTILINE)
_TARGET_PORT = re.compile(r"^\+ Target Port:\s+(?P<port>\d+)", re.MULTILINE)
_TARGET_HOSTNAME = re.compile(r"^\+ Target Hostname:\s+(?P<host>\S+)", re.MULTILINE)

# Hits: `+ /path: description.` or `+ OSVDB-NNNN: /path: description.`
_HIT_PATH_FIRST = re.compile(
    r"^\+\s+(?P<path>/[^:\s]\S*?):\s*(?P<desc>.+?)\s*$",
    re.MULTILINE,
)
_HIT_OSVDB = re.compile(
    r"^\+\s+OSVDB-\d+:\s+(?P<path>/[^:\s]\S*?):\s*(?P<desc>.+?)\s*$",
    re.MULTILINE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    host = _first(_TARGET_HOSTNAME, text, "host") or _first(_TARGET_IP, text, "ip") or "unknown"
    port_str = _first(_TARGET_PORT, text, "port")
    port = int(port_str) if port_str else 80

    findings: list[Finding] = []
    seen: set[str] = set()
    for regex in (_HIT_OSVDB, _HIT_PATH_FIRST):
        for m in regex.finditer(text):
            endpoint = m.group("path")
            if endpoint in seen:
                continue
            seen.add(endpoint)
            findings.append(
                Finding(
                    tool="nikto",
                    host=host,
                    port=port,
                    protocol="tcp",
                    service="http",
                    url=f"http://{host}:{port}{endpoint}",
                    path=endpoint,
                    banner=m.group("desc").strip(),
                    extra={"description": m.group("desc").strip()},
                )
            )
    return findings


def _first(regex: re.Pattern[str], text: str, group: str) -> str | None:
    m = regex.search(text)
    return m.group(group) if m else None
