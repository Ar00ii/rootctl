"""Parser for feroxbuster default text output.

Lines look like:
    200      GET       42l      512w     8721c http://10.10.10.10/index.html
    301      GET        7l       20w      314c http://10.10.10.10/admin => http://10.10.10.10/admin/

Each row becomes a Finding with the same shape as the gobuster parser.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from rootctl.models import Finding


_LINE = re.compile(
    r"^\s*(?P<status>\d{3})\s+\w+\s+\d+\w?\s+\d+\w?\s+\d+\w?\s+(?P<url>https?://\S+)",
    re.MULTILINE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for m in _LINE.finditer(text):
        url = m.group("url")
        status = int(m.group("status"))
        key = (url, status)
        if key in seen:
            continue
        seen.add(key)
        parsed = urlparse(url)
        host = parsed.hostname or "unknown"
        port = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80
        findings.append(
            Finding(
                tool="feroxbuster",
                host=host,
                port=port,
                protocol="tcp" if port is not None else None,
                service=parsed.scheme or "http",
                url=url,
                path=parsed.path or "/",
                status_code=status,
            )
        )
    return findings
