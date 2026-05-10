"""Parser for `gobuster dir` plain output.

Accepts both:
  - Full output that starts with the `[+] Url: ...` banner block
  - Bare result lines (`/path  (Status: NNN) [Size: N]`), which is what
    `gobuster dir -q` and the typical `tee result.txt` output looks like

Each non-redirect-noise result becomes one Finding with:
  tool         = "gobuster"
  host, port   = parsed from the banner URL when present
  service      = "http" or "https" depending on the banner scheme
  path         = the discovered path (e.g. "/wp-login.php")
  status_code  = HTTP status from "(Status: NNN)"
  url          = host + port + path when host is known
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from rootctl.models import Finding

# Banner line in `gobuster dir` output:
#   [+] Url:                     http://10.10.10.10:8080
_BANNER_URL = re.compile(r"^\[\+\]\s*Url:\s*(\S+)\s*$", re.MULTILINE)

# Result line. Examples:
#   /admin                (Status: 301) [Size: 0] [--> /admin/]
#   /index.php            (Status: 200) [Size: 4321]
# The path may contain dots, dashes, slashes, query, encoded chars.
_RESULT_LINE = re.compile(
    r"^\s*(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d{3})\)",
    re.MULTILINE,
)


def parse(path: str | Path) -> list[Finding]:
    """Parse a gobuster output file and return one Finding per result row."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    """Parse gobuster output already loaded in memory."""
    host, port, service = _banner_target(text)

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for m in _RESULT_LINE.finditer(text):
        endpoint = m.group("path")
        status = int(m.group("status"))
        key = (endpoint, str(status))
        if key in seen:
            continue
        seen.add(key)

        url = None
        if host is not None:
            scheme = service or "http"
            authority = host if port is None else f"{host}:{port}"
            url = f"{scheme}://{authority}{endpoint}"

        findings.append(
            Finding(
                tool="gobuster",
                host=host or "unknown",
                port=port,
                protocol="tcp" if port is not None else None,
                service=service,
                url=url,
                path=endpoint,
                status_code=status,
            )
        )
    return findings


def _banner_target(text: str) -> tuple[str | None, int | None, str | None]:
    """Pull host/port/scheme out of the `[+] Url: ...` banner if present."""
    m = _BANNER_URL.search(text)
    if not m:
        return None, None, None
    parsed = urlparse(m.group(1))
    if not parsed.hostname:
        return None, None, None
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.hostname, port, parsed.scheme or "http"
