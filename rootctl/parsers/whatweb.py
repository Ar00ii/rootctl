"""Parser for whatweb plain text output.

A whatweb line looks like:

  http://target.htb [200] Apache[2.4.41], HTML5, HTTPServer[Apache/2.4.41
  (Ubuntu)], IP[10.10.10.10], MetaGenerator[WordPress 6.0], PoweredBy[WordPress],
  WordPress[6.0]

Each comma-separated tag becomes a Finding with kind="web-tech",
banner=<tag-name>. Tags that name a CMS or framework feed the existing
web chains naturally — `WordPress` matches the wordpress chain via
banner_pattern, `phpMyAdmin` lights up downstream chains as more land.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from rootctl.models import Finding


# Top-level line:
#   http://target.htb [200] Apache[2.4.41], HTML5, ...
_HEADER_LINE = re.compile(
    r"^(?P<url>https?://\S+)\s+\[(?P<status>\d{3})\]\s+(?P<tags>.*)$",
    re.MULTILINE,
)

# Strip square-bracketed value annotations from a tag name. `Apache[2.4.41]`
# → `Apache`. `WordPress[6.0]` → `WordPress`. We keep the version in `extra`.
_TAG_VALUE = re.compile(r"^(?P<name>[A-Za-z0-9_\-]+)(?:\[(?P<value>[^\]]*)\])?$")


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for hdr in _HEADER_LINE.finditer(text):
        url = hdr.group("url")
        status = int(hdr.group("status"))
        tags = hdr.group("tags")
        parsed = urlparse(url)
        host = parsed.hostname or "unknown"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        for tag in _split_tags(tags):
            m = _TAG_VALUE.match(tag.strip())
            if not m:
                continue
            name = m.group("name")
            value = m.group("value")
            key = (url, name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    tool="whatweb",
                    host=host,
                    port=port,
                    protocol="tcp",
                    service=parsed.scheme or "http",
                    url=url,
                    path=parsed.path or "/",
                    status_code=status,
                    kind="web-tech",
                    banner=name if value is None else f"{name}[{value}]",
                    extra={"tech": name, "value": value or ""},
                )
            )
    return findings


def _split_tags(text: str) -> list[str]:
    """Split on commas but ignore commas inside [...] values."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    for c in text:
        if c == "[":
            depth += 1
            buf.append(c)
        elif c == "]":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
    if buf:
        out.append("".join(buf).strip())
    return [t for t in out if t]
