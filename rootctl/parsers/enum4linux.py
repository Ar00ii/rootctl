"""Parser for enum4linux / enum4linux-ng output.

enum4linux dumps several sections (target info, users, groups, shares,
password policy, OS info). The parser only keeps signals that drive new
chains:

  - Discovered Windows / SMB users → kind="ad-user", banner=username
  - Domain name (when present)     → stashed in extra["domain"] of every user

Shares are intentionally skipped: smbmap output is the canonical source
for share permissions and that parser already exists. Duplicating share
findings here would just inflate the report.
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


# Lines like:  S-1-5-21-...-1000 victim\alice (Local User)
_RID_USER = re.compile(
    r"S-1-5-21-[\d-]+\s+(?P<domain>[^\\]+)\\(?P<user>[^\s]+)\s*\(.*?User",
)

# Lines like:  user:[alice] rid:[0x3e9]   (impacket-style enum4linux-ng)
_BRACKET_USER = re.compile(r"user:\[(?P<user>[^\]]+)\]")

# `Domain Name: VICTIM` or `Workgroup/Domain: VICTIM`
_DOMAIN_LINE = re.compile(r"(?:Workgroup|Domain Name|Domain/Workgroup):\s*(?P<domain>\S+)", re.IGNORECASE)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    domain = _detect_domain(text)
    users: dict[str, str] = {}  # username → domain (best guess)

    for m in _RID_USER.finditer(text):
        u = m.group("user").strip()
        d = m.group("domain").strip()
        # Skip default Windows accounts that are never actionable.
        if u.lower() in {"administrator", "guest", "krbtgt"}:
            continue
        users.setdefault(u, d or domain or "")

    for m in _BRACKET_USER.finditer(text):
        u = m.group("user").strip()
        if u.lower() in {"administrator", "guest", "krbtgt"}:
            continue
        users.setdefault(u, domain or "")

    return [
        Finding(
            tool="enum4linux",
            host="local",
            kind="ad-user",
            banner=u,
            extra={"user": u, "domain": d},
        )
        for u, d in users.items()
    ]


def _detect_domain(text: str) -> str | None:
    m = _DOMAIN_LINE.search(text)
    if not m:
        return None
    candidate = m.group("domain").strip()
    return candidate or None
