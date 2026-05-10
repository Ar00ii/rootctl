"""Parser for smbmap output.

Recognizes the canonical table:

    [+] IP: 10.10.10.10:445  Name: WORKGROUP
        Disk                                                  Permissions     Comment
        ----                                                  -----------     -------
        ADMIN$                                                NO ACCESS       Remote Admin
        C$                                                    NO ACCESS       Default share
        share                                                 READ ONLY
        backup                                                READ, WRITE     Backups

Each row becomes a Finding. The kind reflects the access level so chains can
target the actionable cases without having to filter on `extra`:

    NO ACCESS    → kind="smb-share-none"   (skipped — no value)
    READ ONLY    → kind="smb-share-read"
    READ, WRITE  → kind="smb-share-write"
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


# `[+] IP: 10.10.10.10:445`
_HOST_LINE = re.compile(r"\[\+\]\s*IP:\s*(?P<host>\S+?)(?::(?P<port>\d+))?\s")

# Share row: name (no spaces inside default shares are uppercase + $),
# permission, optional comment. The permission column is always one of the
# fixed strings, so we anchor on it.
_PERM = r"(?P<perm>NO ACCESS|READ ONLY|WRITE ONLY|READ, WRITE)"
# Use horizontal whitespace only ([ \t]) so a row never accidentally crosses
# the newline into the next row when there is no comment column.
_SHARE_ROW = re.compile(
    rf"^[ \t]+(?P<share>[A-Za-z0-9._$\-]+)[ \t]+{_PERM}[ \t]*(?P<comment>[^\n]*?)[ \t]*$",
    re.MULTILINE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    host, port = _host_target(text)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for m in _SHARE_ROW.finditer(text):
        share = m.group("share")
        perm = m.group("perm")
        if perm == "NO ACCESS":
            continue
        kind = _kind_for(perm)
        key = (share, kind)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                tool="smbmap",
                host=host or "unknown",
                port=port,
                protocol="tcp" if port is not None else None,
                service="microsoft-ds",
                kind=kind,
                banner=share,
                extra={
                    "share": share,
                    "permission": perm,
                    "comment": m.group("comment") or "",
                },
            )
        )
    return findings


def _host_target(text: str) -> tuple[str | None, int | None]:
    m = _HOST_LINE.search(text)
    if not m:
        return None, None
    host = m.group("host")
    port_str = m.group("port")
    port = int(port_str) if port_str else 445
    return host, port


def _kind_for(perm: str) -> str:
    if perm == "READ, WRITE":
        return "smb-share-write"
    if perm == "WRITE ONLY":
        return "smb-share-write"
    return "smb-share-read"
