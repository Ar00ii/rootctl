"""Parser for `find / -perm -4000` style output.

Accepts both `find ... -ls` (long listing) and bare path output. Each SUID
binary becomes one Finding with kind="suid-binary" and the binary name in
extra so chains can decide whether it's a GTFOBins win.

Recognized line shapes:
  -rwsr-xr-x 1 root root 71M Jan 30  2024 /usr/bin/find
  /usr/bin/find
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


# `-ls`-style line: long perm string (10 chars) ... path. The first character
# of the perm block must be a regular file ('-'), and there must be an 's'
# in the user-execute slot to be SUID.
_LS_LINE = re.compile(
    r"^\s*-[r-][w-][sS][r-][w-][xs-][r-][w-][xt-]\s+\d+\s+\S+\s+\S+\s+"
    r"[\d.,]+[A-Za-z]?\s+\S+\s+\d+\s+\S+\s+(?P<path>/\S+)$",
    re.MULTILINE,
)

# Bare path lines from `find / -perm -4000 -type f`.
_BARE_LINE = re.compile(r"^(?P<path>/(?:usr|bin|sbin|opt|home)/\S+)\s*$", re.MULTILINE)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    seen: set[str] = set()
    findings: list[Finding] = []

    # Prefer `-ls` matches (carry permission info); fall back to bare paths.
    for m in _LS_LINE.finditer(text):
        _push(findings, seen, m.group("path"))
    if not findings:
        for m in _BARE_LINE.finditer(text):
            _push(findings, seen, m.group("path"))
    return findings


def _push(findings: list[Finding], seen: set[str], target: str) -> None:
    if target in seen:
        return
    seen.add(target)
    findings.append(
        Finding(
            tool="find_suid",
            host="local",
            kind="suid-binary",
            banner=target,
            extra={
                "binary": target.rsplit("/", 1)[-1],
                "full_path": target,
            },
        )
    )
