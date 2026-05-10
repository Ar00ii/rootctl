"""Parser for LinPEAS output.

LinPEAS dumps several thousand lines of mixed enumeration with ANSI color
escapes, ASCII-art section headers, and cross-references to GTFOBins. This
parser keeps the surface narrow on purpose:

  - SUID binaries  → kind="suid-binary"   (fires `suid_gtfobins` chain)
  - Capabilities    → kind="linux-capability"  (fires `linux_capability_abuse`)

Anything else (kernel exploits, world-writable crons, sudo tokens, ssh
keys) flows through the extractors transparently — the extractor pipeline
already runs over the file's text in `analyze`, so a leaked id_rsa or a
detected kerberos ticket is picked up without a special branch here.

The parser is robust against ANSI escapes: the input is stripped first.
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


# Standard 7-bit + 8-bit CSI / OSC sequences. Strips colour codes and most
# cursor-positioning noise that LinPEAS spits out.
_ANSI_RE = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)")

# SUID listing line. Tolerates trailing annotations like `---> GTFOBins`
# that LinPEAS appends — we don't anchor to end-of-line.
_SUID_LINE = re.compile(
    r"^[ \t]*-[r-][w-][sS][r-][w-][xs-][r-][w-][xt-]\s+\d+\s+\S+\s+\S+\s+"
    r"[\d.,]+[A-Za-z]?\s+\S+\s+\d+\s+\S+\s+(?P<path>/\S+)",
    re.MULTILINE,
)

# Capability line: `/usr/bin/python3.10 = cap_setuid+ep`.
_CAP_LINE = re.compile(
    r"^[ \t]*(?P<path>/\S+)\s*=\s*(?P<cap>cap_[a-z_,]+)\+(?P<flags>[a-z]+)",
    re.MULTILINE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    clean = _ANSI_RE.sub("", text)
    findings: list[Finding] = []

    suid_seen: set[str] = set()
    for m in _SUID_LINE.finditer(clean):
        target = m.group("path")
        if target in suid_seen:
            continue
        suid_seen.add(target)
        findings.append(
            Finding(
                tool="linpeas",
                host="local",
                kind="suid-binary",
                banner=target,
                extra={
                    "binary": target.rsplit("/", 1)[-1],
                    "full_path": target,
                },
            )
        )

    cap_seen: set[tuple[str, str]] = set()
    for m in _CAP_LINE.finditer(clean):
        target = m.group("path")
        cap = m.group("cap")
        flags = m.group("flags")
        key = (target, cap)
        if key in cap_seen:
            continue
        cap_seen.add(key)
        findings.append(
            Finding(
                tool="linpeas",
                host="local",
                kind="linux-capability",
                banner=cap,
                extra={
                    "binary": target.rsplit("/", 1)[-1],
                    "full_path": target,
                    "capability": cap,
                    "flags": flags,
                },
            )
        )

    return findings
