"""Parser for `hashcat --show` and john `--show` output.

Both tools emit one cracked entry per line in the form `HASH:PASSWORD`,
optionally with usernames or extra fields depending on the source format.
We extract the trailing plaintext password and emit a Finding kind=
"cracked-cred" so the credential_reuse chain fires automatically.

Supported shapes:

  hashcat --show:
    $2y$10$abcdef...:supersecret
    5d41402abc4b2a76b9719d911017c592:hello
  john --show:
    admin:rockyou:1000:1000::/home/admin:/bin/bash
    1 password hash cracked, 0 left

For john's user:password lines we treat the first colon-separated field
as the username so the credential_reuse chain has someone to spray.
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


# A line we trust:
#   - starts with non-whitespace, no leading "[" (skips hashcat status lines)
#   - has at least one colon
#   - last field is a non-empty plaintext password (assume <= 64 chars)
#   - first field is at least 4 chars (skip lines like 1:foo which are noise)
_LINE = re.compile(
    r"^(?P<first>[^\s:]{2,})(?:[:\s]+(?P<rest>.+))$",
)


# Hashcat status lines we never want to confuse with cracked outputs.
_NOISE_PREFIXES = (
    "Session", "Status", "Hash.Mode", "Hash.Target", "Time.Started",
    "Time.Estimated", "Kernel.Feature", "Guess.Base", "Guess.Queue",
    "Speed.", "Recovered", "Progress", "Rejected", "Restore.Point",
    "Restore.Sub", "Candidate", "Hardware.Mon", "Started:", "Stopped:",
    "Approaching", "INFO:", "WARNING:",
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "*", "[")):
            continue
        if any(line.startswith(p) for p in _NOISE_PREFIXES):
            continue
        if ":" not in line:
            continue

        # Last colon-separated field is the password; everything before is
        # the hash (and optionally a username at the very front).
        parts = line.split(":")
        if len(parts) < 2:
            continue
        password = parts[-1]
        if not _looks_like_password(password):
            continue

        # If the line has at least three colon-fields we tentatively treat
        # the first as the username — that matches john's output and the
        # `user:hash:rounds:...:password` shape some tools produce.
        username = parts[0] if len(parts) > 2 else ""
        cred_value = f"{username}:{password}" if username and not username.startswith("$") else password

        if cred_value in seen:
            continue
        seen.add(cred_value)
        findings.append(
            Finding(
                tool="hashcat",
                host="local",
                kind="cracked-cred",
                banner=cred_value,
                extra={
                    "password": password,
                    "username": username,
                    "raw": line,
                },
            )
        )
    return findings


def _looks_like_password(s: str) -> bool:
    """Plaintext passwords are 1-64 chars and don't look like a hash field."""
    if not s or len(s) > 64:
        return False
    # Pure-hex strings of length 32/40/64/128 are hash fragments, not pw.
    if re.fullmatch(r"[A-Fa-f0-9]{32}", s):
        return False
    if re.fullmatch(r"[A-Fa-f0-9]{40}", s):
        return False
    if re.fullmatch(r"[A-Fa-f0-9]{64}", s):
        return False
    if re.fullmatch(r"[A-Fa-f0-9]{128}", s):
        return False
    return True
