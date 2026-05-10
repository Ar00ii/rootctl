"""Parser for `sudo -l` output.

Each allowed entry under `User <name> may run the following commands` becomes
one Finding. We split on whether the target is a script (ends in .sh / .py /
.pl) or a regular binary so two chains can fire independently:
  - kind = "sudo-script"  → PATH hijacking territory
  - kind = "sudo-binary"  → GTFOBins lookup
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding

# Lines that grant sudo rights, e.g.
#   (root) NOPASSWD: /usr/bin/find
#   (ALL : ALL) NOPASSWD: /usr/bin/vim
#   (root) /usr/bin/less /var/log/syslog
_RULE = re.compile(
    r"^\s*\((?P<runas>[^)]+)\)\s*"
    r"(?:(?P<nopasswd>NOPASSWD|PASSWD|SETENV)\s*:\s*)?"
    r"(?P<command>\S.*)$",
    re.MULTILINE,
)

_SCRIPT_SUFFIXES = (".sh", ".py", ".pl", ".rb")


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for m in _RULE.finditer(text):
        cmd = m.group("command").strip()
        # Take the first token as the executable; anything after is args.
        executable = cmd.split()[0]
        if executable in seen:
            continue
        seen.add(executable)

        kind = "sudo-script" if executable.endswith(_SCRIPT_SUFFIXES) else "sudo-binary"
        binary_name = executable.rsplit("/", 1)[-1]

        findings.append(
            Finding(
                tool="sudo_l",
                host="local",
                kind=kind,
                banner=executable,
                extra={
                    "binary": binary_name,
                    "full_path": executable,
                    "runas": m.group("runas").strip(),
                    "nopasswd": m.group("nopasswd") or "",
                    "args": cmd[len(executable):].strip(),
                },
            )
        )
    return findings
