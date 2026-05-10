"""Parser for pspy output (cron / scheduled-task watcher).

pspy lines look like:

  2024/05/06 12:00:00 CMD: UID=0    PID=12345  /bin/bash /opt/scripts/backup.sh
  2024/05/06 12:01:00 CMD: UID=0    PID=12346  /usr/sbin/CRON -f

We only emit Findings for commands that run as UID=0 — that's where privesc
lives. Each row produces kind="cron-job" with the executed command in
`extra["command"]` so the cron_writable chain (and any future cron-related
chain) can fire generically.
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


_LINE = re.compile(
    r"CMD:\s*UID=(?P<uid>\d+)\s+PID=\d+\s+(?P<command>.+?)$",
    re.MULTILINE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for m in _LINE.finditer(text):
        uid = int(m.group("uid"))
        if uid != 0:
            continue
        command = m.group("command").strip()
        # Skip pspy's own self-reference and the cron daemon itself —
        # neither is actionable.
        if "pspy" in command or command.split()[0].endswith("/CRON"):
            continue
        if command in seen:
            continue
        seen.add(command)

        executable = command.split()[0]
        findings.append(
            Finding(
                tool="pspy",
                host="local",
                kind="cron-job",
                banner=command,
                extra={
                    "command": command,
                    "executable": executable,
                    "uid": "0",
                },
            )
        )
    return findings
