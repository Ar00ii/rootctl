"""Parser for `whoami /priv` output.

Each row in the privilege table becomes a Finding with kind="windows-privilege"
and banner=privilege name. Only privileges in the `Enabled` state matter for
exploitation, so disabled ones are skipped.

Example input:
  PRIVILEGES INFORMATION
  ----------------------

  Privilege Name                Description                    State
  ============================= ============================== ========
  SeShutdownPrivilege           Shut down the system           Disabled
  SeImpersonatePrivilege        Impersonate a client           Enabled
  SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding

# Match a privilege row. Three columns separated by 2+ spaces; the privilege
# name always starts with "Se" and ends with "Privilege".
_PRIV_LINE = re.compile(
    r"^(Se[A-Za-z]+Privilege)\s{2,}.+?\s{2,}(Enabled|Disabled)\s*$",
    re.MULTILINE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for m in _PRIV_LINE.finditer(text):
        name, state = m.group(1), m.group(2)
        if state != "Enabled":
            continue
        if name in seen:
            continue
        seen.add(name)
        findings.append(
            Finding(
                tool="whoami_priv",
                host="local",
                kind="windows-privilege",
                banner=name,
                extra={"privilege": name, "state": state},
            )
        )
    return findings
