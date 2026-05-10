"""Parser for netexec / crackmapexec stdout.

netexec (formerly CrackMapExec / nxc) is the standard mass-auth tool for
SMB/MSSQL/WinRM/LDAP. The plain output looks like:

  SMB  10.10.10.10  445  DC01  [*] Windows Server 2019 ... (signing:True)
  SMB  10.10.10.10  445  DC01  [+] HTB.LOCAL\\alice:Sup3rSecret (Pwn3d!)
  SMB  10.10.10.10  445  DC01  [+] HTB.LOCAL\\bob:hunter2
  SMB  10.10.10.10  445  DC01  [-] HTB.LOCAL\\charlie:wrong STATUS_LOGON_FAILURE

What we care about:

  - `[+] domain\\user:secret (Pwn3d!)` → kind=valid-admin-cred (CRITICAL)
  - `[+] domain\\user:secret`          → kind=valid-cred (HIGH)
  - SMB rows containing `signing:False` → kind=smb-no-signing (relay-able)
"""

from __future__ import annotations

import re
from pathlib import Path

from rootctl.models import Finding


_VALID_LINE = re.compile(
    r"\[\+\]\s+(?:(?P<domain>[^\\/\s]+)[\\/])?(?P<user>[^\s:]+):(?P<secret>\S+?)"
    r"(?:\s+\((?P<flag>Pwn3d!)\))?\s*$",
    re.MULTILINE,
)

_SIGNING_LINE = re.compile(
    r"^\s*(?P<proto>SMB|MSSQL)\s+(?P<host>\S+)\s+\d+\s+(?P<name>\S+)\s+\[\*\][^\n]*signing:False",
    re.MULTILINE | re.IGNORECASE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen_creds: set[tuple[str, str]] = set()
    for m in _VALID_LINE.finditer(text):
        user = m.group("user")
        secret = m.group("secret")
        domain = m.group("domain") or ""
        # Skip the chain banner shown by some tools when no auth was provided.
        if user.lower() in {"anonymous", "guest"} and not secret:
            continue
        key = (user, secret)
        if key in seen_creds:
            continue
        seen_creds.add(key)
        is_admin = m.group("flag") == "Pwn3d!"
        findings.append(
            Finding(
                tool="netexec",
                host="local",
                kind="valid-admin-cred" if is_admin else "valid-cred",
                banner=f"{user}:{secret}",
                extra={
                    "user": user,
                    "secret": secret,
                    "domain": domain,
                    "admin": "true" if is_admin else "false",
                },
            )
        )

    seen_signing: set[str] = set()
    for m in _SIGNING_LINE.finditer(text):
        target = m.group("host")
        if target in seen_signing:
            continue
        seen_signing.add(target)
        findings.append(
            Finding(
                tool="netexec",
                host=target,
                kind="smb-no-signing",
                banner=m.group("name"),
                extra={"hostname": m.group("name"), "host": target},
            )
        )
    return findings
