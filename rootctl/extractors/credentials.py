"""Plaintext credential detection.

Targets the most common patterns observed in pentest output and config dumps:
  - `user:password` style lines (FTP wordlists, hydra hits, dumped tables)
  - `username=...; password=...` query/form snippets
  - `mysql -u <u> -p<p>` and similar one-liners
  - HTTP Basic auth URLs (`http://user:pass@host/`)
"""

from __future__ import annotations

import re

from rootctl.models import CriticalExtract, Severity


# A user:pass line is matched conservatively:
#   - user is 1..40 chars of word/dash/dot/at
#   - pass is 4..64 chars of printable non-space
# Lines that look like timestamps or URLs are filtered out.
_USERPASS_LINE = re.compile(
    r"(?m)^\s*([A-Za-z0-9._@\-]{1,40}):([!-~]{4,64})\s*$"
)

# `Found user/pass: ...` style lines from hydra / netexec / smbclient outputs.
_FOUND_LINE = re.compile(
    r"\[\d+\]\[(?:ssh|ftp|smb|http(?:s)?|telnet|mysql|mssql|rdp)\][^\n]*"
    r"login:\s*([^\s]+)\s+password:\s*(\S+)",
    re.IGNORECASE,
)

# HTTP Basic auth URL pattern. Excludes empty creds and obvious schemas.
_BASIC_URL = re.compile(
    r"https?://([A-Za-z0-9._\-]+):([^@\s/]+)@([A-Za-z0-9.\-]+)"
)

# Inline DB connection strings: `mysql -u root -ptoor`, `psql -h ... -U user`.
_MYSQL_INLINE = re.compile(
    r"mysql\s+(?:-h\s*\S+\s+)?-u\s*([A-Za-z0-9._\-]+)\s+-p([!-~]{1,64})"
)

# wp-config.php style lines.
_WPCONFIG = re.compile(
    r"define\(\s*'(DB_USER|DB_PASSWORD)'\s*,\s*'([^']+)'\s*\)",
)

# HTTP Authorization headers, captured from request dumps / Burp logs.
# Bearer tokens are usually JWTs (handled by hashes.py) but Basic auth
# is base64(user:pass) and worth surfacing as a credential.
_AUTH_BASIC = re.compile(
    r"Authorization:\s*Basic\s+(?P<b64>[A-Za-z0-9+/=]{8,})"
)
_AUTH_BEARER = re.compile(
    r"Authorization:\s*Bearer\s+(?P<token>[A-Za-z0-9._\-]{20,})"
)

# DSN-style URLs that carry credentials in-band:
#   postgres://user:pass@host:5432/db
#   mysql://user:pass@host:3306/
#   mongodb://user:pass@host:27017/
#   redis://:pass@host:6379/
#   amqp://user:pass@host:5672/
# Captures: scheme, user (may be empty for redis), pass, host, optional port.
_DSN_URL = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mongodb|redis|amqp|ampqs)://"
    r"(?P<user>[A-Za-z0-9._\-]*):(?P<pass>[^@\s/]{1,128})@"
    r"(?P<host>[A-Za-z0-9.\-]+)(?::(?P<port>\d+))?"
)

# Lines that shouldn't be flagged as `user:pass`: likely false positives like
# protocol prefixes, ANSI escape garbage, base64 padding, etc.
_NOISE_USERS = frozenset({
    "http", "https", "ftp", "ssh", "rdp", "smb", "ldap", "mysql", "psql",
    "file", "tcp", "udp", "v6", "ipv4", "ipv6",
})


def extract(text: str, source: str = "raw") -> list[CriticalExtract]:
    out: list[CriticalExtract] = []
    seen: set[tuple[str, str, str]] = set()

    def push(kind: str, value: str, severity: Severity = Severity.HIGH) -> None:
        key = (kind, value, source)
        if key in seen:
            return
        seen.add(key)
        out.append(
            CriticalExtract(
                kind=kind,
                value=value,
                source=source,
                next_command=_next_command(kind, value),
                severity=severity,
            )
        )

    for m in _USERPASS_LINE.finditer(text):
        user, pwd = m.group(1), m.group(2)
        if user.lower() in _NOISE_USERS:
            continue
        push("user:pass", f"{user}:{pwd}")

    for m in _FOUND_LINE.finditer(text):
        push("hydra-cred", f"{m.group(1)}:{m.group(2)}", Severity.CRITICAL)

    for m in _BASIC_URL.finditer(text):
        push("basic-auth-url", f"{m.group(1)}:{m.group(2)}@{m.group(3)}")

    for m in _MYSQL_INLINE.finditer(text):
        push("mysql-cli", f"{m.group(1)}:{m.group(2)}")

    for m in _WPCONFIG.finditer(text):
        push("wp-config", f"{m.group(1)}={m.group(2)}")

    for m in _AUTH_BASIC.finditer(text):
        import base64 as _b64
        try:
            decoded = _b64.b64decode(m.group("b64"), validate=True).decode("utf-8", errors="replace")
        except Exception:
            decoded = ""
        if ":" in decoded and len(decoded) <= 128:
            push("basic-auth-header", decoded, Severity.CRITICAL)

    for m in _AUTH_BEARER.finditer(text):
        push("bearer-token", m.group("token"), Severity.HIGH)

    for m in _DSN_URL.finditer(text):
        scheme = m.group("scheme")
        user = m.group("user") or ""
        pwd = m.group("pass")
        host = m.group("host")
        port = m.group("port") or ""
        value = f"{scheme}://{user}:{pwd}@{host}" + (f":{port}" if port else "")
        push("dsn-url", value, Severity.CRITICAL)

    return out


def _next_command(kind: str, value: str) -> str | None:
    if kind in ("user:pass", "hydra-cred", "mysql-cli"):
        user, _, pwd = value.partition(":")
        return (
            f"# Try the credential against common services:\n"
            f"ssh {user}@$VICTIMA           # SSH (port 22)\n"
            f"smbclient -L //$VICTIMA -U {user}%{pwd}\n"
            f"evil-winrm -i $VICTIMA -u {user} -p '{pwd}'\n"
            f"netexec smb $VICTIMA -u {user} -p '{pwd}'"
        )
    if kind == "basic-auth-url":
        return f"curl -v {value.split(':')[0]}:{value.split(':',1)[1].split('@')[0]}@{value.split('@')[1]}"
    return None
