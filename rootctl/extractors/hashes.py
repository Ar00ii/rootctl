"""Hash detection.

Each `_Sig` describes one hash family: a regex that recognizes it, the human
label, the hashcat mode (`-m`) and john format (`--format=`) needed to crack
it, and the resulting severity.

Detection is conservative: when in doubt we err on the side of NOT emitting a
match, because false positives drown out the real artifacts in long outputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from rootctl.models import CriticalExtract, Severity


@dataclass(frozen=True)
class _Sig:
    name: str               # human label (e.g. "NTLM")
    pattern: re.Pattern[str]
    hashcat_mode: int | None
    john_format: str | None
    severity: Severity = Severity.HIGH


# Order matters: more specific patterns come first so a generic 32-hex match
# does not swallow an NTLM or MySQL-pre4 hash.
_SIGNATURES: tuple[_Sig, ...] = (
    # MCF / structured first
    _Sig(
        "bcrypt",
        re.compile(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}"),
        3200, "bcrypt",
        Severity.HIGH,
    ),
    _Sig(
        "phpass",
        re.compile(r"\$P\$[./A-Za-z0-9]{31}"),
        400, "phpass",
        Severity.HIGH,
    ),
    _Sig(
        "phpass-h",
        re.compile(r"\$H\$[./A-Za-z0-9]{31}"),
        400, "phpass",
        Severity.HIGH,
    ),
    _Sig(
        "md5crypt",
        re.compile(r"\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}"),
        500, "md5crypt",
        Severity.HIGH,
    ),
    _Sig(
        "sha256crypt",
        re.compile(r"\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}"),
        7400, "sha256crypt",
        Severity.HIGH,
    ),
    _Sig(
        "sha512crypt",
        re.compile(r"\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}"),
        1800, "sha512crypt",
        Severity.HIGH,
    ),
    _Sig(
        "argon2",
        re.compile(r"\$argon2(?:i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"),
        None, "argon2",
        Severity.HIGH,
    ),
    # Kerberos
    _Sig(
        "kerberos-asrep",
        re.compile(r"\$krb5asrep\$23\$[^\s:]+:[A-Fa-f0-9]+\$[A-Fa-f0-9]+"),
        18200, "krb5asrep",
        Severity.CRITICAL,
    ),
    _Sig(
        "kerberos-tgs",
        re.compile(r"\$krb5tgs\$23\$\*[^*]+\*\$[A-Fa-f0-9]+\$[A-Fa-f0-9]+"),
        13100, "krb5tgs",
        Severity.CRITICAL,
    ),
    # Domain Cached Credentials v2 (Windows DCC2 / mscash2). Format produced
    # by impacket-secretsdump for cached domain logons:
    #   $DCC2$10240#username#hex32
    _Sig(
        "dcc2",
        re.compile(r"\$DCC2\$\d+#[^#\s]+#[A-Fa-f0-9]{32}"),
        2100, "mscash2",
        Severity.HIGH,
    ),
    # Net-NTLMv2 (Responder/MITM captures): user::domain:challenge:hmac:blob
    _Sig(
        "net-ntlmv2",
        re.compile(r"[^\s:]+::[^\s:]+:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]+"),
        5600, "netntlmv2",
        Severity.CRITICAL,
    ),
    # JWT — three base64url segments separated by dots
    _Sig(
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        16500, "jwt",
        Severity.HIGH,
    ),
    # MySQL >= 4.1 hash starts with '*' followed by 40 hex chars
    _Sig(
        "mysql4.1+",
        re.compile(r"\*[A-Fa-f0-9]{40}\b"),
        300, "mysql-sha1",
        Severity.HIGH,
    ),
    # NTLM appears as either 32-hex alone or 'LM:NT' pair. Pair form first.
    _Sig(
        "lm:ntlm",
        re.compile(r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b"),
        1000, "nt",
        Severity.CRITICAL,
    ),
    # Plain hex digests — bound by word boundaries to avoid mid-string matches.
    _Sig(
        "sha512",
        re.compile(r"\b[A-Fa-f0-9]{128}\b"),
        1700, "raw-sha512",
        Severity.MEDIUM,
    ),
    _Sig(
        "sha256",
        re.compile(r"\b[A-Fa-f0-9]{64}\b"),
        1400, "raw-sha256",
        Severity.MEDIUM,
    ),
    _Sig(
        "sha1",
        re.compile(r"\b[A-Fa-f0-9]{40}\b"),
        100, "raw-sha1",
        Severity.LOW,
    ),
    _Sig(
        "md5_or_ntlm",
        # 32 hex chars — could be MD5 OR NTLM. We surface both candidate next-commands.
        re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        0, "raw-md5",
        Severity.MEDIUM,
    ),
)


def extract(text: str, source: str = "raw") -> list[CriticalExtract]:
    """Return every hash candidate found in `text`."""
    seen: set[tuple[str, str]] = set()
    out: list[CriticalExtract] = []

    for sig in _SIGNATURES:
        for m in sig.pattern.finditer(text):
            value = m.group(0)
            key = (sig.name, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(_to_extract(sig, value, source))

    return out


def extract_iter(text: str, source: str = "raw") -> Iterable[CriticalExtract]:
    """Iterator variant for very large inputs."""
    yield from extract(text, source)


def _to_extract(sig: _Sig, value: str, source: str) -> CriticalExtract:
    return CriticalExtract(
        kind=sig.name,
        value=value,
        source=source,
        next_command=_suggest_command(sig, value),
        severity=sig.severity,
    )


def _suggest_command(sig: _Sig, value: str) -> str | None:
    """Build an exact next command for the most common cracking workflow."""
    if sig.name == "md5_or_ntlm":
        # Both candidates are useful — surface them on one line.
        return (
            "hashcat -m 0  -a 0 hash.txt /usr/share/wordlists/rockyou.txt   "
            "# if MD5\n"
            "hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt # if NTLM"
        )
    if sig.hashcat_mode is not None:
        return (
            f"hashcat -m {sig.hashcat_mode} -a 0 hash.txt "
            "/usr/share/wordlists/rockyou.txt"
        )
    if sig.john_format:
        return f"john --format={sig.john_format} --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
    return None
