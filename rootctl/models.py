"""Core data types shared by parsers, the matching engine, and the reporter.

Every data structure here is a frozen dataclass: matches and findings flow
through the pipeline as immutable values, which keeps the engine deterministic
and easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Severity assigned to a finding or chain match.

    The string base class makes the enum trivially serializable to YAML/JSON
    and lets it sort lexicographically in display tables when needed. The
    canonical priority order is enforced by `Severity.rank`.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Lower rank = higher priority. Used for sort keys."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


@dataclass(frozen=True)
class Finding:
    """A normalized fact extracted from a tool output.

    Parsers emit `Finding` instances. The matching engine uses the fields here
    to evaluate chain triggers. All optional fields default to None so that
    parsers can fill in only what their tool actually exposes.
    """

    tool: str                       # source tool, e.g. "nmap", "gobuster"
    host: str                       # IP or hostname the finding belongs to
    port: int | None = None
    protocol: str | None = None     # "tcp" / "udp"
    service: str | None = None      # nmap service name, e.g. "http"
    product: str | None = None      # banner product, e.g. "Werkzeug httpd"
    version: str | None = None      # banner version, e.g. "2.1.2"
    banner: str | None = None       # full raw banner if available
    # Web-content fields, populated by HTTP enumerators (gobuster, ffuf, ...).
    # Service-level parsers leave them None.
    url: str | None = None          # full URL, e.g. "http://10.10.10.10:8080/wp-login.php"
    path: str | None = None         # path component, e.g. "/wp-login.php"
    status_code: int | None = None  # HTTP status returned for the path
    # Generic kind tag, populated by extractors and other typed sources
    # (e.g. "bcrypt", "kerberos-asrep", "private-key", "SeImpersonatePrivilege").
    kind: str | None = None
    extra: dict[str, str] = field(default_factory=dict)  # tool-specific blob

    @property
    def label(self) -> str:
        """Compact human label, used in reports and logs."""
        # Synthetic findings emitted by extractors_to_findings have host="extract"
        # and carry the real source in extra["source"]. Render them as
        # "<kind> extracted from <source>" so chain panels are not just "extract".
        if self.host == "extract" and self.kind:
            source = self.extra.get("source") if self.extra else None
            tail = f" from {source}" if source else ""
            return f"{self.kind} extracted{tail}"
        bits = [self.host]
        if self.port is not None:
            proto = self.protocol or "tcp"
            bits.append(f"{self.port}/{proto}")
        if self.service:
            bits.append(self.service)
        if self.product:
            v = f" {self.version}" if self.version else ""
            bits.append(f"({self.product}{v})")
        if self.path:
            status = f" [{self.status_code}]" if self.status_code is not None else ""
            bits.append(f"{self.path}{status}")
        return " ".join(bits)


@dataclass(frozen=True)
class ChainStep:
    """A single step in an attack chain."""

    id: int
    title: str
    command: str | None = None      # exact command, copied verbatim from source
    notes: str | None = None        # context, gotchas, expected output


@dataclass(frozen=True)
class CommonError:
    """An error observed in the wild and its proven solution.

    Captured as-is from the source notes — never invented. This is the section
    that differentiates rootctl from generic cheat-sheets.
    """

    error: str
    solution: str


@dataclass(frozen=True)
class ChainMatch:
    """An attack chain that matched against one or more findings.

    `findings` lists the findings that triggered the match (typically one,
    sometimes several when an `any_of` trigger fires from multiple sources).
    """

    chain_id: str
    title: str
    severity: Severity
    tags: tuple[str, ...]
    description: str
    steps: tuple[ChainStep, ...]
    common_errors: tuple[CommonError, ...]
    references: tuple[str, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class CriticalExtract:
    """A high-value artifact pulled from raw output (hash, credential, secret).

    Reserved for the extractor pipeline (phase 3). `kind` is the family of
    artifact ("ntlm", "md5", "jwt", "aws_key", ...). `next_command` is the
    suggested follow-up (e.g. the exact hashcat command with the right -m).
    """

    kind: str
    value: str
    source: str                     # where it came from (file/line, finding label)
    next_command: str | None = None
    severity: Severity = Severity.HIGH
