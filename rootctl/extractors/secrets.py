"""Secret token detection.

Patterns target high-confidence cloud / SaaS / VCS credentials that, if leaked
in a tool output or config dump, are immediately actionable: AWS access keys,
Google service-account JSON fragments, GitHub tokens, Slack tokens, generic
PEM private keys, and `.env`-style assignments to obvious secret variables.

Each match is conservative — short or low-entropy strings are filtered out so
the noise floor on a 50 MB scrape stays low.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rootctl.models import CriticalExtract, Severity


@dataclass(frozen=True)
class _Sig:
    name: str
    pattern: re.Pattern[str]
    severity: Severity = Severity.HIGH
    next_command: str | None = None


_SIGNATURES: tuple[_Sig, ...] = (
    # AWS access key id — fixed AKIA / ASIA prefix, 20 chars total.
    _Sig(
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "aws sts get-caller-identity   # confirm the key is live before anything else",
    ),
    # AWS secret access key when explicitly labelled. The bare 40-char form is
    # too generic to flag without a context anchor.
    _Sig(
        "aws-secret-access-key",
        re.compile(
            r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        Severity.CRITICAL,
    ),
    # GitHub personal access tokens (classic + fine-grained) and app tokens.
    _Sig(
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b"),
        Severity.CRITICAL,
        "curl -H 'Authorization: token <TOKEN>' https://api.github.com/user",
    ),
    _Sig(
        "github-fine-grained",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        Severity.CRITICAL,
    ),
    # Slack bot/user/app tokens.
    _Sig(
        "slack-token",
        re.compile(r"\bxox[abopr]-[A-Za-z0-9-]{10,}\b"),
        Severity.HIGH,
        "curl -H 'Authorization: Bearer <TOKEN>' https://slack.com/api/auth.test",
    ),
    # Google API keys.
    _Sig(
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        Severity.HIGH,
    ),
    # Stripe live secret keys are unambiguously catastrophic.
    _Sig(
        "stripe-live",
        re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
        Severity.CRITICAL,
    ),
    # AWS S3 bucket references — a bucket name on its own is recon, not a
    # leaked secret, but it pivots straight into a public-read / writable
    # check, so we surface it. Three URL forms, all unambiguous:
    #   s3://bucket-name/key
    #   bucket.s3.amazonaws.com / bucket.s3-website-...amazonaws.com
    #   s3.amazonaws.com/bucket
    _Sig(
        "aws-s3-bucket",
        re.compile(
            r"(?:s3://[a-z0-9][a-z0-9.\-]{2,62}|"
            r"\b[a-z0-9][a-z0-9.\-]{2,62}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|"
            r"\bs3\.amazonaws\.com/[a-z0-9][a-z0-9.\-]{2,62})"
        ),
        Severity.MEDIUM,
        "aws s3 ls s3://BUCKET --no-sign-request   # check public read",
    ),
    # Kubernetes service-account tokens — JWT-shaped but with the kube
    # signing-issuer claim. Treat as a CRITICAL secret because they grant
    # API access from anywhere the API server is reachable.
    _Sig(
        "kubernetes-token",
        re.compile(
            r"\beyJhbGciOi[A-Za-z0-9_\-]+\.eyJpc3Mi[A-Za-z0-9_\-=]+(?:kubernetes|serviceaccount)[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-]+"
        ),
        Severity.CRITICAL,
    ),
    # RFC 1918 private addresses surfaced from a target's responses are
    # SSRF / pivot candidates. Severity LOW — informational only, but
    # downstream chains can target the discovered subnet.
    _Sig(
        "internal-ipv4",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
        Severity.LOW,
    ),
    # Plain email addresses are valuable as username material for
    # password sprays / kerbrute / wpscan / hydra.
    _Sig(
        "email-address",
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        Severity.INFO,
    ),
    # Group Policy Preferences cpassword — Microsoft published the AES key
    # in MSDN, so anyone who can read SYSVOL can decrypt it. Format:
    # cpassword="<base64>" inside Groups.xml / Services.xml / ScheduledTasks.xml.
    _Sig(
        "gpp-cpassword",
        re.compile(r'cpassword="(?P<value>[A-Za-z0-9+/=]{16,})"'),
        Severity.CRITICAL,
        "gpp-decrypt '<base64>'   # Kali ships gpp-decrypt — instant plaintext",
    ),
    # PEM private keys — match the header line; the body is pulled out below.
    _Sig(
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        Severity.CRITICAL,
        "ssh-keygen -y -f <keyfile>   # extract the public key, then test against $VICTIMA",
    ),
    # JWT secret env var — flag the assignment (the JWT itself is handled by hashes.py).
    _Sig(
        "jwt-secret-env",
        re.compile(r"(?i)(?:jwt_secret|jwt_signing_key)\s*[:=]\s*['\"]?([!-~]{8,})['\"]?"),
        Severity.HIGH,
    ),
    # Generic .env-style secret assignment. We only fire on variable names that
    # are unambiguously credentials and require a value of length >= 8.
    _Sig(
        "env-secret",
        re.compile(
            r"(?im)^\s*(?:[A-Z_]*(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY))\s*"
            r"[:=]\s*['\"]?([!-~]{8,})['\"]?\s*$"
        ),
        Severity.HIGH,
    ),
)


def extract(text: str, source: str = "raw") -> list[CriticalExtract]:
    seen: set[tuple[str, str]] = set()
    out: list[CriticalExtract] = []

    for sig in _SIGNATURES:
        for m in sig.pattern.finditer(text):
            value = m.group(0)
            key = (sig.name, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                CriticalExtract(
                    kind=sig.name,
                    value=value,
                    source=source,
                    next_command=sig.next_command,
                    severity=sig.severity,
                )
            )

    return out
