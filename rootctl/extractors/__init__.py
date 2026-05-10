"""Pattern-based extractors that pull hashes, credentials, and secrets out of raw text.

Each extractor module exposes `extract(text: str, source: str) -> list[CriticalExtract]`.
"""

from rootctl.models import CriticalExtract, Finding

# Module label used as `tool` for synthetic Findings derived from extracts.
# Hash-family kinds get tool="hashes", credential kinds get tool="credentials",
# everything else gets tool="secrets". The classification is intentionally
# conservative — when in doubt, we err on the side of "secrets".
_HASH_KINDS = frozenset({
    "bcrypt", "phpass", "phpass-h", "md5crypt", "sha256crypt", "sha512crypt",
    "argon2", "kerberos-asrep", "kerberos-tgs", "net-ntlmv2", "jwt",
    "mysql4.1+", "lm:ntlm", "sha512", "sha256", "sha1", "md5_or_ntlm", "dcc2",
})
_CRED_KINDS = frozenset({
    "user:pass", "hydra-cred", "basic-auth-url", "mysql-cli", "wp-config",
    "dsn-url", "basic-auth-header", "bearer-token",
})


def extract_all(text: str, source: str = "raw") -> list[CriticalExtract]:
    """Run every extractor over `text` and return the merged list."""
    # Import lazily so the package imports cleanly even before all extractors land.
    from rootctl.extractors.hashes import extract as extract_hashes
    from rootctl.extractors.credentials import extract as extract_credentials
    from rootctl.extractors.secrets import extract as extract_secrets

    return [
        *extract_hashes(text, source=source),
        *extract_credentials(text, source=source),
        *extract_secrets(text, source=source),
    ]


def extracts_to_findings(extracts: list[CriticalExtract]) -> list[Finding]:
    """Convert each extract into a synthetic Finding so chains can match on it.

    The Finding's `kind` mirrors the extract kind (e.g. "bcrypt"); `banner`
    holds the raw value, which lets banner_pattern triggers also fire if a
    chain prefers regex matching over kind equality.
    """
    out: list[Finding] = []
    for e in extracts:
        if e.kind in _HASH_KINDS:
            tool = "hashes"
        elif e.kind in _CRED_KINDS:
            tool = "credentials"
        else:
            tool = "secrets"
        out.append(
            Finding(
                tool=tool,
                host="extract",
                kind=e.kind,
                banner=e.value,
                extra={"source": e.source},
            )
        )
    return out
