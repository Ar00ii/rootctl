"""Matcher performance budget.

The project's hard rule covers nmap parsing for 100 hosts in <2s. The same
budget applies to the full pipeline. With ~60+ chains in the catalog and
hundreds of findings flowing in from a multi-tool engagement, the matcher
must still complete fast.

Synthesizes 500 findings spanning every kind currently emitted, runs the
real chain catalog over them, and asserts the run finishes in under 1
second.
"""

from __future__ import annotations

import time
from pathlib import Path

from rootctl.engine.matcher import load_chains, match
from rootctl.models import Finding


def _build_findings(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    # Mix of services / paths / kinds — exercise every clause type.
    for i in range(50):
        findings.append(
            Finding(
                tool="nmap", host=f"10.0.0.{i}", port=22, protocol="tcp",
                service="ssh", product="OpenSSH", version="9.2p1",
                banner="OpenSSH 9.2p1",
            )
        )
    for i in range(50):
        findings.append(
            Finding(
                tool="nmap", host=f"10.0.1.{i}", port=445, protocol="tcp",
                service="microsoft-ds", product="Samba", version="4.6",
                banner="Samba 4.6",
            )
        )
    for i in range(100):
        findings.append(
            Finding(
                tool="gobuster", host=f"web{i}.local", port=80,
                service="http", path=f"/wp-login.php", status_code=200,
            )
        )
    for kind in ("bcrypt", "kerberos-asrep", "kerberos-tgs", "lm:ntlm", "dcc2",
                  "private-key", "valid-cred", "valid-admin-cred",
                  "ad-user", "ad-asreproast-target", "ad-kerberoastable-target",
                  "suid-binary", "sudo-binary", "windows-privilege",
                  "linux-capability", "smb-share-write", "cron-job"):
        for i in range(15):
            findings.append(
                Finding(
                    tool="extract", host="local", kind=kind,
                    banner=f"sample-{kind}-{i}",
                )
            )
    return findings


def test_matcher_runs_400_findings_under_1s(repo_root: Path, chains_dir: Path) -> None:
    chains = load_chains(chains_dir)
    findings = _build_findings(repo_root)
    assert len(findings) >= 400

    t0 = time.perf_counter()
    matches = match(findings, chains)
    elapsed = time.perf_counter() - t0

    assert matches, "expected at least one chain to fire on the synthetic input"
    assert elapsed < 1.0, f"500-finding match took {elapsed:.3f}s, budget is 1.0s"
