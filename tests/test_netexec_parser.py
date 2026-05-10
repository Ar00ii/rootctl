"""Parser-level checks for netexec / crackmapexec output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import netexec as nxc_parser


def test_parses_creds_and_signing(examples_dir: Path) -> None:
    findings = nxc_parser.parse(examples_dir / "test_netexec.txt")
    by_kind: dict[str, list[str]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f.banner)

    # Two valid creds — admin and non-admin — and one no-signing host.
    assert "alice:Sup3rSecret" in by_kind["valid-cred"]
    assert "admin_jdoe:Welcome2024" in by_kind["valid-admin-cred"]
    # The signing:False line for WEB01 produces an smb-no-signing entry.
    assert any(b == "WEB01" for b in by_kind["smb-no-signing"])
    # signing:True for DC01 must NOT generate one.
    assert not any(b == "DC01" for b in by_kind.get("smb-no-signing", []))


def test_failed_logins_are_ignored() -> None:
    text = "SMB  1.2.3.4  445  X  [-] DOM\\bob:wrong STATUS_LOGON_FAILURE\n"
    findings = nxc_parser.parse_text(text)
    assert findings == []
