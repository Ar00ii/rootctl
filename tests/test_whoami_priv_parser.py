"""Parser-level checks for `whoami /priv` output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import whoami_priv as wp_parser


def test_parse_only_returns_enabled_privileges(examples_dir: Path) -> None:
    findings = wp_parser.parse(examples_dir / "test_whoami_priv.txt")
    names = {f.banner for f in findings}
    assert names == {
        "SeChangeNotifyPrivilege",
        "SeImpersonatePrivilege",
        "SeCreateGlobalPrivilege",
        "SeBackupPrivilege",
    }
    # Disabled ones must NOT show up.
    assert "SeAuditPrivilege" not in names

    for f in findings:
        assert f.kind == "windows-privilege"
        assert f.extra["state"] == "Enabled"
