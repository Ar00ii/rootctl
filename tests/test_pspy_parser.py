"""Parser-level checks for pspy output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import pspy as pspy_parser


def test_parse_keeps_only_root_commands(examples_dir: Path) -> None:
    findings = pspy_parser.parse(examples_dir / "test_pspy.txt")
    cmds = {f.extra["command"] for f in findings}

    assert any("backup.sh" in c for c in cmds)
    assert any("cleanup.sh" in c for c in cmds)
    assert any("healthcheck.py" in c for c in cmds)

    # UID=1000 row must be filtered.
    assert not any("whoami" in c for c in cmds)
    # Self-reference (pspy itself) and CRON daemon are skipped.
    assert not any("pspy" in c for c in cmds)
    assert not any(c.split()[0].endswith("CRON") for c in cmds)

    for f in findings:
        assert f.kind == "cron-job"
        assert f.extra["uid"] == "0"
