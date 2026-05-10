"""Parser-level checks for enum4linux output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import enum4linux as e4l_parser


def test_parses_users_and_skips_default_accounts(examples_dir: Path) -> None:
    findings = e4l_parser.parse(examples_dir / "test_enum4linux.txt")
    users = {f.banner for f in findings}
    assert users == {"alice", "bob", "svc_sql", "admin_jdoe"}
    # Default accounts are explicitly skipped.
    assert "Administrator" not in users
    assert "Guest" not in users
    assert "krbtgt" not in users

    for f in findings:
        assert f.kind == "ad-user"
        assert f.extra["domain"] == "HTB"


def test_bracket_form_is_supported() -> None:
    text = (
        "Workgroup/Domain: WIDGET\n"
        "user:[carol] rid:[0x3e9]\n"
        "user:[dave] rid:[0x3ea]\n"
    )
    findings = e4l_parser.parse_text(text)
    users = {f.banner for f in findings}
    assert users == {"carol", "dave"}
