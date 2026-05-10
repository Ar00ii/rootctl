"""Parser-level checks for `sudo -l` output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import sudo_l as sudo_parser


def test_parse_extracts_each_binary(examples_dir: Path) -> None:
    findings = sudo_parser.parse(examples_dir / "test_sudo_l.txt")
    by_path = {f.extra["full_path"]: f for f in findings}

    # Five distinct rules; the .sh entry must come back as kind=sudo-script.
    assert set(by_path) == {
        "/usr/bin/find",
        "/usr/bin/vim",
        "/opt/scripts/backup.sh",
        "/usr/bin/python3",
        "/usr/local/bin/neofetch",
    }
    assert by_path["/usr/bin/find"].kind == "sudo-binary"
    assert by_path["/opt/scripts/backup.sh"].kind == "sudo-script"

    # NOPASSWD propagation
    assert all(f.extra.get("nopasswd") == "NOPASSWD" for f in findings)
    # runas captured
    assert by_path["/usr/local/bin/neofetch"].extra["runas"].startswith("ALL")


def test_parse_text_dedupes_same_executable() -> None:
    text = (
        "User u may run the following commands on host:\n"
        "    (root) NOPASSWD: /usr/bin/find\n"
        "    (ALL) NOPASSWD: /usr/bin/find -name foo\n"
    )
    findings = sudo_parser.parse_text(text)
    assert len(findings) == 1
    assert findings[0].extra["full_path"] == "/usr/bin/find"
