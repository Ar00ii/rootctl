"""Parser-level checks for LinPEAS output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import linpeas as linpeas_parser


def test_extracts_suid_and_capabilities(examples_dir: Path) -> None:
    findings = linpeas_parser.parse(examples_dir / "test_linpeas.txt")

    suids = {f.extra["full_path"] for f in findings if f.kind == "suid-binary"}
    assert {"/usr/bin/find", "/usr/bin/nmap", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd"} == suids

    caps = {(f.extra["full_path"], f.extra["capability"]) for f in findings if f.kind == "linux-capability"}
    assert ("/usr/bin/python3.10", "cap_setuid") in caps
    assert ("/usr/bin/perl", "cap_setuid") in caps
    assert ("/usr/bin/tar", "cap_dac_read_search") in caps


def test_strips_ansi_escapes() -> None:
    text = (
        "\x1B[31m-rwsr-xr-x 1 root root 71M Jan 30  2024 /usr/bin/find\x1B[0m\n"
        "\x1B[33m/usr/bin/python3 = cap_setuid+ep\x1B[0m\n"
    )
    findings = linpeas_parser.parse_text(text)
    kinds = {f.kind for f in findings}
    assert kinds == {"suid-binary", "linux-capability"}
