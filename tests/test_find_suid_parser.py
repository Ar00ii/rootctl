"""Parser-level checks for `find ... -perm -4000` output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import find_suid as suid_parser


def test_parse_long_listing(examples_dir: Path) -> None:
    findings = suid_parser.parse(examples_dir / "test_find_suid.txt")
    bins = {f.extra["full_path"] for f in findings}
    assert {"/usr/bin/find", "/usr/bin/nmap", "/usr/bin/su", "/usr/bin/sudo"} <= bins
    assert all(f.kind == "suid-binary" for f in findings)


def test_parse_bare_paths() -> None:
    text = "/usr/bin/find\n/usr/bin/nmap\n/sbin/mount.cifs\n"
    findings = suid_parser.parse_text(text)
    bins = {f.extra["full_path"] for f in findings}
    assert bins == {"/usr/bin/find", "/usr/bin/nmap", "/sbin/mount.cifs"}
