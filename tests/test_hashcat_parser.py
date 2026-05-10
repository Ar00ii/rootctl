"""Parser-level checks for hashcat / john --show output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import hashcat as hashcat_parser


def test_parses_cracked_lines(examples_dir: Path) -> None:
    findings = hashcat_parser.parse(examples_dir / "test_hashcat_show.txt")
    pwds = {f.extra["password"] for f in findings}
    # Every password recovered, regardless of hash flavor or extra columns.
    assert "supersecret" in pwds
    assert "hello" in pwds
    assert "Password1" in pwds
    assert "correcthorsebatterystaple" in pwds


def test_skips_status_lines() -> None:
    text = (
        "Status...........: Running\n"
        "Speed.#1.........: 12345 H/s\n"
        "Recovered........: 0/3\n"
        "$2y$10$xxx:realpw\n"
    )
    findings = hashcat_parser.parse_text(text)
    pwds = {f.extra["password"] for f in findings}
    assert pwds == {"realpw"}


def test_pure_hex_does_not_count_as_password() -> None:
    """abc:5d41402abc4b2a76b9719d911017c592 must not be flagged as cracked."""
    text = "Hash.Target......: 5d41402abc4b2a76b9719d911017c592\n"
    findings = hashcat_parser.parse_text(text)
    assert findings == []
