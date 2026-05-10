"""Parser-level checks for nikto plain text output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import nikto as nikto_parser


def test_parses_paths_and_target(examples_dir: Path) -> None:
    findings = nikto_parser.parse(examples_dir / "test_nikto.txt")
    paths = {f.path for f in findings}
    # Every hit, with or without OSVDB prefix, becomes a Finding.
    assert "/admin" in paths
    assert "/uploads/" in paths
    assert "/wp-login.php" in paths
    assert "/phpmyadmin/" in paths
    assert "/icons/" in paths
    assert "/CHANGELOG.txt" in paths
    # Pure metadata lines (Server header, Start Time) must not produce findings.
    assert all(f.path is not None and f.path.startswith("/") for f in findings)

    by_path = {f.path: f for f in findings}
    assert by_path["/wp-login.php"].host == "target.htb"
    assert by_path["/wp-login.php"].port == 80
    assert by_path["/wp-login.php"].url == "http://target.htb:80/wp-login.php"
