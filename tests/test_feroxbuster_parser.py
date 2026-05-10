"""Parser-level checks for feroxbuster default text output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import feroxbuster as fero_parser


def test_parse_default_text(examples_dir: Path) -> None:
    findings = fero_parser.parse(examples_dir / "test_feroxbuster.txt")
    paths = {f.path for f in findings}
    assert paths == {
        "/index.html", "/admin", "/login.php", "/wp-admin",
        "/wp-login.php", "/uploads",
    }
    by_path = {f.path: f for f in findings}
    assert by_path["/index.html"].status_code == 200
    assert by_path["/admin"].status_code == 301
    assert all(f.tool == "feroxbuster" for f in findings)
