"""Parser-level checks for ffuf JSON output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import ffuf as ffuf_parser


def test_parse_json_fixture(examples_dir: Path) -> None:
    findings = ffuf_parser.parse(examples_dir / "test_ffuf.json")
    paths = {f.path for f in findings}
    assert paths == {"/admin", "/login.php", "/wp-login.php", "/uploads"}
    by_path = {f.path: f for f in findings}
    assert by_path["/wp-login.php"].status_code == 200
    assert by_path["/admin"].status_code == 301
    assert all(f.tool == "ffuf" and f.host == "10.10.11.99" and f.port == 80 for f in findings)
