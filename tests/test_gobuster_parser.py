"""Parser-level checks for the gobuster reader."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import gobuster as gobuster_parser


def test_parse_with_banner(examples_dir: Path) -> None:
    findings = gobuster_parser.parse(examples_dir / "test_gobuster.txt")
    assert findings, "expected at least one finding"

    # Banner pulls host/port/scheme.
    assert all(f.tool == "gobuster" for f in findings)
    assert all(f.host == "10.10.11.99" for f in findings)
    assert all(f.port == 80 for f in findings)
    assert all(f.service == "http" for f in findings)

    by_path = {f.path: f for f in findings}
    assert "/wp-login.php" in by_path
    assert by_path["/wp-login.php"].status_code == 200
    assert by_path["/wp-login.php"].url == "http://10.10.11.99:80/wp-login.php"
    assert by_path["/.htaccess"].status_code == 403


def test_parse_text_without_banner() -> None:
    text = (
        "/login (Status: 200) [Size: 1024]\n"
        "/admin (Status: 301) [Size: 312] [--> /admin/]\n"
        "garbage line that should be ignored\n"
    )
    findings = gobuster_parser.parse_text(text)
    assert {f.path for f in findings} == {"/login", "/admin"}
    # No banner means host/port can't be inferred.
    for f in findings:
        assert f.host == "unknown"
        assert f.port is None
        assert f.url is None


def test_parser_dedupes_repeated_lines() -> None:
    text = (
        "[+] Url: http://example.com\n"
        "/foo (Status: 200) [Size: 1]\n"
        "/foo (Status: 200) [Size: 1]\n"
    )
    findings = gobuster_parser.parse_text(text)
    assert len(findings) == 1
