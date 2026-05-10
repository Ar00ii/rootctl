"""Parser-level checks for nuclei JSONL and plain output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import nuclei as nuclei_parser


def test_parse_jsonl_fixture(examples_dir: Path) -> None:
    findings = nuclei_parser.parse(examples_dir / "test_nuclei.jsonl")
    assert len(findings) == 4

    by_kind = {f.kind: f for f in findings}
    assert "tech-detect" in by_kind
    assert by_kind["CVE-2021-44228"].extra["severity"] == "critical"
    assert by_kind["CVE-2021-44228"].host == "10.10.11.99"
    assert by_kind["CVE-2021-44228"].port == 8080
    assert by_kind["git-config"].path == "/.git/config"


def test_parse_plain_text() -> None:
    text = (
        "[2026-04-29 12:00:00] [tech-detect:wordpress] [http] [info] http://1.2.3.4/\n"
        "[2026-04-29 12:00:01] [CVE-2021-44228] [http] [critical] http://1.2.3.4:8080/api\n"
    )
    findings = nuclei_parser.parse_text(text)
    kinds = {f.kind for f in findings}
    assert kinds == {"tech-detect:wordpress", "CVE-2021-44228"}
    crit = next(f for f in findings if f.kind == "CVE-2021-44228")
    assert crit.extra["severity"] == "critical"
    assert crit.port == 8080
