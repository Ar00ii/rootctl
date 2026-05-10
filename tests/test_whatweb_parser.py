"""Parser-level checks for whatweb output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import whatweb as whatweb_parser


def test_parses_tags_and_versions(examples_dir: Path) -> None:
    findings = whatweb_parser.parse(examples_dir / "test_whatweb.txt")
    techs = {f.extra["tech"] for f in findings}
    assert "Apache" in techs
    assert "WordPress" in techs
    assert "Werkzeug" in techs
    assert "Python" in techs

    by_tech = {f.extra["tech"]: f for f in findings if f.extra["tech"] in {"WordPress", "Werkzeug"}}
    assert by_tech["WordPress"].extra["value"] == "6.0"
    assert by_tech["Werkzeug"].extra["value"] == "2.1.2"
    assert by_tech["Werkzeug"].port == 8080


def test_split_tags_respects_brackets() -> None:
    text = (
        "http://x [200] Foo[a, b], Bar[c]\n"
    )
    findings = whatweb_parser.parse_text(text)
    techs = {f.extra["tech"] for f in findings}
    # Comma inside Foo[a, b] is not a separator.
    assert techs == {"Foo", "Bar"}
