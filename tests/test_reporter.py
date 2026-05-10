"""Reporter determinism and content checks.

Two runs over the same input must produce byte-identical markdown — one of
the project's hard rules.
"""

from __future__ import annotations

from pathlib import Path

from rootctl.engine.matcher import load_chains, match
from rootctl.engine.reporter import render_markdown
from rootctl.parsers import nmap as nmap_parser


def test_markdown_is_deterministic(chains_dir: Path, examples_dir: Path) -> None:
    findings = nmap_parser.parse(examples_dir / "test_werkzeug.xml")
    chains = load_chains(chains_dir)
    matches = match(findings, chains)

    a = render_markdown(findings, matches)
    b = render_markdown(findings, matches)
    assert a == b


def test_markdown_contains_chain_steps(chains_dir: Path, examples_dir: Path) -> None:
    findings = nmap_parser.parse(examples_dir / "test_werkzeug.xml")
    chains = load_chains(chains_dir)
    matches = match(findings, chains)

    md = render_markdown(findings, matches)
    assert "werkzeug_debug_pin_rce" in md
    assert "CRITICAL" in md
    # A literal command from the chain — proves we didn't summarize it away.
    assert "gobuster dir -u http://dominio.thl:8080" in md


def test_markdown_includes_severity_breakdown(chains_dir: Path, examples_dir: Path) -> None:
    findings = nmap_parser.parse(examples_dir / "multi_service.xml")
    chains = load_chains(chains_dir)
    matches = match(findings, chains)

    md = render_markdown(findings, matches)
    assert "By severity:" in md
    assert "HIGH:" in md
