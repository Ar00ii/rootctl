"""Smoke tests for the typer CLI surface.

Exercises the user-facing commands (analyze / chains / show / extract)
through CliRunner so an accidental Typer signature change is caught fast.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from rootctl.cli import app

runner = CliRunner()


def test_help_lists_every_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("analyze", "chains", "show", "extract"):
        assert cmd in result.stdout


def test_chains_lists_loaded_chains() -> None:
    result = runner.invoke(app, ["chains"])
    assert result.exit_code == 0
    # Rich truncates long IDs in the table; assert on prefixes that survive.
    assert "werkzeug_debug_pin" in result.stdout
    assert "ssh_brute_force" in result.stdout
    assert "Loaded chains" in result.stdout


def test_show_existing_chain() -> None:
    result = runner.invoke(app, ["show", "werkzeug_debug_pin_rce"])
    assert result.exit_code == 0
    assert "Werkzeug" in result.stdout
    assert "/console" in result.stdout


def test_show_markdown_is_pipe_friendly() -> None:
    """`show --markdown` must emit unstyled markdown directly, not a Rich panel."""
    result = runner.invoke(app, ["show", "werkzeug_debug_pin_rce", "--markdown"])
    assert result.exit_code == 0
    # No box-drawing chars in raw mode.
    assert "╭" not in result.stdout
    assert "│" not in result.stdout
    assert "# [CRITICAL]" in result.stdout
    assert "```bash" in result.stdout


def test_show_unknown_chain_exits_nonzero() -> None:
    result = runner.invoke(app, ["show", "no_such_chain"])
    assert result.exit_code == 1
    assert "No chain found" in result.stdout


def test_analyze_nmap_fixture(repo_root: Path) -> None:
    result = runner.invoke(
        app, ["analyze", str(repo_root / "examples" / "test_werkzeug.xml")]
    )
    assert result.exit_code == 0, result.stdout
    assert "werkzeug_debug_pin_rce" in result.stdout or "Werkzeug" in result.stdout


def test_analyze_multi_input_merges(repo_root: Path) -> None:
    """Two input files should merge into one report — chains from BOTH must fire."""
    nmap = repo_root / "examples" / "test_werkzeug.xml"
    gobuster = repo_root / "examples" / "test_gobuster.txt"
    result = runner.invoke(app, ["analyze", str(nmap), str(gobuster)])
    assert result.exit_code == 0, result.stdout
    # Werkzeug fires from nmap, WordPress from gobuster — both must appear.
    assert "Werkzeug" in result.stdout
    assert "WordPress" in result.stdout


def test_extract_runs_without_error(repo_root: Path) -> None:
    result = runner.invoke(
        app, ["extract", str(repo_root / "examples" / "test_hashes.txt")]
    )
    assert result.exit_code == 0, result.stdout
    assert "extracts" in result.stdout


def test_chains_filter_by_tag() -> None:
    result = runner.invoke(app, ["chains", "--tag", "wordpress"])
    assert result.exit_code == 0, result.stdout
    # IDs may be truncated by Rich; assert by surviving prefix.
    assert "wordpress_enum_to_r" in result.stdout
    # The header reports the count parenthetically; we don't pin the
    # exact count — the catalog grows over time.
    assert "Loaded chains" in result.stdout
    # ssh_brute_force does not carry the wordpress tag.
    assert "ssh_brute_force" not in result.stdout


def test_chains_filter_by_severity() -> None:
    result = runner.invoke(app, ["chains", "--severity", "CRITICAL"])
    assert result.exit_code == 0, result.stdout
    assert "Loaded chains" in result.stdout
    # Werkzeug is CRITICAL, MySQL is MEDIUM — only the first should appear.
    assert "werkzeug_debug_pin" in result.stdout
    assert "mysql_open" not in result.stdout


def test_tools_lists_parsers_and_extractors() -> None:
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0, result.stdout
    # Sample a few parsers that must be wired.
    assert "nmap" in result.stdout
    assert "gobuster" in result.stdout
    assert "bloodhound" in result.stdout
    # And the three extractor categories.
    assert "hashes" in result.stdout
    assert "credentials" in result.stdout
    assert "secrets" in result.stdout


def test_kinds_lists_distinct_kinds() -> None:
    result = runner.invoke(app, ["kinds"])
    assert result.exit_code == 0, result.stdout
    assert "Kinds in use" in result.stdout
    # Sample a few that should always be there.
    assert "bcrypt" in result.stdout
    assert "lm:ntlm" in result.stdout
    assert "ad-user" in result.stdout


def test_validate_passes_on_repo() -> None:
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 0, result.stdout
    assert "OK" in result.stdout


def test_validate_fails_on_bad_chain(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "chain_id: bad\ntitle: x\nseverity: LOW\n"
        "trigger: { not_a_real_field: 1 }\n"
        "description: x\nsteps: [{id: 1, title: t}]\n"
    )
    result = runner.invoke(app, ["validate", "--chains", str(tmp_path)])
    assert result.exit_code == 1
    assert "Schema error" in result.stdout


def test_analyze_min_severity_filter(repo_root: Path) -> None:
    """--min-severity HIGH should drop MEDIUM/LOW/INFO matches."""
    import json

    examples = repo_root / "examples"
    args = [
        "analyze", "--json", "--min-severity", "HIGH",
        str(examples / "multi_service.xml"),
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    severities = {m["severity"] for m in payload["matches"]}
    # multi_service triggers HIGH (ssh, smb, ftp, winrm) and MEDIUM (mysql, rdp).
    # With cutoff at HIGH, MEDIUM disappears.
    assert "MEDIUM" not in severities
    assert severities <= {"CRITICAL", "HIGH"}


def test_analyze_top_filter(repo_root: Path) -> None:
    import json

    args = [
        "analyze", "--json", "--top", "2",
        str(repo_root / "examples" / "multi_service.xml"),
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert len(payload["matches"]) == 2


def test_analyze_invalid_severity_errors(repo_root: Path) -> None:
    args = [
        "analyze", "--min-severity", "URGENT",
        str(repo_root / "examples" / "test_werkzeug.xml"),
    ]
    result = runner.invoke(app, args)
    assert result.exit_code != 0
    assert "URGENT" in result.stdout or "URGENT" in (result.stderr or "")


def test_analyze_json_output_is_parseable(repo_root: Path) -> None:
    import json

    result = runner.invoke(
        app, ["analyze", str(repo_root / "examples" / "test_werkzeug.xml"), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert sorted(payload) == ["extracts", "findings", "matches"]
    chain_ids = {m["chain_id"] for m in payload["matches"]}
    assert "werkzeug_debug_pin_rce" in chain_ids
