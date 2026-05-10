"""Coverage for the interactive console in rootctl/repl.py.

The REPL is exercised by feeding `input()` a scripted iterator of lines
and capturing what Rich writes through the shared console. We do not spawn
a real PTY here — that path is left to the hand-driven smoke check in the
README. This file just guards the dispatch and built-ins.
"""

from __future__ import annotations

import io
import sys

import pytest
from rich.console import Console

from rootctl import __version__
from rootctl.cli import app, _FORMAT_PARSERS
from rootctl import repl


@pytest.fixture
def fake_console() -> Console:
    return Console(file=io.StringIO(), width=120, force_terminal=False, color_system=None)


def _drive_repl(monkeypatch, fake_console, lines: list[str]) -> str:
    """Run the REPL with `input()` answering from `lines`. Returns Rich output.

    Subcommands write through the module-level `cli.console`, so we redirect
    that one too — otherwise their output ends up on the real stdout and our
    captured buffer only sees the REPL banner / built-ins.
    """
    iterator = iter(lines)

    def _fake_input(_prompt: str = "") -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr("builtins.input", _fake_input)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("rootctl.cli.console", fake_console)
    parser_modules = {fn.__module__ for fn in _FORMAT_PARSERS.values()}
    rc = repl.run_console(app, fake_console, chains_count=42, parsers_count=len(parser_modules))
    assert rc == 0
    return fake_console.file.getvalue()


def test_banner_renders_with_chain_and_parser_counts(monkeypatch, fake_console: Console) -> None:
    out = _drive_repl(monkeypatch, fake_console, ["exit"])
    assert "rootctl" in out
    assert __version__ in out
    assert "42 chains" in out
    assert "0 telemetry" in out
    # ASCII banner block character is present.
    assert "█" in out


def test_help_lists_subcommands(monkeypatch, fake_console: Console) -> None:
    out = _drive_repl(monkeypatch, fake_console, ["help", "exit"])
    for sub in ("analyze", "chains", "show", "extract", "tools", "kinds", "validate"):
        assert sub in out


def test_version_dispatches_to_builtin(monkeypatch, fake_console: Console) -> None:
    out = _drive_repl(monkeypatch, fake_console, ["version", "exit"])
    assert f"rootctl {__version__}" in out


def test_subcommand_dispatch_runs_validate(monkeypatch, fake_console: Console) -> None:
    out = _drive_repl(monkeypatch, fake_console, ["validate", "exit"])
    assert "loaded" in out and "chain" in out


def test_unknown_command_does_not_crash(monkeypatch, fake_console: Console) -> None:
    out = _drive_repl(monkeypatch, fake_console, ["definitely-not-a-command", "exit"])
    # Click's UsageError formatting; the REPL stays alive and reaches `exit`.
    assert "usage" in out.lower() or "no such" in out.lower() or "error" in out.lower()


def test_blank_lines_and_comments_are_ignored(monkeypatch, fake_console: Console) -> None:
    out = _drive_repl(monkeypatch, fake_console, ["", "   ", "# nothing", "version", "exit"])
    assert __version__ in out


def test_eof_exits_cleanly(monkeypatch, fake_console: Console) -> None:
    # No "exit" line — relies on EOFError from the iterator.
    out = _drive_repl(monkeypatch, fake_console, [])
    assert "rootctl" in out


def test_non_tty_falls_back_to_help(monkeypatch) -> None:
    """When stdin is not a terminal, the REPL must not block on input()."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    fake_console = Console(file=io.StringIO(), width=120, force_terminal=False, color_system=None)

    def _explode(_prompt: str = "") -> str:
        raise AssertionError("input() must not be called in non-tty mode")

    monkeypatch.setattr("builtins.input", _explode)
    rc = repl.run_console(app, fake_console, chains_count=1, parsers_count=1)
    assert rc == 0
