"""Interactive `rootctl` console — invoked when the binary is run with no args.

The shell is intentionally thin: every line the user types is shlex-split and
fed back through the same Typer command tree the non-interactive CLI uses, so
features land in the REPL automatically as soon as they ship as commands. A
handful of REPL-only built-ins (`help`, `clear`, `banner`, `version`, `exit`)
short-circuit before that dispatch.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

import click
import typer
from rich.console import Console

from rootctl import __version__

# Block characters drawn from U+2588 / U+255A box-drawing set. Renders the
# 'ROOTCTL' wordmark in roughly the same dimensions msfconsole uses for its
# banner — six rows tall, ASCII-only fallback safe inside a UTF-8 terminal.
_BANNER = r"""
██████╗  ██████╗  ██████╗ ████████╗ ██████╗████████╗██╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝╚══██╔══╝██║
██████╔╝██║   ██║██║   ██║   ██║   ██║        ██║   ██║
██╔══██╗██║   ██║██║   ██║   ██║   ██║        ██║   ██║
██║  ██║╚██████╔╝╚██████╔╝   ██║   ╚██████╗   ██║   ███████╗
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝   ╚═╝   ╚══════╝
"""

# Subcommands exposed by the CLI app. Sourced at runtime from the Click
# command tree, but kept here as a hard-coded fallback so tab-completion has
# a stable list when the introspection path fails (e.g. tests).
_SUBCOMMANDS = (
    "analyze",
    "chains",
    "show",
    "extract",
    "tools",
    "kinds",
    "validate",
)
_BUILTINS = ("help", "?", "exit", "quit", "clear", "version", "banner")

# `\x01` / `\x02` mark non-printing escape sequences for GNU readline so the
# colored prompt does not corrupt history navigation cursor math. They are
# stripped by libedit on macOS, which means a literal `\x01` may print there;
# Kali / Debian ship GNU readline so this is the right tradeoff for the
# primary platform.
_PROMPT = "\x01\x1b[1;31m\x02rootctl\x01\x1b[0m\x02 > "


def run_console(
    typer_app: typer.Typer,
    console: Console,
    chains_count: int,
    parsers_count: int,
) -> int:
    """REPL entry point. Returns a process exit code."""
    if not sys.stdin.isatty():
        # Non-tty stdin (pipe, redirect, CI) — print help instead of hanging
        # on a prompt nobody can answer.
        from typer.main import get_command

        get_command(typer_app)(["--help"], standalone_mode=False)
        return 0

    _print_banner(console, chains_count, parsers_count)
    _setup_readline()

    click_cmd = _to_click(typer_app)

    while True:
        try:
            raw = input(_PROMPT)
        except EOFError:
            console.print()
            return 0
        except KeyboardInterrupt:
            console.print("[dim]^C — type 'exit' to leave[/dim]")
            continue

        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line in ("exit", "quit"):
            return 0
        if line in ("help", "?"):
            _print_help(console)
            continue
        if line == "clear":
            console.clear()
            continue
        if line == "version":
            console.print(f"rootctl {__version__}")
            continue
        if line == "banner":
            _print_banner(console, chains_count, parsers_count)
            continue

        try:
            args = shlex.split(line)
        except ValueError as exc:
            console.print(f"[red]parse error:[/red] {exc}")
            continue

        try:
            click_cmd.main(args=args, standalone_mode=False, prog_name="rootctl")
        except click.exceptions.UsageError as exc:
            # Click prints usage errors itself when standalone, but with
            # standalone_mode=False we have to format them.
            console.print(f"[red]usage:[/red] {exc.format_message()}")
        except click.exceptions.Exit:
            # `--help` raises Exit(0); subcommands raise Exit(1) on failure.
            # Either way, swallow it so the REPL keeps running.
            pass
        except SystemExit:
            pass
        except KeyboardInterrupt:
            console.print("[dim]^C — interrupted[/dim]")


def _to_click(typer_app: typer.Typer) -> click.Command:
    from typer.main import get_command

    return get_command(typer_app)


def _print_banner(console: Console, chains_count: int, parsers_count: int) -> None:
    console.print()
    for line in _BANNER.strip("\n").splitlines():
        console.print(f"[bold red]{line}[/bold red]")
    console.print()

    # Categories = number of immediate child directories of the chains root.
    cats = _count_categories()

    bar = "[bold red]+[/bold red] -- --=\\[ "
    console.print(
        f"       =\\[ [bold]rootctl[/bold] v{__version__}", highlight=False
    )
    console.print(
        f"{bar}{chains_count} chains across {cats} categories", highlight=False
    )
    console.print(
        f"{bar}{parsers_count} parsers · 3 extractor categories",
        highlight=False,
    )
    console.print(
        f"{bar}0 telemetry · 0 cloud · 0 invented chain steps", highlight=False
    )
    console.print()
    console.print(
        "[dim]type [bold]help[/bold] for built-ins, or any subcommand "
        "(analyze, chains, show, extract, …)[/dim]",
        highlight=False,
    )
    console.print()


def _count_categories() -> int:
    from rootctl.engine.matcher import DEFAULT_CHAINS_DIR

    root = Path(DEFAULT_CHAINS_DIR)
    if not root.is_dir():
        return 0
    return sum(1 for p in root.iterdir() if p.is_dir())


def _print_help(console: Console) -> None:
    console.print()
    console.print("[bold]Built-in REPL commands[/bold]")
    console.print("  [cyan]help[/cyan] · [cyan]?[/cyan]      — this message")
    console.print("  [cyan]banner[/cyan]        — reprint the banner")
    console.print("  [cyan]clear[/cyan]         — clear the screen")
    console.print("  [cyan]version[/cyan]       — print rootctl version")
    console.print("  [cyan]exit[/cyan] · [cyan]quit[/cyan]   — leave (Ctrl-D also works)")
    console.print()
    console.print("[bold]Subcommands[/bold] (append [cyan]--help[/cyan] for details)")
    for name in _SUBCOMMANDS:
        console.print(f"  [green]{name}[/green]")
    console.print()


def _setup_readline() -> None:
    """Wire stdlib readline for line editing, history, and tab completion."""
    try:
        import readline
    except ImportError:
        return

    completions = sorted(set(_SUBCOMMANDS) | {b for b in _BUILTINS if b != "?"})

    def _complete(text: str, state: int):
        matches = [c for c in completions if c.startswith(text)]
        return matches[state] if state < len(matches) else None

    readline.set_completer(_complete)
    readline.parse_and_bind("tab: complete")
    # libedit (Apple) uses a different bind syntax; the GNU form above is a
    # no-op there, the line below covers libedit.
    readline.parse_and_bind("bind ^I rl_complete")
