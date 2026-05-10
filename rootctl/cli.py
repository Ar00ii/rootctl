"""Typer CLI entry point.

Commands:
  analyze   parse one or more tool outputs, match chains, print a report
  chains    list every chain loaded from disk
  show      print a single chain in full (steps, common errors, references)
  extract   run extractors over a text file (hashes, credentials, secrets)
  validate  load every chain and report any schema errors
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import List

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from rootctl import __version__

from rootctl.engine.matcher import DEFAULT_CHAINS_DIR, load_chains, match
from rootctl.engine.reporter import render_markdown, render_terminal
from rootctl.extractors import extract_all, extracts_to_findings
from rootctl.parsers import (
    bloodhound as bh_parser,
    enum4linux as e4l_parser,
    feroxbuster as fero_parser,
    ffuf as ffuf_parser,
    find_suid as suid_parser,
    gobuster as gobuster_parser,
    hashcat as hashcat_parser,
    linpeas as linpeas_parser,
    netexec as nxc_parser,
    nikto as nikto_parser,
    nmap as nmap_parser,
    nuclei as nuclei_parser,
    pspy as pspy_parser,
    smbmap as smbmap_parser,
    sudo_l as sudo_parser,
    whatweb as whatweb_parser,
    whoami_priv as whoami_parser,
)

app = typer.Typer(
    name="rootctl",
    help="Offline pentest output triage. No telemetry, no cloud.",
    add_completion=False,
)

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"rootctl {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """Offline pentest output triage. No telemetry, no cloud."""
    if ctx.invoked_subcommand is not None:
        return None
    # Bare `rootctl` with no subcommand → drop into the interactive console.
    from rootctl.repl import run_console
    from rootctl.engine.matcher import DEFAULT_CHAINS_DIR, load_chains

    chains = load_chains(DEFAULT_CHAINS_DIR)
    parser_modules = {fn.__module__ for fn in _FORMAT_PARSERS.values()}
    raise typer.Exit(
        code=run_console(app, console, len(chains), len(parser_modules))
    )

# Format hint determines which parser is selected for `analyze`. New parsers
# get added here as they ship.
_FORMAT_PARSERS = {
    "nmap": nmap_parser.parse,
    "gobuster": gobuster_parser.parse,
    "ffuf": ffuf_parser.parse,
    "feroxbuster": fero_parser.parse,
    "nuclei": nuclei_parser.parse,
    "smbmap": smbmap_parser.parse,
    "linpeas": linpeas_parser.parse,
    "pspy": pspy_parser.parse,
    "hashcat": hashcat_parser.parse,
    "john": hashcat_parser.parse,
    "enum4linux": e4l_parser.parse,
    "bloodhound": bh_parser.parse,
    "nikto": nikto_parser.parse,
    "whatweb": whatweb_parser.parse,
    "netexec": nxc_parser.parse,
    "sudo": sudo_parser.parse,
    "suid": suid_parser.parse,
    "whoami": whoami_parser.parse,
}


@app.command()
def analyze(
    paths: List[Path] = typer.Argument(..., exists=True, readable=True, help="One or more tool outputs to analyze."),
    fmt: str = typer.Option("auto", "--format", "-f", help=f"Input format: auto | {' | '.join(_FORMAT_PARSERS)}"),
    chains_dir: Path = typer.Option(DEFAULT_CHAINS_DIR, "--chains", help="Directory containing chain YAMLs."),
    markdown_out: Path | None = typer.Option(None, "--out", "-o", help="Also write a markdown report to this path."),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON to stdout (suppresses the human report)."),
    min_severity: str | None = typer.Option(None, "--min-severity", help="Hide chain matches below this severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)."),
    only_tag: str | None = typer.Option(None, "--tag", "-t", help="Only show chain matches carrying this tag."),
    top: int | None = typer.Option(None, "--top", help="Only show the first N chain matches (after severity sort)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Collapse output to chain panels only — no findings/extracts tables."),
) -> None:
    """Parse PATHS, match chains against findings, and print a prioritized report.

    Multiple files are merged into a single report — useful for triaging an
    engagement folder where nmap, gobuster, sudo -l, and a creds dump all
    contribute findings to the same target.
    """
    findings = []
    extracts = []
    for path in paths:
        parser_fn = _select_parser(fmt, path)
        findings.extend(parser_fn(path))

        text = _read_text_safely(path)
        if text:
            file_extracts = extract_all(text, source=str(path))
            extracts.extend(file_extracts)
            findings.extend(extracts_to_findings(file_extracts))

    chains = load_chains(chains_dir)
    matches = match(findings, chains)
    matches = _apply_match_filters(matches, min_severity, only_tag, top)

    if json_out:
        typer.echo(_to_json(findings, matches, extracts))
        return

    render_terminal(findings, matches, extracts=extracts, console=console, quiet=quiet)

    if markdown_out is not None:
        markdown_out.write_text(
            render_markdown(findings, matches, extracts=extracts), encoding="utf-8"
        )
        console.print(f"[green]Wrote markdown report to {markdown_out}[/green]")


@app.command(name="chains")
def chains_cmd(
    chains_dir: Path = typer.Option(DEFAULT_CHAINS_DIR, "--chains", help="Directory containing chain YAMLs."),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Only show chains carrying this tag."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Only show chains at this severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)."),
) -> None:
    """List every chain loaded from CHAINS_DIR (filterable by tag and/or severity)."""
    loaded = load_chains(chains_dir)
    if tag:
        loaded = [c for c in loaded if tag in c.tags]
    if severity:
        sev = severity.upper()
        loaded = [c for c in loaded if c.severity.value == sev]

    if not loaded:
        msg = f"No chains found under {chains_dir}"
        if tag or severity:
            msg += f" matching {tag=} {severity=}"
        console.print(f"[yellow]{msg}[/yellow]")
        raise typer.Exit(code=1)

    table = Table(title=f"Loaded chains ({len(loaded)})", show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Chain ID")
    table.add_column("Title")
    table.add_column("Tags")
    for c in loaded:
        table.add_row(c.severity.value, c.chain_id, c.title, ", ".join(c.tags))
    console.print(table)


@app.command()
def show(
    chain_id: str = typer.Argument(..., help="Chain ID to display in full."),
    chains_dir: Path = typer.Option(DEFAULT_CHAINS_DIR, "--chains", help="Directory containing chain YAMLs."),
    raw: bool = typer.Option(False, "--markdown", help="Print raw markdown to stdout (no Rich formatting). Pipe-friendly."),
) -> None:
    """Print one chain in full — every step, common error, and reference."""
    loaded = load_chains(chains_dir)
    chain = next((c for c in loaded if c.chain_id == chain_id), None)
    if chain is None:
        console.print(f"[red]No chain found with id '{chain_id}'[/red]")
        console.print(f"Run [bold]rootctl chains[/bold] to see all {len(loaded)} loaded chains.")
        raise typer.Exit(code=1)

    md = _chain_to_markdown(chain)
    if raw:
        typer.echo(md)
        return
    console.print(Panel(Markdown(md), border_style="cyan"))


def _chain_to_markdown(chain) -> str:
    parts: list[str] = [
        f"# [{chain.severity.value}] {chain.title}",
        "",
        f"**Chain ID:** `{chain.chain_id}`  ",
        f"**Tags:** {', '.join(f'`{t}`' for t in chain.tags) or '_(none)_'}",
        "",
        chain.description,
        "",
        "## Steps",
    ]
    for s in chain.steps:
        parts.append(f"### {s.id}. {s.title}")
        if s.command:
            parts.append("```bash")
            parts.append(s.command)
            parts.append("```")
        if s.notes:
            parts.append(f"> {s.notes}")
        parts.append("")
    if chain.common_errors:
        parts.append("## Common errors")
        for e in chain.common_errors:
            parts.append(f"- **{e.error}** → {e.solution}")
        parts.append("")
    if chain.references:
        parts.append("## References")
        for ref in chain.references:
            parts.append(f"- {ref}")
    return "\n".join(parts)


@app.command()
def extract(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Text file to scan for hashes, credentials, secrets."),
    chains_dir: Path = typer.Option(DEFAULT_CHAINS_DIR, "--chains", help="Directory containing chain YAMLs."),
) -> None:
    """Pull hashes, credentials, and secrets out of a raw text file (and match chains)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    items = extract_all(text, source=str(path))
    findings = extracts_to_findings(items)
    chains = load_chains(chains_dir)
    matches = match(findings, chains)
    render_terminal(findings, matches, extracts=items, console=console)


@app.command()
def tools() -> None:
    """List supported parsers and extractor categories."""
    table = Table(title=f"Parsers ({len(_FORMAT_PARSERS)})", show_header=True, header_style="bold")
    table.add_column("--format")
    table.add_column("Module")
    for fmt in sorted(_FORMAT_PARSERS):
        fn = _FORMAT_PARSERS[fmt]
        module = fn.__module__.rsplit(".", 1)[-1]
        table.add_row(fmt, module)
    console.print(table)

    extractors = Table(title="Extractors", show_header=True, header_style="bold")
    extractors.add_column("Module")
    extractors.add_column("Emits kind=")
    extractors.add_row(
        "hashes",
        "bcrypt, phpass, md5crypt, sha256crypt, sha512crypt, argon2, "
        "kerberos-asrep, kerberos-tgs, net-ntlmv2, jwt, mysql4.1+, "
        "lm:ntlm, dcc2, sha512, sha256, sha1, md5_or_ntlm",
    )
    extractors.add_row(
        "credentials",
        "user:pass, hydra-cred, basic-auth-url, basic-auth-header, "
        "bearer-token, mysql-cli, wp-config, dsn-url",
    )
    extractors.add_row(
        "secrets",
        "aws-access-key-id, aws-secret-access-key, aws-s3-bucket, "
        "kubernetes-token, github-token, github-fine-grained, slack-token, "
        "google-api-key, stripe-live, private-key, jwt-secret-env, env-secret",
    )
    console.print(extractors)


@app.command()
def kinds(
    chains_dir: Path = typer.Option(DEFAULT_CHAINS_DIR, "--chains", help="Directory containing chain YAMLs."),
) -> None:
    """List every distinct `kind` referenced by any loaded chain.

    Useful when authoring a new chain — tells you what tags the parsers
    and extractors actually emit so you can pick a `kind:` clause that
    matches reality instead of inventing a label that never fires.
    """
    loaded = load_chains(chains_dir)
    kinds_used: dict[str, list[str]] = {}

    def _collect_clause(clause):
        for key in ("kind", "kind_in"):
            if key in clause:
                vals = clause[key] if isinstance(clause[key], list) else [clause[key]]
                for v in vals:
                    kinds_used.setdefault(v, []).append(c.chain_id)

    for c in loaded:
        trigger = c.trigger
        if "any_of" in trigger:
            for cl in trigger["any_of"]:
                _collect_clause(cl)
        else:
            _collect_clause(trigger)

    if not kinds_used:
        console.print("[yellow]No chain references a `kind` trigger.[/yellow]")
        return

    table = Table(title=f"Kinds in use ({len(kinds_used)})", show_header=True, header_style="bold")
    table.add_column("Kind")
    table.add_column("# chains")
    table.add_column("Chains")
    for kind in sorted(kinds_used):
        chain_ids = sorted(set(kinds_used[kind]))
        table.add_row(kind, str(len(chain_ids)), ", ".join(chain_ids))
    console.print(table)


@app.command()
def validate(
    chains_dir: Path = typer.Option(DEFAULT_CHAINS_DIR, "--chains", help="Directory containing chain YAMLs."),
) -> None:
    """Load every chain and report any schema errors. Exit 1 on first failure."""
    try:
        loaded = load_chains(chains_dir)
    except ValueError as e:
        console.print(f"[red]Schema error:[/red] {e}")
        raise typer.Exit(code=1)

    if not loaded:
        console.print(f"[yellow]No chains found under {chains_dir}[/yellow]")
        raise typer.Exit(code=1)

    console.print(
        f"[green]OK[/green] — loaded [bold]{len(loaded)}[/bold] chain(s) "
        f"from {chains_dir}"
    )


def _apply_match_filters(matches, min_severity: str | None, only_tag: str | None, top: int | None):
    """Apply --min-severity / --tag / --top to the match list, in that order."""
    from rootctl.models import Severity

    out = list(matches)
    if min_severity:
        try:
            cutoff = Severity(min_severity.upper()).rank
        except ValueError:
            raise typer.BadParameter(
                f"unknown severity '{min_severity}'. "
                "Expected one of CRITICAL, HIGH, MEDIUM, LOW, INFO."
            )
        out = [m for m in out if m.severity.rank <= cutoff]
    if only_tag:
        out = [m for m in out if only_tag in m.tags]
    if top is not None and top >= 0:
        out = out[:top]
    return out


def _to_json(findings, matches, extracts) -> str:
    """Serialize a full analyze run as JSON for downstream tooling."""
    payload = {
        "findings": [_finding_dict(f) for f in findings],
        "extracts": [_extract_dict(e) for e in extracts],
        "matches": [_match_dict(m) for m in matches],
    }
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _finding_dict(f) -> dict:
    d = asdict(f)
    return d


def _extract_dict(e) -> dict:
    d = asdict(e)
    d["severity"] = e.severity.value
    return d


def _match_dict(m) -> dict:
    return {
        "chain_id": m.chain_id,
        "title": m.title,
        "severity": m.severity.value,
        "tags": list(m.tags),
        "description": m.description,
        "steps": [
            {"id": s.id, "title": s.title, "command": s.command, "notes": s.notes}
            for s in m.steps
        ],
        "common_errors": [
            {"error": e.error, "solution": e.solution} for e in m.common_errors
        ],
        "references": list(m.references),
        "findings": [_finding_dict(f) for f in m.findings],
    }


def _read_text_safely(path: Path) -> str:
    """Read a file as UTF-8 text. Returns "" on read error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _select_parser(fmt: str, path: Path):
    """Pick the parser callable based on user-provided format hint or file shape."""
    if fmt != "auto":
        if fmt not in _FORMAT_PARSERS:
            raise typer.BadParameter(
                f"unsupported format '{fmt}'. Available: {', '.join(_FORMAT_PARSERS)}"
            )
        return _FORMAT_PARSERS[fmt]

    # Auto-detect based on extension and a quick header sniff.
    suffix = path.suffix.lower()
    head = path.read_bytes()[:2048]
    if suffix == ".xml" and b"nmaprun" in head.lower():
        return nmap_parser.parse
    # nuclei JSONL: starts with a JSON object containing "template-id".
    if b'"template-id"' in head or b'"templateID"' in head:
        return nuclei_parser.parse
    # ffuf JSON output: starts with `{` and contains "commandline" / "results".
    if b'"commandline"' in head and b'"results"' in head:
        return ffuf_parser.parse
    # BloodHound JSON dumps: contain "Properties" and a "meta" block.
    if b'"Properties"' in head and b'"meta"' in head:
        return bh_parser.parse
    # smbmap default text output has a fixed "Disk ... Permissions" header.
    if b"Disk" in head and b"Permissions" in head and b"[+] IP:" in head:
        return smbmap_parser.parse
    # Gobuster `dir` output has a recognizable banner or status-tagged lines.
    if b"Gobuster" in head or b"(Status:" in head:
        return gobuster_parser.parse
    # `sudo -l` output starts with "Matching Defaults" or contains the
    # "may run the following commands" lead-in.
    if b"may run the following commands" in head or b"Matching Defaults entries" in head:
        return sudo_parser.parse
    # `whoami /priv` has a fixed PRIVILEGES INFORMATION header.
    if b"PRIVILEGES INFORMATION" in head:
        return whoami_parser.parse
    # LinPEAS section banners use box-drawing characters that don't appear
    # in the other supported formats.
    if b"\xe2\x95\x94" in head and b"\xe2\x95\xa3" in head:  # ╔ + ╣
        return linpeas_parser.parse
    # pspy: lines start with timestamp + CMD: UID=N PID=...
    if b"CMD: UID=" in head:
        return pspy_parser.parse
    # enum4linux header.
    if b"enum4linux" in head:
        return e4l_parser.parse
    # nikto report header.
    if b"Nikto v" in head:
        return nikto_parser.parse
    # whatweb lines start with a URL followed by `[NNN]` (HTTP status).
    if re.search(rb"^https?://\S+\s+\[\d{3}\]", head, re.MULTILINE):
        return whatweb_parser.parse
    # netexec / crackmapexec rows start with PROTO + ip + port + name + bracket tag.
    if re.search(rb"^(?:SMB|MSSQL|WINRM|LDAP|FTP|RDP)\s+\S+\s+\d+\s+\S+\s+\[", head, re.MULTILINE):
        return nxc_parser.parse
    # `find ... -ls` long listing of SUID files: rows start with -rwsr.
    if b"-rws" in head[:512]:
        return suid_parser.parse
    # No structured parser fits — return a no-op so the file still flows
    # through the extractors (hashes / credentials / secrets) unchanged.
    # Use --format explicitly to override.
    return _noop_parser


def _noop_parser(_path: Path) -> list:
    """Fallback parser: produce no structured findings. Extractors still run."""
    return []


if __name__ == "__main__":
    app()
