"""Render findings, chain matches, and extracts to terminal or markdown.

Two output modes:
  - `render_terminal`: pretty Rich output for interactive use.
  - `render_markdown`: stable markdown intended for piping to a file.

Both modes consume the same input so they stay in sync.
"""

from __future__ import annotations

from typing import Iterable

from rich.console import Console, Group, RenderableType
from rich.markdown import Markdown
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from rootctl.models import ChainMatch, CriticalExtract, Finding, Severity

# Color per severity for the Rich table — chosen to be readable on both light
# and dark terminals.
_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_terminal(
    findings: Iterable[Finding],
    matches: Iterable[ChainMatch],
    extracts: Iterable[CriticalExtract] = (),
    console: Console | None = None,
    quiet: bool = False,
) -> None:
    """Print a colored summary to stdout.

    `quiet=True` collapses the report to summary + chain panels only —
    skips the findings table and the critical extracts table. Useful when
    the operator already knows what was scanned and only wants the next
    actions to take.
    """
    console = console or Console()
    findings = list(findings)
    matches = list(matches)
    extracts = list(extracts)

    real_count = sum(1 for f in findings if f.host != "extract")
    summary = (
        f"[bold]rootctl[/bold] — {real_count} findings · "
        f"{len(matches)} chain matches · {len(extracts)} extracts"
    )
    sev_breakdown = _severity_breakdown(matches)
    if sev_breakdown:
        summary += f"\n{sev_breakdown}"
    console.print(Panel.fit(summary, border_style="green"))

    real_findings = [f for f in findings if f.host != "extract"]
    if real_findings and not quiet:
        table = Table(title="Findings", show_header=True, header_style="bold")
        table.add_column("Host")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Banner")
        for f in real_findings:
            port = f"{f.port}/{f.protocol or 'tcp'}" if f.port else "-"
            table.add_row(f.host, port, f.service or "-", f.banner or "-")
        console.print(table)

    if extracts and not quiet:
        table = Table(title="Critical extracts", show_header=True, header_style="bold")
        table.add_column("Kind")
        table.add_column("Value")
        table.add_column("Next command")
        for e in extracts:
            color = _SEVERITY_COLOR.get(e.severity, "")
            table.add_row(
                f"[{color}]{e.kind}[/{color}]" if color else e.kind,
                e.value,
                e.next_command or "-",
            )
        console.print(table)

    for m in matches:
        color = _SEVERITY_COLOR.get(m.severity, "")
        title = f"[{color}]{m.severity.value}[/{color}] · {m.title}"
        console.print(Panel(_chain_renderable(m), title=title, border_style=color or "white"))


def _chain_renderable(m: ChainMatch) -> RenderableType:
    """Build a Rich-native renderable for one chain panel.

    Avoids going through Markdown so multi-line commands render as proper
    monospace code blocks instead of being centered / re-flowed by the
    Markdown renderer's blockquote pass.
    """
    parts: list[RenderableType] = []
    if m.tags:
        tag_text = Text("Tags: ", style="dim")
        tag_text.append(", ".join(m.tags), style="cyan")
        parts.append(tag_text)
    parts.append(Text(m.description.rstrip(), style=""))

    parts.append(Rule(style="dim"))
    parts.append(Text("Triggered by:", style="bold"))
    for f in m.findings:
        parts.append(Text(f"  • {f.label}"))

    parts.append(Rule(style="dim"))
    parts.append(Text("Steps:", style="bold"))
    for s in m.steps:
        parts.append(Text(f"  {s.id}. {s.title}", style="bold white"))
        if s.command:
            parts.append(
                Padding(
                    Syntax(
                        s.command.rstrip(),
                        "bash",
                        theme="ansi_dark",
                        background_color="default",
                        word_wrap=True,
                    ),
                    (0, 0, 0, 5),
                )
            )
        if s.notes:
            parts.append(Padding(Text(s.notes.rstrip(), style="dim italic"), (0, 0, 0, 5)))

    if m.common_errors:
        parts.append(Rule(style="dim"))
        parts.append(Text("If it fails — common errors:", style="bold"))
        for e in m.common_errors:
            err = Text("  • ", style="bold")
            err.append(e.error, style="red")
            parts.append(err)
            parts.append(Padding(Text(e.solution.rstrip(), style="dim"), (0, 0, 0, 4)))

    if m.references:
        parts.append(Rule(style="dim"))
        parts.append(Text("References:", style="bold"))
        for ref in m.references:
            parts.append(Text(f"  • {ref}", style="blue underline"))

    return Group(*parts)


def render_markdown(
    findings: Iterable[Finding],
    matches: Iterable[ChainMatch],
    extracts: Iterable[CriticalExtract] = (),
) -> str:
    """Return a deterministic markdown report as a single string."""
    findings = list(findings)
    matches = list(matches)
    extracts = list(extracts)

    out: list[str] = ["# rootctl report", ""]
    out.append(
        f"- Findings: **{len(findings)}**  \n"
        f"- Chain matches: **{len(matches)}**  \n"
        f"- Critical extracts: **{len(extracts)}**"
    )
    if matches:
        counts: dict[Severity, int] = {}
        for m in matches:
            counts[m.severity] = counts.get(m.severity, 0) + 1
        bits = [
            f"{sev.value}: {counts[sev]}"
            for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
            if counts.get(sev, 0)
        ]
        out.append(f"- By severity: {' · '.join(bits)}")
    out.append("")

    real_findings = [f for f in findings if f.host != "extract"]
    if real_findings:
        out += ["## Findings", "", "| Host | Port | Service | Banner |", "|---|---|---|---|"]
        for f in real_findings:
            port = f"{f.port}/{f.protocol or 'tcp'}" if f.port else "-"
            out.append(f"| {f.host} | {port} | {f.service or '-'} | {_md_escape(f.banner or '-')} |")
        out.append("")

    if extracts:
        out += ["## Critical extracts", "", "| Severity | Kind | Value | Next command |", "|---|---|---|---|"]
        for e in extracts:
            out.append(
                f"| {e.severity.value} | {e.kind} | `{_md_escape(e.value)}` | "
                f"{('`' + _md_escape(e.next_command) + '`') if e.next_command else '-'} |"
            )
        out.append("")

    if matches:
        out += ["## Chain matches", ""]
        for m in matches:
            out.append(f"### [{m.severity.value}] {m.title} (`{m.chain_id}`)")
            out.append("")
            out.append(_chain_markdown(m))
            out.append("")

    return "\n".join(out).rstrip() + "\n"


def _chain_markdown(m: ChainMatch) -> str:
    parts: list[str] = []
    if m.tags:
        parts.append("**Tags:** " + ", ".join(f"`{t}`" for t in m.tags))
    parts.append(m.description)
    parts.append("")
    parts.append("**Triggered by:**")
    for f in m.findings:
        parts.append(f"- {f.label}")
    parts.append("")
    parts.append("**Steps:**")
    for s in m.steps:
        parts.append(f"{s.id}. {s.title}")
        if s.command:
            parts.append("   ```")
            parts.append(f"   {s.command}")
            parts.append("   ```")
        if s.notes:
            parts.append(f"   > {s.notes}")
    if m.common_errors:
        parts.append("")
        parts.append("**If it fails — common errors:**")
        for e in m.common_errors:
            parts.append(f"- **{e.error}** → {e.solution}")
    if m.references:
        parts.append("")
        parts.append("**References:**")
        for ref in m.references:
            parts.append(f"- {ref}")
    return "\n".join(parts)


def _md_escape(text: str) -> str:
    """Escape characters that would break a markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def _severity_breakdown(matches: list[ChainMatch]) -> str:
    """Build a one-line severity tally like 'CRITICAL: 3 · HIGH: 6 · MEDIUM: 3'."""
    if not matches:
        return ""
    counts: dict[Severity, int] = {}
    for m in matches:
        counts[m.severity] = counts.get(m.severity, 0) + 1
    bits: list[str] = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        color = _SEVERITY_COLOR.get(sev, "")
        if color:
            bits.append(f"[{color}]{sev.value}[/{color}]: {n}")
        else:
            bits.append(f"{sev.value}: {n}")
    return " · ".join(bits)
