"""Parser for nuclei output.

Two input shapes are accepted:

  - JSONL (`nuclei ... -jsonl`): one JSON object per line, the canonical
    machine-readable form.
  - Plain text (default stdout): bracketed lines like
      [2026-04-29 12:00:00] [tech-detect:wordpress] [http] [info] http://10.10.10.10/

Each result becomes one Finding with tool="nuclei", kind=template-id,
banner=info.name (or template-id), url=matched-at, and severity carried in
`extra["severity"]` for downstream display.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from rootctl.models import Finding


# Bracketed plain-text lines: [time] [template-id] [proto] [severity] url
_TEXT_LINE = re.compile(
    r"\[\S+\s+\S+\]\s*"                  # timestamp [optional]
    r"\[(?P<template>[^\]]+)\]\s*"
    r"\[(?P<proto>[^\]]+)\]\s*"
    r"\[(?P<severity>info|low|medium|high|critical|unknown)\]\s*"
    r"(?P<url>https?://\S+)",
    re.IGNORECASE,
)


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    # Try JSONL first — first non-empty line that parses as JSON commits us.
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                json.loads(line)
                return _parse_jsonl(text)
            except json.JSONDecodeError:
                pass
        break
    return _parse_plain(text)


def _parse_jsonl(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(_finding_from_jsonl(obj))
    return findings


def _finding_from_jsonl(obj: dict) -> Finding:
    info = obj.get("info") or {}
    template_id = obj.get("template-id") or obj.get("templateID") or "unknown"
    name = info.get("name") or template_id
    severity = (info.get("severity") or "unknown").lower()
    url = obj.get("matched-at") or obj.get("host") or ""
    host, port, path, scheme = _split_url(url)
    return Finding(
        tool="nuclei",
        host=host or "unknown",
        port=port,
        protocol="tcp" if port is not None else None,
        service=scheme,
        kind=template_id,
        banner=name,
        url=url or None,
        path=path,
        extra={"severity": severity, "template_id": template_id},
    )


def _parse_plain(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for m in _TEXT_LINE.finditer(text):
        template = m.group("template")
        url = m.group("url").rstrip(",;]")
        key = (template, url)
        if key in seen:
            continue
        seen.add(key)
        host, port, path, scheme = _split_url(url)
        findings.append(
            Finding(
                tool="nuclei",
                host=host or "unknown",
                port=port,
                protocol="tcp" if port is not None else None,
                service=scheme or m.group("proto").lower(),
                kind=template,
                banner=template,
                url=url,
                path=path,
                extra={"severity": m.group("severity").lower(), "template_id": template},
            )
        )
    return findings


def _split_url(url: str) -> tuple[str | None, int | None, str | None, str | None]:
    if not url:
        return None, None, None, None
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port
    if port is None and parsed.scheme:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/"
    return host, port, path, parsed.scheme or None
