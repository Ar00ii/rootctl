"""Load YAML chains and match them against parsed findings.

Loading is recursive: any `*.yaml` / `*.yml` file under the chains root is
parsed. Triggers are evaluated in pure Python and operate exclusively on the
fields of `Finding`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import yaml

from rootctl.models import (
    ChainMatch,
    ChainStep,
    CommonError,
    Finding,
    Severity,
)

# Default location for the curated knowledge base, resolved relative to the
# repository root. Can be overridden by passing an explicit path to `load_chains`.
DEFAULT_CHAINS_DIR = Path(__file__).resolve().parent.parent / "chains"


# Trigger clauses understood by the matcher. Anything outside this set is
# rejected at load time so typos do not silently disable a chain.
_VALID_TRIGGER_KEYS = frozenset({
    "tool",
    "port",
    "port_in",
    "service",
    "service_pattern",
    "product",
    "product_pattern",
    "banner_pattern",
    "path_pattern",
    "path_in",
    "status",
    "status_in",
    "kind",
    "kind_in",
    "kind_pattern",
})


@dataclass(frozen=True)
class Chain:
    """In-memory representation of a chain YAML file."""

    chain_id: str
    title: str
    severity: Severity
    tags: tuple[str, ...]
    description: str
    trigger: dict[str, Any]
    steps: tuple[ChainStep, ...]
    common_errors: tuple[CommonError, ...]
    references: tuple[str, ...]
    source_path: Path


def load_chains(root: str | Path | None = None) -> list[Chain]:
    """Recursively load every YAML chain under `root`.

    Returns chains sorted deterministically by `chain_id` so two runs over the
    same tree always evaluate matches in the same order.
    """
    base = Path(root) if root is not None else DEFAULT_CHAINS_DIR
    if not base.exists():
        return []

    chains: list[Chain] = []
    seen: set[str] = set()
    for path in sorted(base.rglob("*.y*ml")):
        if path.suffix.lower() not in (".yaml", ".yml"):
            continue
        chain = _load_chain_file(path)
        if chain.chain_id in seen:
            raise ValueError(
                f"duplicate chain_id '{chain.chain_id}' in {path}"
            )
        seen.add(chain.chain_id)
        chains.append(chain)

    chains.sort(key=lambda c: c.chain_id)
    return chains


def match(findings: Iterable[Finding], chains: Iterable[Chain]) -> list[ChainMatch]:
    """Return the chain matches produced by the given findings.

    A chain matches if at least one finding satisfies its trigger. The
    resulting list is sorted by severity (most critical first), then by
    `chain_id`, so output is stable across runs.
    """
    findings = list(findings)
    matches: list[ChainMatch] = []
    for chain in chains:
        triggered = tuple(f for f in findings if _trigger_matches(chain.trigger, f))
        if not triggered:
            continue
        matches.append(
            ChainMatch(
                chain_id=chain.chain_id,
                title=chain.title,
                severity=chain.severity,
                tags=chain.tags,
                description=chain.description,
                steps=chain.steps,
                common_errors=chain.common_errors,
                references=chain.references,
                findings=triggered,
            )
        )
    matches.sort(key=lambda m: (m.severity.rank, m.chain_id))
    return matches


# --- internals ----------------------------------------------------------------


def _load_chain_file(path: Path) -> Chain:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")

    required = ("chain_id", "title", "severity", "trigger", "description", "steps")
    missing = [k for k in required if k not in raw]
    if missing:
        raise ValueError(f"{path}: missing required keys: {missing}")

    severity = Severity(raw["severity"])
    trigger = _normalize_trigger(raw["trigger"], path)
    steps = tuple(_parse_step(s) for s in raw["steps"])
    common_errors = tuple(
        CommonError(error=str(e["error"]), solution=str(e["solution"]))
        for e in raw.get("common_errors") or []
    )

    return Chain(
        chain_id=str(raw["chain_id"]),
        title=str(raw["title"]),
        severity=severity,
        tags=tuple(str(t) for t in raw.get("tags") or ()),
        description=str(raw["description"]).strip(),
        trigger=trigger,
        steps=steps,
        common_errors=common_errors,
        references=tuple(str(r) for r in raw.get("references") or ()),
        source_path=path,
    )


def _parse_step(raw: dict[str, Any]) -> ChainStep:
    return ChainStep(
        id=int(raw["id"]),
        title=str(raw["title"]),
        command=str(raw["command"]).strip() if raw.get("command") else None,
        notes=str(raw["notes"]).strip() if raw.get("notes") else None,
    )


def _normalize_trigger(raw: Any, path: Path) -> dict[str, Any]:
    """Validate trigger structure and return it as a normalized dict.

    Two forms are accepted:
      - a plain mapping with one or more clause keys (AND between them)
      - a mapping with a single `any_of` key holding a list of clause mappings
        (OR between list entries, AND inside each entry)
    """
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: trigger must be a mapping")

    if "any_of" in raw:
        if set(raw.keys()) != {"any_of"}:
            raise ValueError(f"{path}: 'any_of' trigger cannot mix with other keys")
        clauses = raw["any_of"]
        if not isinstance(clauses, list) or not clauses:
            raise ValueError(f"{path}: 'any_of' must be a non-empty list")
        normalized = []
        for clause in clauses:
            if not isinstance(clause, dict):
                raise ValueError(f"{path}: each 'any_of' entry must be a mapping")
            _validate_clause(clause, path)
            normalized.append(dict(clause))
        return {"any_of": normalized}

    _validate_clause(raw, path)
    return dict(raw)


# Trigger keys whose value is a regex string. Compiled at load time so a
# malformed pattern surfaces in `rootctl validate`, not the first time the
# chain happens to evaluate against a real finding.
_REGEX_TRIGGER_KEYS = frozenset({
    "service_pattern",
    "product_pattern",
    "banner_pattern",
    "path_pattern",
    "kind_pattern",
})


def _validate_clause(clause: dict[str, Any], path: Path) -> None:
    unknown = set(clause.keys()) - _VALID_TRIGGER_KEYS
    if unknown:
        raise ValueError(f"{path}: unknown trigger keys {sorted(unknown)}")
    for key in _REGEX_TRIGGER_KEYS & clause.keys():
        try:
            _re(clause[key])
        except re.error as e:
            raise ValueError(f"{path}: invalid regex for {key!r}: {e}") from e


def _trigger_matches(trigger: dict[str, Any], finding: Finding) -> bool:
    if "any_of" in trigger:
        return any(_clause_matches(c, finding) for c in trigger["any_of"])
    return _clause_matches(trigger, finding)


def _clause_matches(clause: dict[str, Any], f: Finding) -> bool:
    """All conditions in `clause` must hold for the finding."""
    if "tool" in clause and clause["tool"] != f.tool:
        return False
    if "port" in clause and clause["port"] != f.port:
        return False
    if "port_in" in clause:
        ports = clause["port_in"]
        if f.port is None or f.port not in ports:
            return False
    if "service" in clause:
        if (f.service or "").lower() != str(clause["service"]).lower():
            return False
    if "service_pattern" in clause:
        if not f.service or not _re(clause["service_pattern"]).search(f.service):
            return False
    if "product" in clause:
        if not f.product or str(clause["product"]).lower() not in f.product.lower():
            return False
    if "product_pattern" in clause:
        if not f.product or not _re(clause["product_pattern"]).search(f.product):
            return False
    if "banner_pattern" in clause:
        if not f.banner or not _re(clause["banner_pattern"]).search(f.banner):
            return False
    if "path_pattern" in clause:
        if not f.path or not _re(clause["path_pattern"]).search(f.path):
            return False
    if "path_in" in clause:
        paths = clause["path_in"]
        if f.path is None or f.path not in paths:
            return False
    if "status" in clause and clause["status"] != f.status_code:
        return False
    if "status_in" in clause:
        codes = clause["status_in"]
        if f.status_code is None or f.status_code not in codes:
            return False
    if "kind" in clause and clause["kind"] != f.kind:
        return False
    if "kind_in" in clause:
        kinds = clause["kind_in"]
        if f.kind is None or f.kind not in kinds:
            return False
    if "kind_pattern" in clause:
        if not f.kind or not _re(clause["kind_pattern"]).search(f.kind):
            return False
    return True


@lru_cache(maxsize=512)
def _re(pattern: str) -> re.Pattern[str]:
    """Cache compiled regexes — chains reuse the same patterns across runs."""
    return re.compile(pattern, re.IGNORECASE)
