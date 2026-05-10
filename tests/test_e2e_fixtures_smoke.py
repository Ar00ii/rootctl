"""Smoke test: every shipped fixture must analyze without crashing.

This is a drag-net guard. Individual parser tests assert structure; this
one asserts the full CLI pipeline (parser + extractor + matcher + reporter
+ JSON serializer) survives every fixture we ship — so a regression in,
say, the JSON encoder shows up here even if no parser test changed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rootctl.cli import app

runner = CliRunner()


def _fixtures(examples_dir: Path) -> list[Path]:
    return sorted(
        p
        for p in examples_dir.iterdir()
        if p.is_file() and p.suffix.lower() in {".xml", ".txt", ".json", ".jsonl"}
    )


@pytest.mark.parametrize("fixture_name", [p.name for p in _fixtures(Path(__file__).resolve().parent.parent / "examples")])
def test_analyze_every_fixture(examples_dir: Path, fixture_name: str) -> None:
    fixture = examples_dir / fixture_name
    result = runner.invoke(app, ["analyze", "--json", str(fixture)])
    assert result.exit_code == 0, f"{fixture_name}: {result.stdout}"
    payload = json.loads(result.stdout)
    assert {"findings", "matches", "extracts"} <= payload.keys()
