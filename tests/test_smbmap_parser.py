"""Parser-level checks for smbmap output."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import smbmap as smbmap_parser


def test_parse_skips_no_access_and_classifies(examples_dir: Path) -> None:
    findings = smbmap_parser.parse(examples_dir / "test_smbmap.txt")
    by_share = {f.extra["share"]: f for f in findings}

    # NO ACCESS shares must NOT appear.
    assert "ADMIN$" not in by_share
    assert "IPC$" not in by_share

    assert by_share["share"].kind == "smb-share-read"
    assert by_share["backup"].kind == "smb-share-write"
    assert by_share["scripts"].kind == "smb-share-write"

    for f in findings:
        assert f.tool == "smbmap"
        assert f.host == "10.10.11.99"
        assert f.port == 445
