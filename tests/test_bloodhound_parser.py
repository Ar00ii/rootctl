"""Parser-level checks for BloodHound JSON dumps."""

from __future__ import annotations

from pathlib import Path

from rootctl.parsers import bloodhound as bh_parser


def test_parse_users_emits_specific_kinds(examples_dir: Path) -> None:
    findings = bh_parser.parse(examples_dir / "test_bloodhound_users.json")
    by_kind: dict[str, list[str]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f.banner)

    assert by_kind["ad-asreproast-target"] == ["alice"]
    assert by_kind["ad-kerberoastable-target"] == ["svc_sql"]
    assert by_kind["ad-unconstrained-user"] == ["admin_jdoe"]
    assert by_kind["ad-admincount"] == ["admin_jdoe"]
    # Plus a generic ad-user entry per principal.
    assert set(by_kind["ad-user"]) == {"alice", "svc_sql", "admin_jdoe"}


def test_parse_computers_unconstrained() -> None:
    text = (
        '{"data": [{"ObjectIdentifier":"S-1-5-21-1-2-3-4","Properties":'
        '{"name":"DC01.HTB.LOCAL","domain":"HTB.LOCAL","unconstraineddelegation":true,'
        '"operatingsystem":"Windows Server 2019"}}],'
        '"meta":{"type":"computers","count":1,"version":5}}'
    )
    findings = bh_parser.parse_text(text)
    kinds = {f.kind for f in findings}
    assert "ad-unconstrained-computer" in kinds
    target = next(f for f in findings if f.kind == "ad-unconstrained-computer")
    assert target.banner == "DC01"
    assert target.extra["os"] == "Windows Server 2019"
