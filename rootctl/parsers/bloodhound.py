"""Parser for BloodHound JSON dumps (users.json, computers.json, groups.json).

BloodHound flattens AD into JSON. This parser keeps the surface narrow:
  - User where Properties.asreproastable is true  → kind="ad-asreproast-target"
  - User where Properties.kerberoastable is true  → kind="ad-kerberoastable-target"
  - User where Properties.unconstraineddelegation → kind="ad-unconstrained-user"
  - User where Properties.admincount == 1         → kind="ad-admincount"
  - Computer where unconstraineddelegation        → kind="ad-unconstrained-computer"
  - Any user record                               → kind="ad-user" (matches existing chain)

A typical bloodhound-python collection produces multiple JSON files. Run
this parser on each individually, or pass them all to `rootctl analyze`
in one call.
"""

from __future__ import annotations

import json
from pathlib import Path

from rootctl.models import Finding


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    obj = json.loads(text)
    meta = obj.get("meta") or {}
    data = obj.get("data") or []
    type_hint = (meta.get("type") or "").lower()

    findings: list[Finding] = []
    for entry in data:
        props = entry.get("Properties") or {}
        name = props.get("name") or props.get("samaccountname") or ""
        domain = props.get("domain") or ""
        if type_hint == "computers":
            findings.extend(_findings_for_computer(name, domain, props))
        else:
            findings.extend(_findings_for_user(name, domain, props))
    return findings


def _findings_for_user(name: str, domain: str, p: dict) -> list[Finding]:
    out: list[Finding] = []
    sam = p.get("samaccountname") or name.split("@", 1)[0]

    # Always emit a generic ad-user so user_list_to_attacks fires too.
    if sam and sam.lower() not in {"krbtgt", "guest"}:
        out.append(_user_finding(sam, domain, "ad-user", p))

    if p.get("asreproastable"):
        out.append(_user_finding(sam, domain, "ad-asreproast-target", p))
    if p.get("kerberoastable"):
        out.append(_user_finding(sam, domain, "ad-kerberoastable-target", p))
    if p.get("unconstraineddelegation"):
        out.append(_user_finding(sam, domain, "ad-unconstrained-user", p))
    if p.get("admincount"):
        out.append(_user_finding(sam, domain, "ad-admincount", p))
    return out


def _findings_for_computer(name: str, domain: str, p: dict) -> list[Finding]:
    out: list[Finding] = []
    short = name.split(".", 1)[0]
    if p.get("unconstraineddelegation"):
        out.append(
            Finding(
                tool="bloodhound",
                host="local",
                kind="ad-unconstrained-computer",
                banner=short,
                extra={"computer": short, "domain": domain, "os": p.get("operatingsystem", "") or ""},
            )
        )
    return out


def _user_finding(sam: str, domain: str, kind: str, p: dict) -> Finding:
    return Finding(
        tool="bloodhound",
        host="local",
        kind=kind,
        banner=sam,
        extra={
            "user": sam,
            "domain": domain,
            "enabled": str(p.get("enabled", "")),
            "displayname": p.get("displayname", "") or "",
        },
    )
