"""Parser for ffuf output.

Accepts ffuf's `-of json` machine-readable output:

  {
    "commandline": "ffuf -u http://target/FUZZ -w wordlist.txt",
    "time": "...",
    "results": [
      {
        "input": {"FUZZ": "admin"},
        "position": 0,
        "status": 200,
        "length": 1234,
        "words": 100,
        "lines": 50,
        "url": "http://target/admin",
        "host": "target"
      }
    ]
  }

Each result becomes a Finding with the same surface as the gobuster parser
(tool, host, port, service, path, status_code, url) so the existing web
chains (wordpress, login form, php upload, sqli) fire on ffuf output too.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from rootctl.models import Finding


def parse(path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)


def parse_text(text: str) -> list[Finding]:
    obj = json.loads(text)
    results = obj.get("results") or []
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for r in results:
        url = r.get("url") or ""
        status = int(r.get("status") or 0)
        if not url or status == 0:
            continue
        key = (url, status)
        if key in seen:
            continue
        seen.add(key)

        parsed = urlparse(url)
        host = parsed.hostname or r.get("host") or "unknown"
        port = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80
        path = parsed.path or "/"
        findings.append(
            Finding(
                tool="ffuf",
                host=host,
                port=port,
                protocol="tcp" if port is not None else None,
                service=parsed.scheme or "http",
                url=url,
                path=path,
                status_code=status,
                extra={"length": str(r.get("length", 0)), "words": str(r.get("words", 0))},
            )
        )
    return findings
