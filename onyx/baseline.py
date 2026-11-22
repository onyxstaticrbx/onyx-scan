"""Baselines: how this tool gets into a CI pipeline without a wall of red.

A studio that adopts a scanner on a mature codebase gets 400 findings on day one.
If the build goes red, the tool is uninstalled by lunchtime. A baseline says:
"these are known; fail only on what is new." That single file is the difference
between a demo and something that stays in the pipeline.

Fingerprints must be stable across edits, because a line number changes every
time someone adds a comment. A fingerprint therefore covers the rule, the file,
and the shape of the offending code, never its position.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

VERSION = 1


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def fingerprint(finding: dict) -> str:
    """Stable identity for a finding. Independent of line numbers."""
    parts = [
        str(finding.get("rule_id", "")),
        str(finding.get("path", "")),
        _normalise(finding.get("snippet", ""))[:160],
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def fingerprints_for(findings: list[dict]) -> dict[str, str]:
    return {str(id(f)): fingerprint(f) for f in findings}


def build(findings: list[dict]) -> dict:
    entries = []
    seen = set()
    for finding in findings:
        fp = fingerprint(finding)
        if fp in seen:
            continue
        seen.add(fp)
        entries.append({
            "fingerprint": fp,
            "rule_id": finding.get("rule_id"),
            "path": finding.get("path"),
            "snippet": _normalise(finding.get("snippet", ""))[:160],
        })
    entries.sort(key=lambda e: (str(e["rule_id"]), str(e["path"])))
    return {
        "version": VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "count": len(entries),
        "entries": entries,
    }


def write(path: str | Path, findings: list[dict]) -> dict:
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    payload = build(findings)
    file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def load(path: str | Path) -> dict:
    file = Path(path)
    if not file.exists():
        return {"version": VERSION, "count": 0, "entries": []}
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{file}: invalid JSON ({exc.msg}) at line {exc.lineno}") from exc
    if payload.get("version") != VERSION:
        raise ValueError(f"{file}: unsupported baseline version {payload.get('version')}")
    return payload


def known_set(payload: dict) -> set[str]:
    return {e["fingerprint"] for e in payload.get("entries", []) if e.get("fingerprint")}


def split(findings: list[dict], known: set[str]) -> dict:
    """Separate what is new from what the studio has already seen."""
    new, existing = [], []
    for finding in findings:
        target = existing if fingerprint(finding) in known else new
        target.append(finding)
    return {"new": new, "known": existing, "known_count": len(existing), "new_count": len(new)}
