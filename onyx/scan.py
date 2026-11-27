"""Scan orchestration: place file -> report dict. No model calls, no network."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from .place import Place, PlaceParseError, load_place
from .rules import SEVERITY_ORDER, ScanResult, scan_place

ENGINE = "onyx-static"
ENGINE_VERSION = "0.3.0"


class ScanError(Exception):
    pass


def _replay_id(place: Place, findings: list[dict]) -> str:
    """Identity of a scan: derived from content, never from the local file path.

    The path is deliberately excluded: the same bytes read from a different directory
    must produce the same id, or provenance and evidence links break the moment the file
    moves.
    """
    h = hashlib.sha256()
    for inst in sorted(place.instances, key=lambda i: i.path):
        if inst.is_script:
            source = inst.source or ""
            h.update(f"{inst.path}\x00{inst.class_name}\x00{source}\x00".encode())
    for f in findings:
        h.update(f"{f['rule_id']}:{f['path']}:{f['line']}".encode())
    return h.hexdigest()[:16]


NUMERIC_PLACE = ("instances", "scripts", "client_scripts", "server_scripts", "modules",
                 "remotes", "client_reachable_remotes")
NUMERIC_COVERAGE = ("client_reachable_remotes", "remotes_referenced",
                    "handlers_without_validation", "scripts_scanned", "lines_scanned",
                    "scripts_not_analyzed")
SEVERITIES = ("critical", "high", "medium", "low", "info")
#: A single place scan is bounded so a hostile or enormous project returns a partial,
#: counted report instead of hanging a CI job. CLI may override with --time-budget.
DEFAULT_TIME_BUDGET = 120.0


def combine(reports: list[dict], names: list[str]) -> dict:
    """Merge several place scans into one report for a multi-place engagement.

    Each finding's `path` is prefixed with the file it came from. That is not
    cosmetic: identity (and therefore retest and baseline matching) is derived from
    rule + path + snippet, so two places containing the same line must not collapse
    into one finding.
    """
    if not reports:
        raise ScanError("no reports to combine")
    if len(reports) == 1:
        return reports[0]

    findings: list[dict] = []
    counts = {sev: 0 for sev in SEVERITIES}
    coverage = {key: 0 for key in NUMERIC_COVERAGE}
    place: dict = {"path": f"{len(reports)} place(s)", **{key: 0 for key in NUMERIC_PLACE}}
    for report, name in zip(reports, names, strict=False):
        for finding in report.get("findings", []):
            merged = dict(finding)
            merged["path"] = f"{name}::{finding.get('path', '')}"
            merged["place"] = name
            findings.append(merged)
            counts[merged.get("severity", "info")] = counts.get(merged.get("severity", "info"), 0) + 1
        for key in NUMERIC_COVERAGE:
            coverage[key] += int(report.get("coverage", {}).get(key) or 0)
        for key in NUMERIC_PLACE:
            place[key] += int(report.get("place", {}).get(key) or 0)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9), f["path"], f["line"]))
    joined = "|".join(str(r.get("replay_id", "")) for r in reports)
    first = reports[0]
    return {
        "replay_id": hashlib.sha256(joined.encode()).hexdigest()[:16],
        "kind": first.get("kind", "scan"),
        "engine": first.get("engine", ""),
        "engine_version": first.get("engine_version", ""),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "language": first.get("language", "luau"),
        "place": place,
        "headline": (f"{len(findings)} finding(s) across {len(reports)} place(s): "
                     + ", ".join(f"{n} ({len(r.get('findings', []))})"
                                 for n, r in zip(names, reports, strict=False))),
        "counts": counts,
        "coverage": coverage,
        "findings": findings,
        "provenance": {
            "method": "static analysis",
            "executed": False,
            "note": (
                "Findings describe code patterns. Paths are prefixed with the file they "
                "came from so that identical lines in different places stay distinct. No "
                "finding is marked confirmed until it has been executed."
            ),
            "places": list(names),
        },
    }


def scan_source(source: str, *, class_name: str = "Script",
                path: str = "public/script.luau",
                budget_seconds: float | None = DEFAULT_TIME_BUDGET):
    """Scan one script's text. Used for public-code measurement and for tests.

    A loose file has no place around it, so place-level rules (orphan remotes,
    bindables in ReplicatedStorage) cannot fire and are not reported here.
    """
    from .place import Instance, Place
    from .rules import scan_place

    root = Instance(class_name="DataModel", name="game", path="game")
    inst = Instance(
        class_name=class_name, name=Path(path).stem,
        path=f"game.{class_name}.{Path(path).stem}", source=source,
    )
    inst.parent = root
    root.children.append(inst)
    return scan_place(Place(path=path, root=root, instances=[inst]),
                      budget_seconds=budget_seconds)


def load_input(path: str | Path) -> Place:
    """Load a place file or a Rojo project directory into one Place model.

    The caller should not care which input produced the Place; rules and the emulator
    both see the same instance tree.
    """
    p = Path(path)
    if p.is_dir() or p.name.endswith(".project.json"):
        from .rojo import load_rojo_project
        try:
            return load_rojo_project(p)
        except PlaceParseError as exc:
            raise ScanError(str(exc)) from exc
    try:
        return load_place(p)
    except PlaceParseError as exc:
        raise ScanError(str(exc)) from exc


def scan_file(path: str | Path, *, budget_seconds: float | None = DEFAULT_TIME_BUDGET) -> dict:
    try:
        place = load_input(path)
    except PlaceParseError as exc:
        raise ScanError(str(exc)) from exc

    result: ScanResult = scan_place(place, budget_seconds=budget_seconds)
    findings = [f.to_dict() for f in result.findings]

    counts = result.counts()
    critical = [f for f in findings if f["severity"] == "critical"]

    # The one line a human reads first. Severity framing, not counts. A partial read
    # (skipped source, unresolved require, parser fallback) must not read as "clean".
    partial = []
    cov = result.coverage
    if int(cov.get("require_unresolved") or 0):
        partial.append(f"{int(cov['require_unresolved'])} unresolved require(s)")
    if int(cov.get("scripts_skipped") or 0):
        partial.append(f"{int(cov['scripts_skipped'])} skipped source file(s)")
    if int(cov.get("module_parse_failures") or 0):
        partial.append(f"{int(cov['module_parse_failures'])} parser fallback(s)")
    if cov.get("module_analysis_error"):
        partial.append("module analysis failed")
    if cov.get("time_budget_exceeded"):
        shown_budget = budget_seconds if budget_seconds is not None else DEFAULT_TIME_BUDGET
        partial.append(
            f"time budget {shown_budget:g}s exceeded; "
            f"{int(cov.get('scripts_not_analyzed') or 0)} script(s) not analyzed"
        )
    if critical:
        headline = (
            f"{len(critical)} critical issue{'s' if len(critical) != 1 else ''} "
            f"found in {cov['scripts_scanned']} scripts"
        )
    elif partial:
        headline = (
            f"No critical issues found in {cov['scripts_scanned']} scripts — partial scan: "
            + ", ".join(partial)
        )
    else:
        headline = f"No critical issues in {cov['scripts_scanned']} scripts"

    return {
        "replay_id": _replay_id(place, findings),
        "kind": "scan",
        "engine": ENGINE,
        "engine_version": ENGINE_VERSION,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "language": "luau",
        "place": result.place_summary,
        "headline": headline,
        "counts": counts,
        "coverage": {**result.coverage,
                     "time_budget_seconds": budget_seconds},
        "findings": findings,
        # Honesty flag. Static analysis reports code patterns, not demonstrated
        # exploits. Nothing here is "confirmed" until it is executed and recorded.
        "provenance": {
            "method": "static analysis",
            "executed": False,
            "note": (
                "Findings describe code patterns. No finding is marked confirmed "
                "until it has been executed and recorded in a replay."
            ),
        },
    }


def show_name(report: dict) -> str:
    critical = report["counts"].get("critical", 0)
    high = report["counts"].get("high", 0)
    if critical:
        return f"{critical} critical"
    if high:
        return f"{high} high"
    return "clean"


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["path"], f["line"]))
