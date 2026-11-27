"""Public CLI for the scanner: scan, verify, baseline, rules.

This is the command surface of the published package. The private workspace keeps the larger
CLI internal; those modules do not ship, so this file
must not import them and must not grow commands that depend on them.

    onyx scan place.rbxlx [--json out.json] [--baseline FILE --fail-on-new]
    onyx verify place.rbxlx [--json out.json] [--luau PATH]
    onyx baseline place.rbxlx [-o FILE]
    onyx rules

Exit codes: 0 clean/success, 1 usage or read error, 2 gate failure (critical finding, or a
finding that breaks the baseline gate).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import baseline as baseline_mod
from . import sandbox
from . import finding_help
from . import policy as policy_mod
from . import rules as rules_mod
from .scan import ScanError, scan_file
from .verify import VerifyError, find_luau, luau_missing_hint, to_report, verify_place


def _enrich(report: dict) -> None:
    """Attach the check, the measured label and the paste-ready prompt to every finding."""
    for f in report.get("findings", []):
        rid = f.get("rule_id", "")
        f["check"] = finding_help.check_for(rid)
        f["precision"] = (finding_help.precision_for(rid) if f.get("measured", True)
                          else finding_help.PRECISION_FALLBACK)
        f["prompt"] = finding_help.prompt_for(f)


def _coverage_notes(report: dict) -> list[str]:
    """Facts that make a zero-finding report not a clean report."""
    cov = report.get("coverage", {})
    notes: list[str] = []
    source = cov.get("source") or {}
    skipped = int(cov.get("scripts_skipped") or 0)
    if skipped:
        reasons = source.get("skipped") or []
        if reasons:
            notes.append(f"{skipped} source file(s) skipped: " + "; ".join(reasons[:3]))
        else:
            notes.append(f"{skipped} source file(s) skipped — see coverage JSON")
    unsupported = source.get("unsupported") or []
    if unsupported:
        notes.append(f"{len(unsupported)} unsupported project feature(s): "
                     + "; ".join(unsupported[:3]))
    failures = int(cov.get("module_parse_failures") or 0)
    if failures:
        notes.append(f"{failures} script(s) fell back to the token parser")
    unresolved = int(cov.get("require_unresolved") or 0)
    if unresolved:
        notes.append(f"{unresolved} require reference(s) unresolved")
    analysis_error = cov.get("module_analysis_error")
    if analysis_error:
        notes.append(f"module analysis failed ({analysis_error}); cross-file paths were not checked")
    if cov.get("time_budget_exceeded"):
        notes.append(
            f"time budget {cov.get('time_budget_seconds', 120):g}s exceeded; "
            f"{int(cov.get('scripts_not_analyzed') or 0)} script(s) not analyzed — the result is partial"
        )
    return notes


def _print_human(report: dict) -> None:
    print(f"\n  {report['headline']}")
    place = report["place"]
    cov = report["coverage"]
    print(
        f"  {place['scripts']} scripts · {cov['lines_scanned']:,} lines · "
        f"{place['client_reachable_remotes']} client-reachable remotes"
    )
    for note in _coverage_notes(report):
        print(f"  coverage: {note}")
    print()
    if not report["findings"]:
        print("  No findings.\n")
        return
    for f in report["findings"]:
        sev = f["severity"].upper().ljust(8)
        print(f"  [{sev}] {f['rule_id']}  {f['path']}:{f['line']}")
        print(f"           {f['title']}")
        print(f"           {f['consequence']}")
        if f.get("check"):
            print(f"           check      {f['check']}")
        if f.get("precision"):
            p = f["precision"]
            print(f"           precision  {p['label']} — {p['plain']}")
        print()
    counts = ", ".join(f"{v} {k}" for k, v in report["counts"].items() if v)
    print(f"  {counts}\n")


def _scan(args) -> int:
    try:
        report = scan_file(args.place, budget_seconds=args.time_budget)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _enrich(report)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not args.quiet:
        _print_human(report)
        if report.get("findings"):
            print("  Precision labels were measured on the 0.2.2 engine "
                  "(the author's own measurement), not an external audit — how to read "
                  "the labels, with intervals:")
            print("  https://github.com/onyxstaticrbx/onyx-scan#precision\n")
    if args.prompt:
        for f in report["findings"]:
            print(f"  FIX PROMPT — {f['rule_id']}  {f['path']}:{f['line']}")
            print("  " + f["prompt"].replace("\n", "\n  ") + "\n")

    if args.fail_on_critical and report["counts"].get("critical", 0):
        return 2

    if args.baseline_path or args.fail_on_new:
        policy = policy_mod.load(None)
        applied = policy_mod.apply(policy, report["findings"],
                                   baseline_mod.fingerprints_for(report["findings"]))
        candidates = applied["findings"]
        baseline_path = Path(args.baseline_path) if args.baseline_path else Path(".onyx-baseline.json")
        if baseline_path.exists() or args.fail_on_new:
            known = baseline_mod.known_set(baseline_mod.load(baseline_path))
            split = baseline_mod.split(candidates, known)
            if args.fail_on_new:
                candidates = split["new"]
            if not args.quiet:
                print(f"  baseline: {split['known_count']} known · {split['new_count']} new"
                      f"  ({baseline_path})")
        failing = policy_mod.failing(policy, candidates)
        if failing:
            print(f"  FAIL: {len(failing)} finding(s) at or above `{policy['fail_on']}`\n",
                  file=sys.stderr)
            for f in failing[:10]:
                print(f"    {f['severity']:<8} {f['rule_id']}  {f['path']}:{f['line']}",
                      file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"  PASS: nothing at or above `{policy['fail_on']}`\n")
    return 0


def _verify(args) -> int:
    if sandbox.is_windows():
        print(f"error: {sandbox.WINDOWS_VERIFY_UNSUPPORTED}", file=sys.stderr)
        return 1
    if find_luau() is None and not args.luau:
        print(f"error: {luau_missing_hint()}", file=sys.stderr)
        return 1
    try:
        static = scan_file(args.place)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"  {static['headline']}")
    print("  executing under the emulator …")
    try:
        result = verify_place(args.place, luau_bin=args.luau)
    except (VerifyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    report = to_report(result, static, args.place)
    remotes = report.get("remotes_fuzzed", len(result.remotes))
    per_remote = report.get("payloads_per_remote", 0)
    print(f"  executed on Luau · {remotes} remote(s) × {per_remote} payloads = "
          f"{remotes * per_remote} client actions\n")
    if not result.confirmed:
        print("  No exploit confirmed. Static findings remain unproven.\n")
    for c in result.confirmed:
        print(f"  [CONFIRMED {c['severity'].upper()}] {c['rule_id']}  {c['remote']}")
        print(f"     {c['claim']}")
        ev = c.get("evidence") or {}
        for m in ev.get("moves", []):
            print(f"     move  {m.get('label', '?')}: {m.get('key', '?')} "
                  f"{m.get('before')} -> {m.get('after')}")
        print()
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.fail_on_confirmed and result.confirmed:
        return 2
    return 0


def _baseline(args) -> int:
    try:
        report = scan_file(args.place, budget_seconds=getattr(args, "time_budget", 120.0))
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out) if args.out else Path(".onyx-baseline.json")
    payload = baseline_mod.write(out, report["findings"])
    print(f"\n  baseline written · {payload['count']} finding(s) recorded as known")
    print(f"  {out}\n")
    print("  CI now fails only on findings that are not in this file.\n")
    return 0


def _rules() -> int:
    for rule in rules_mod.SCRIPT_RULES:
        ids = finding_help.RULE_FUNCTIONS.get(rule.__name__)
        if not ids:
            continue
        doc = (rule.__doc__ or "").strip().splitlines()
        desc = doc[0] if doc else finding_help.RULE_TITLES.get(rule.__name__, "")
        print(f"{', '.join(ids):22} {desc}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="onyx", description="Static exploit scan for Roblox places")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan a .rbxlx / .rbxmx file or a Rojo project")
    sp.add_argument("place", help="path to .rbxlx, .rbxmx, a Rojo project directory, or a .project.json")
    sp.add_argument("--json", dest="json_out", help="write raw report JSON here")
    sp.add_argument("--fail-on-critical", action="store_true", help="exit 2 if any critical found")
    sp.add_argument("--baseline", dest="baseline_path", default=None,
                    help="baseline file; findings already in it are not 'new'")
    sp.add_argument("--fail-on-new", action="store_true",
                    help="exit 2 only for findings that are not in the baseline")
    sp.add_argument("--time-budget", type=float, default=120.0, metavar="SECONDS",
                    help="wall-clock budget for one place scan; on expiry the report is partial "
                         "and says which scripts were not analyzed (default: 120)")
    sp.add_argument("--quiet", action="store_true")
    sp.add_argument("--prompt", action="store_true",
                    help="print a paste-ready fix prompt for every finding")

    vp = sub.add_parser("verify", help="execute a place against the emulator and confirm what is real")
    vp.add_argument("place", help="path to .rbxlx, .rbxmx, a Rojo project directory, or a .project.json")
    vp.add_argument("--json", dest="json_out", help="write verification report JSON here")
    vp.add_argument("--luau", default=None, help="path to a luau interpreter (default: auto-detect)")
    vp.add_argument("--fail-on-confirmed", action="store_true",
                    help="exit 2 if any exploit is confirmed (for CI)")

    bp = sub.add_parser("baseline", help="record the current findings as known")
    bp.add_argument("place", help="path to .rbxlx, .rbxmx, a Rojo project directory, or a .project.json")
    bp.add_argument("-o", "--out", default=None, help="baseline path (default: .onyx-baseline.json)")

    sub.add_parser("rules", help="list every rule id and what it catches")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        return _scan(args)
    if args.cmd == "verify":
        return _verify(args)
    if args.cmd == "baseline":
        return _baseline(args)
    return _rules()


if __name__ == "__main__":
    raise SystemExit(main())
