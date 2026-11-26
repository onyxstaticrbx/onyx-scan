#!/usr/bin/env python3
"""Fail the gate if a tree ships private identifiers.

An early audit found leaks by hand (a private place hash and two internal workspace paths
left in comments). A careful manual grep means the fourth leak is found by a stranger, so
this runs the same checks as a test over the assembled tree.

Scope, stated honestly: a clean result means none of the known patterns matched. It is not
proof that nothing private shipped - it is the checks we know to make.

The private identifier lists (account handles, place ids, private place hashes) are NOT in
this file: a checker that ships the very handles it looks for is its own leak. They are
supplied from local files that stay on the maintainer's machine:

    python tools/leak_check.py --tree . --handles ~/.onyx/handles.txt \
        --place-ids ~/.onyx/place-ids.txt --hashes ~/.onyx/hashes.txt

One identifier per line; empty lines and lines starting with `#` are ignored. The
maintainer's private edition of this tool also checks internal business vocabulary whose
word list is itself private, so that part is deliberately not in this public copy.

Usage:
    python tools/leak_check.py --tree .
    python tools/leak_check.py --tree . --json
    python tools/leak_check.py --tree . --no-git
Exit: 0 = no finding; 1 = finding(s); 2 = tree/list file problem.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

#: public identity, allowed to appear (LICENSE holder and repository URL)
PUBLIC_HANDLE = "onyxstaticrbx"

#: generic long-hex (32, 40, 64 chars - sha1/sha256 and similar digests)
LONG_HASH = re.compile(r"\b[0-9a-f]{32,}\b")
#: bytes that make a file non-text; a file with NUL is not scanned as text
NUL = b"\x00"

PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "key": re.compile(
        r"sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}"
        r"|AKIA[0-9A-Z]{12,}|pypi-[A-Za-z0-9_-]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}"
        r"|-----BEGIN [A-Z ]+-----"
    ),
    "bearer": re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}"),
    # Split so this file does not match its own pattern.
    "user-path": re.compile(r"/roo" r"t/|/hom" r"e/|/" r"Users/|/va" r"r/www"),
}

PLACE_SUFFIXES = {".rbxlx", ".rbxm", ".rbxl"}
#: two deliberately public demo fixtures; every other place file is a finding
ALLOWED_PLACE_FILES = {"examples/demo_addcash_before.rbxlx",
                       "examples/demo_addcash_after.rbxlx"}

SKIP_DIRS = {".git", "dist", "build", "__pycache__"}
TEXT_LIMIT = 4 * 1024 * 1024


def _read_list(path: str | None) -> list[str]:
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"no list file at {p}")
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def scan_tree(tree: Path, handles: list[str], place_ids: list[str],
              hashes: list[str]) -> tuple[list[dict], int]:
    findings: list[dict] = []
    checked = 0
    hash_re = (re.compile(r"\b(?:%s)\b" % "|".join(map(re.escape, sorted(hashes))))
               if hashes else None)
    id_res = {pid: re.compile(rf"\b{pid}\b") for pid in place_ids}
    for path in sorted(tree.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(tree)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if any(part.endswith(".egg-info") for part in rel.parts):
            continue
        if path.suffix.lower() in PLACE_SUFFIXES and rel.as_posix() not in ALLOWED_PLACE_FILES:
            findings.append({"file": str(rel), "line": 0, "kind": "place-file",
                             "match": path.name})
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > TEXT_LIMIT or NUL in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        checked += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            for name, pattern in PATTERNS.items():
                m = pattern.search(line)
                if m:
                    findings.append({"file": str(rel), "line": lineno, "kind": name,
                                     "match": m.group(0)[:80]})
            m = LONG_HASH.search(line)
            if m:
                findings.append({"file": str(rel), "line": lineno, "kind": "private-hash",
                                 "match": m.group(0)[:80]})
            if hash_re:
                m = hash_re.search(line)
                if m:
                    findings.append({"file": str(rel), "line": lineno, "kind": "private-hash",
                                     "match": m.group(0)})
            for handle in handles:
                if handle.lower() in low:
                    findings.append({"file": str(rel), "line": lineno, "kind": "handle",
                                     "match": handle})
            for pid, rx in id_res.items():
                if rx.search(line):
                    findings.append({"file": str(rel), "line": lineno, "kind": "place-id",
                                     "match": pid})
    return findings, checked


def check_git_authors(tree: Path, handle: str = PUBLIC_HANDLE) -> list[dict]:
    """Pre-push: every commit author must be the GitHub no-reply identity."""
    if not (tree / ".git").exists():
        return []
    try:
        run = subprocess.run(["git", "-C", str(tree), "log", "--format=%an <%ae>"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return [{"file": ".git", "line": 0, "kind": "commit-author",
                 "match": f"cannot read git log: {exc}"}]
    if run.returncode != 0:
        return [{"file": ".git", "line": 0, "kind": "commit-author",
                 "match": "git log failed: " + (run.stderr.strip()[:120] or "no commits")}]
    allowed = re.compile(rf"(?:\d+\+)?{re.escape(handle)}@users\.noreply\.github\.com$")
    out: list[dict] = []
    for line in run.stdout.splitlines():
        if not line.strip():
            continue
        m = re.fullmatch(r"(.*?)\s*<([^>]*)>", line)
        name, email = (m.group(1), m.group(2)) if m else ("", line)
        if not name or not allowed.fullmatch(email):
            out.append({"file": ".git", "line": 0, "kind": "commit-author",
                        "match": line.strip()[:120]})
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="check a tree for private identifiers")
    ap.add_argument("--tree", required=True)
    ap.add_argument("--handles", default=None, help="file of private handles, one per line")
    ap.add_argument("--place-ids", default=None, help="file of private place ids")
    ap.add_argument("--hashes", default=None, help="file of private place hashes")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-git", action="store_true", help="skip the commit-author check")
    args = ap.parse_args(argv[1:])
    tree = Path(args.tree)
    if not tree.is_dir():
        print(f"no tree at {tree}", file=sys.stderr)
        return 2
    findings, checked = scan_tree(tree, _read_list(args.handles),
                                  _read_list(args.place_ids), _read_list(args.hashes))
    if not args.no_git:
        findings += check_git_authors(tree)
    if args.json:
        print(json.dumps(findings, indent=1))
    elif findings:
        for f in findings[:40]:
            print(f"{f['file']}:{f['line']}  {f['kind']}  {f['match']}")
        print(f"{len(findings)} finding(s) - the tree is not clean")
    else:
        print(f"clean: {checked} text files; no place ids, private hashes, handles, "
              "emails, keys, bearer tokens or user paths")
        print("note: clean means none of the known patterns matched, not that nothing "
              "private shipped.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
