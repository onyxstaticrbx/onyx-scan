#!/usr/bin/env python3
"""Check a built sdist/wheel against the published-contents allowlists.

Why this exists: the publish workflow used to carry its own copy of the sdist allowlist.
A new public module (`rojo.py`, `luau_ast.py`, `require_graph.py`) was added to the package
but not to that copy, so the publish job would have rejected its own correctly built sdist —
after the release button was pressed. The allowlist belongs in one file, and every workflow
that builds a distribution must run this check, not just the publish job.

Usage:
    python tools/check_artifacts.py dist
    python tools/check_artifacts.py dist --json
Exit: 0 = both artifacts match; 1 = a mismatch.
"""

from __future__ import annotations

import glob
import json
import sys
import tarfile
import zipfile
from pathlib import Path

#: Every module the published wheel is allowed to contain. An extra name is a leak
#: (a private module shipped by accident); a missing name is a packaging regression.
WHEEL_MODULES = {
    "onyx/__init__.py",
    "onyx/baseline.py",
    "onyx/cli.py",
    "onyx/finding_help.py",
    "onyx/lexer.py",
    "onyx/luau/__init__.py",
    "onyx/luau/harness.luau",
    "onyx/luau/mock.luau",
    "onyx/luau_ast.py",
    "onyx/place.py",
    "onyx/policy.py",
    "onyx/require_graph.py",
    "onyx/rojo.py",
    "onyx/rules.py",
    "onyx/sandbox.py",
    "onyx/scan.py",
    "onyx/verify.py",
}

#: Repository furniture plus package files. `python -m build` writes exactly this set for
#: this package; anything else in the sdist means the source tree now ships more than the
#: package, which is a leak risk until proven otherwise.
SDIST_ALLOWED = WHEEL_MODULES | {
    "pyproject.toml",
    "setup.cfg",
    "PKG-INFO",
    "LICENSE",
    "README.md",
    "README-PYPI.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "onyx_scan.egg-info/PKG-INFO",
    "onyx_scan.egg-info/SOURCES.txt",
    "onyx_scan.egg-info/dependency_links.txt",
    "onyx_scan.egg-info/entry_points.txt",
    "onyx_scan.egg-info/requires.txt",
    "onyx_scan.egg-info/top_level.txt",
}

#: Present in every good sdist; a missing one means the build dropped package data.
SDIST_REQUIRED = WHEEL_MODULES | {"pyproject.toml", "PKG-INFO"}


def check_wheel(path: Path) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = {n for n in zf.namelist() if not n.endswith("/")}
    dist_info_prefix = "onyx_scan-"
    unexpected = sorted(n for n in names
                        if n not in WHEEL_MODULES
                        and not (n.startswith(dist_info_prefix) and ".dist-info/" in n))
    missing = sorted(WHEEL_MODULES - names)
    if unexpected:
        problems.append(f"wheel has unexpected files: {unexpected}")
    if missing:
        problems.append(f"wheel is missing files: {missing}")
    if any(n.startswith(("tests/", "test/")) for n in names):
        problems.append("wheel contains test files")
    if not any(n.endswith("onyx/luau/mock.luau") for n in names):
        problems.append("wheel is missing onyx/luau/mock.luau")
    return problems


def check_sdist(path: Path) -> list[str]:
    problems: list[str] = []
    with tarfile.open(path) as tf:
        names = {m.name.split("/", 1)[1] for m in tf.getmembers()
                 if m.isfile() and "/" in m.name}
    extra = sorted(names - SDIST_ALLOWED)
    missing = sorted(SDIST_REQUIRED - names)
    if extra:
        problems.append(f"sdist has unexpected files: {extra}")
    if missing:
        problems.append(f"sdist is missing files: {missing}")
    return problems


def main(argv: list[str]) -> int:
    args = argv[1:]
    as_json = "--json" in args
    args = [a for a in args if not a.startswith("--")]
    directory = Path(args[0] if args else "dist")
    sdist = glob.glob(str(directory / "*.tar.gz"))
    wheel = glob.glob(str(directory / "*.whl"))
    problems: list[str] = []
    if not sdist:
        problems.append(f"no sdist in {directory}")
    if not wheel:
        problems.append(f"no wheel in {directory}")
    checked = {}
    if sdist:
        problems.extend(check_sdist(Path(sdist[0])))
        checked["sdist"] = Path(sdist[0]).name
    if wheel:
        problems.extend(check_wheel(Path(wheel[0])))
        checked["wheel"] = Path(wheel[0]).name
    if as_json:
        print(json.dumps({"checked": checked, "problems": problems}, indent=1))
    elif problems:
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
    else:
        print(f"artifacts ok: {checked['wheel']}, {checked['sdist']}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
