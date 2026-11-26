# Changelog

Notable changes to `onyx-scan`. The version in each heading matches the `version` field in
`pyproject.toml`, the `MEASURED_AS_OF` label in `onyx/finding_help.py`, and the footer printed by
the scanner.

## 0.3.0 (unreleased)

Rojo project input, a pure-Python Luau AST parser, and resolved cross-file require
support. Existing rule ids stay the same; the new cross-file shape is L001 when a
handler delegates to a resolved ModuleScript function that writes state.

- `onyx scan <dir>` accepts a Rojo project directory (or `*.project.json`) and maps it to
the same `Place` model as XML. `verify` consumes the same model.
- Hostile directory input is bounded: no symlinks, no `$path` escape, caps on files,
source bytes, nesting and total source. Skipped files and unresolved requires are
reported, not silently dropped.
- A real AST parser (`onyx/luau_ast.py`) supports statements, expressions, types,
string interpolation, generics and Luau syntax used by place scripts. On a parse
failure the scan falls back to the token path and counts the fallback in coverage.
- `onyx/require_graph.py` resolves `script.Parent.X`, `game.ReplicatedStorage...`,
`GetService`, `WaitForChild`/`FindFirstChild` and simple local aliases. Numeric,
asset and dynamic requires are counted as unresolved.
- The 0.2.2 precision labels are unchanged and still describe the token engine; the
cross-file L001 extension has no measured rate yet and is printed as a low-severity
lead (medium confidence), so `--fail-on-critical` cannot fail on it.
- `scan` has a wall-clock budget (default 120 s, `--time-budget`); expiry returns a partial
report with a coverage note instead of hanging. The parser bounds source bytes, tokens,
nodes, expression depth and per-script time, and any exceeded limit becomes a counted
fallback, not a crash.
- The cross-module README claim now says one hop through simple `require` forms is
resolved and the rest is counted as unresolved; the precision footer says the labels were
measured on the 0.2.2 engine.
- Coverage reports `require_by_pattern`: resolved and unresolved one-hop `require` calls
by syntactic shape (`script.Parent.child`, `game:GetService.child`, `local alias.child`,
`numeric asset id`, ...). An unresolved total now names the forms, so a partial read can
say which shapes the scanner understands.
- The publish allowlist moved to `tools/check_artifacts.py` and runs in `test-linux` and
`test-windows` as well as at publish, so a public module missing from it fails on the pull
request instead of after the release button is pressed. `tools/leak_check.py` ships the
public-safe copy; private identifier lists are supplied from local files.
- CI scans `examples/rojo_demo` on Linux and Windows and asserts the unmeasured lead
prints at low severity and cannot fail `--fail-on-critical`.

## 0.2.2 (released)

First public release.

- Message and release-metadata follow-up to 0.2.1. `onyx verify` is now described consistently as tested on
  **Linux and WSL 2 (Ubuntu)**; macOS is untested, and native Windows remains unsupported for
  `verify`. The missing-Luau hint shows the Ubuntu install commands only on Linux/WSL, points macOS at
  the releases page without a command, and keeps the Windows zip hint separate. The Linux/WSL
  hint now downloads the CI-pinned Luau 0.748 Ubuntu zip and checks the same SHA-256 before
  unzipping, instead of following `releases/latest`.
- WSL 2 (Ubuntu) was tested manually with the TestPyPI 0.2.1 wheel and Luau 0.748: the vulnerable
  example confirmed L001 (`2001 -> 1000002001`), `--fail-on-confirmed` returned exit 2, and the
  fixed example printed `No exploit confirmed`. This is one distro on one machine, not a claim
  about WSL 1, other distros, or macOS.
- `MEASURED_AS_OF`, the scanner footer, `pyproject.toml`, `engine_version` and this changelog now
  agree on 0.2.2.
- Release plumbing: `pyproject.toml` links Source and Issues back to the repository; the publish
  workflow is manual-only (no release trigger) and checks the sdist contents; `SECURITY.md`
  points reporters at GitHub private vulnerability reporting.

## 0.2.1 (TestPyPI dry run only)

TestPyPI-only build; superseded by 0.2.2 before the first real release.

- Windows: `onyx scan` works on native Windows (maintainer-tested; CI will re-check Python 3.12).
  `onyx verify` now fails closed with a clear "not supported on Windows, use WSL" message instead
  of crashing inside `preexec_fn`. The POSIX CPU, memory and file-size limits are not silently
  dropped.
- A Windows CI job scans both shipped examples and asserts that `verify` refuses safely with
  Luau present; an Ubuntu CI job installs Luau and proves `verify` confirms the vulnerable example
  (exit 0, and exit 2 with `--fail-on-confirmed`) while the fixed example is not confirmed. The
  missing-Luau hint now shows only the current platform's install line.
- `MEASURED_AS_OF`, the scanner footer, `pyproject.toml` and this changelog now agree on 0.2.1.

## 0.2.0 (TestPyPI dry run only)

TestPyPI-only build; superseded by 0.2.1 before the first real release.

- Static scan for client-controlled writes in Roblox XML place and model files, with a rule id on
  every finding.
- `onyx verify` executes a handler under a mock of the documented Roblox API and records what it
  can and cannot confirm, including the moves that made the finding reproducible.
- `onyx baseline` records accepted findings so a later scan can fail only on new ones.
- Measured precision labels with the checked count and a 95% interval; a rule with too few
  checked findings prints `underpowered — N checked`, and a rule with none prints
  `no measured rate`.
- `--prompt` turns a finding into a paste-ready fix prompt, and `onyx rules` lists rule ids and
  what each one catches.
- Two example places ship with the repository: one vulnerable, one fixed.
