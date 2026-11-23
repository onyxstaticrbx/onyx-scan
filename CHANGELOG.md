# Changelog

Notable changes to `onyx-scan`. The version in each heading matches the `version` field in
`pyproject.toml`, the `MEASURED_AS_OF` label in `onyx/finding_help.py`, and the footer printed by
the scanner.

## 0.2.1 (unreleased)

First public release.

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
