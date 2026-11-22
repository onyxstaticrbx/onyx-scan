# Changelog

Notable changes to `onyx-scan`. The version in each heading matches the `version` field in
`pyproject.toml`, the `MEASURED_AS_OF` label in `onyx/finding_help.py`, and the footer printed by
the scanner.

## 0.2.0 (unreleased)

First public release.

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
