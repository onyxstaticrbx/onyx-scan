"""Policy: the file a studio uses to make this tool judge their code their way.

A security tool that only has one opinion is a demo. A tool that takes a policy
file becomes part of a studio's process, because the studio's judgement outranks the
tool's defaults and the file lives in their repo next to the code it describes.

`.onyx.json`:

    {
      "version": 1,
      "rules": {
        "disable": ["ONYX-L008"],
        "severity": { "ONYX-L016": "low" }
      },
      "fail_on": "critical",
      "fail_on_new": true,
      "baseline": ".onyx/baseline.json",
      "state": ".onyx/triage.json",
      "ignore": [
        { "rule": "ONYX-L012", "reason": "sandboxed internal tooling", "until": "2027-01-01" }
      ]
    }

Everything here is a judgement call the user is allowed to make. What is
*not* optional is the record: every suppression needs a reason, and every
reason is counted in the metrics the console shows.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .rules import SEVERITY_ORDER

SEVERITIES = ("info", "low", "medium", "high", "critical")

DEFAULTS: dict = {
    "version": 1,
    "rules": {"disable": [], "severity": {}},
    "fail_on": "critical",
    "fail_on_new": True,
    "baseline": ".onyx/baseline.json",
    "state": ".onyx/triage.json",
    "ignore": [],
}

TOP_KEYS = set(DEFAULTS)
RULE_KEYS = {"disable", "severity"}
IGNORE_KEYS = {"rule", "fingerprint", "reason", "until"}


class PolicyError(Exception):
    pass


def _expect(cond: bool, message: str) -> None:
    if not cond:
        raise PolicyError(message)


def validate(policy: dict) -> dict:
    """Reject anything ambiguous. A policy typo must not silently change the verdict."""
    _expect(isinstance(policy, dict), "policy must be a JSON object")

    unknown = set(policy) - TOP_KEYS
    if unknown:
        raise PolicyError(f"unknown policy key(s): {sorted(unknown)}")

    merged = json.loads(json.dumps(DEFAULTS))
    for key, value in policy.items():
        merged[key] = value

    _expect(merged["version"] == 1, "policy version must be 1")

    rules = merged["rules"]
    _expect(isinstance(rules, dict), "rules must be an object")
    unknown_rules = set(rules) - RULE_KEYS
    if unknown_rules:
        raise PolicyError(f"unknown key(s) under rules: {sorted(unknown_rules)}")

    disable = rules.get("disable") or []
    _expect(isinstance(disable, list) and all(isinstance(r, str) for r in disable),
            "rules.disable must be a list of rule ids")

    overrides = rules.get("severity") or {}
    _expect(isinstance(overrides, dict), "rules.severity must be an object")
    for rule_id, sev in overrides.items():
        _expect(isinstance(rule_id, str), "rules.severity keys must be rule ids")
        if sev not in SEVERITIES:
            raise PolicyError(f"rules.severity[{rule_id}] must be one of {SEVERITIES}")

    fail_on = merged["fail_on"]
    if fail_on != "none":
        _expect(fail_on in SEVERITIES, f"fail_on must be one of {SEVERITIES} or 'none'")

    _expect(isinstance(merged["fail_on_new"], bool), "fail_on_new must be true or false")
    for key in ("baseline", "state"):
        _expect(isinstance(merged[key], str) and merged[key], f"{key} must be a path string")

    ignore = merged["ignore"] or []
    _expect(isinstance(ignore, list), "ignore must be a list")
    for entry in ignore:
        _expect(isinstance(entry, dict), "each ignore entry must be an object")
        unknown_ignore = set(entry) - IGNORE_KEYS
        if unknown_ignore:
            raise PolicyError(f"unknown key(s) in ignore entry: {sorted(unknown_ignore)}")
        _expect(bool(entry.get("rule") or entry.get("fingerprint")),
                "each ignore entry needs a rule id or a fingerprint")
        reason = entry.get("reason")
        _expect(isinstance(reason, str) and len(reason.strip()) >= 4,
                "each ignore entry needs a reason of at least 4 characters")

    return merged


def load(path: str | Path | None = None) -> dict:
    if path is None:
        return json.loads(json.dumps(DEFAULTS))
    file = Path(path)
    if not file.exists():
        raise PolicyError(f"policy file not found: {file}")
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{file}: invalid JSON ({exc.msg}) at line {exc.lineno}") from exc
    return validate(raw)


def save(path: str | Path, policy: dict) -> None:
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(validate(policy), indent=2) + "\n", encoding="utf-8")


def _expired(entry: dict, now: float | None = None) -> bool:
    until = entry.get("until")
    if not until:
        return False
    try:
        stamp = time.mktime(time.strptime(str(until)[:10], "%Y-%m-%d"))
    except ValueError:
        return False
    return stamp < (now if now is not None else time.time())


def apply(policy: dict, findings: list[dict], fingerprints: dict[str, str] | None = None) -> dict:
    """Apply the policy. Returns what survived and an honest account of what did not.

    `fingerprints` maps id(finding) -> fingerprint, so ignore entries that match
    by fingerprint work without recomputing hashes here.
    """
    fingerprints = fingerprints or {}
    disabled = set(policy["rules"].get("disable") or [])
    overrides = policy["rules"].get("severity") or {}
    ignores = policy.get("ignore") or []

    kept: list[dict] = []
    suppressed: list[dict] = []
    expired: list[dict] = []

    by_rule = {e["rule"]: e for e in ignores if e.get("rule")}
    by_fp = {e["fingerprint"]: e for e in ignores if e.get("fingerprint")}

    for finding in findings:
        rule_id = finding.get("rule_id")

        if rule_id in disabled:
            suppressed.append({**finding, "suppressed_by": "rule_disabled"})
            continue

        entry = by_rule.get(rule_id) or by_fp.get(fingerprints.get(str(id(finding)), ""))
        if entry:
            if _expired(entry):
                expired.append({**finding, "expired_ignore": entry.get("reason")})
            else:
                suppressed.append({
                    **finding,
                    "suppressed_by": "policy_ignore",
                    "suppressed_reason": entry.get("reason"),
                    "suppressed_until": entry.get("until"),
                })
                continue

        if rule_id in overrides:
            finding = {**finding, "severity": overrides[rule_id], "severity_overridden": True}

        kept.append(finding)

    kept.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f.get("path", ""), f.get("line", 0)))
    return {"findings": kept, "suppressed": suppressed, "expired": expired}


def failing(policy: dict, findings: list[dict]) -> list[dict]:
    """Which findings break the build."""
    fail_on = policy["fail_on"]
    if fail_on == "none":
        return []
    limit = SEVERITY_ORDER.get(fail_on, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f["severity"], 9) <= limit]


def summary(policy: dict) -> dict:
    return {
        "fail_on": policy["fail_on"],
        "fail_on_new": policy["fail_on_new"],
        "baseline": policy["baseline"],
        "state": policy["state"],
        "disabled": policy["rules"].get("disable") or [],
        "severity_overrides": policy["rules"].get("severity") or {},
        "ignore_count": len(policy.get("ignore") or []),
    }
