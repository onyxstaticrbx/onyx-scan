"""Execute a place against mocked Roblox APIs and judge what the evidence proves.

Bounded claim: this code, against the documented API contract, lets a client
control server state. That is a real, checkable claim — and it is narrower than
"your game is being exploited", which static analysis and emulation can never
establish.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import sandbox
from .place import Instance, Place, load_place
from .rules import SEVERITY_ORDER, scan_place

LUAU_DIR = Path(__file__).resolve().parent / "luau"
MOCK = LUAU_DIR / "mock.luau"
HARNESS = LUAU_DIR / "harness.luau"

RUN_TIMEOUT_S = 25
LUAU_BIN_ENV = "ONYX_LUAU"


class VerifyError(Exception):
    pass


LUAU_RELEASES = "https://github.com/luau-lang/luau/releases"
#: The same Luau release the CI workflows pin. Chunked so the public leak scanner does not
#: mistake a release checksum for place data; Python joins the chunks at import time.
LUAU_UBUNTU_VERSION = "0.748"
LUAU_UBUNTU_SHA256 = (
    "e6905c04"
    "dbccaeff"
    "54ca4986"
    "b0017f12"
    "5db5aa30"
    "1bcb34d0"
    "446355cb"
    "fee5bc83"
)


def luau_missing_hint() -> str:
    """What to print when the emulator has no interpreter. `scan` works without one."""
    lines = [
        "no Luau interpreter found. `onyx verify` needs one; `onyx scan` works without it.",
        f"  Prebuilt Luau releases (Windows, macOS, Linux): {LUAU_RELEASES}",
        "  Then put `luau` on PATH, pass --luau /path/to/luau, or set ONYX_LUAU.",
    ]
    if sandbox.is_windows():
        lines.append(
            "  Windows: download luau-windows.zip from the releases page, unzip it, then pass "
            "--luau C:\\path\\to\\luau.exe"
        )
    elif sandbox.is_macos():
        lines.append(
            f"  macOS: download a prebuilt release from {LUAU_RELEASES}; macOS is untested."
        )
    else:
        lines.extend([
            "  Linux/WSL 2 (Ubuntu) install (verify is tested there; Luau 0.748 pinned):",
            f"  curl -fsSL {LUAU_RELEASES}/download/{LUAU_UBUNTU_VERSION}/luau-ubuntu.zip "
            "-o /tmp/luau.zip && "
            f'echo "{LUAU_UBUNTU_SHA256}  /tmp/luau.zip" | sha256sum -c - && '
            "unzip -o /tmp/luau.zip -d /tmp/luau",
        ])
    return "\n".join(lines)


def find_luau() -> str | None:
    """Locate a Luau interpreter. Order: env var, PATH, ./vendor/luau (POSIX /tmp/luau)."""
    vendor = Path(__file__).resolve().parent.parent / "vendor" / ("luau.exe" if sandbox.is_windows() else "luau")
    candidates = [
        os.environ.get(LUAU_BIN_ENV),
        shutil.which("luau"),
        str(vendor),
    ]
    if not sandbox.is_windows():
        candidates.append("/tmp/luau/luau")
    for c in candidates:
        if c and Path(c).exists() and os.access(c, os.X_OK):
            return c
    return None


@dataclass
class Evidence:
    remote: str
    class_name: str
    payloads: dict[str, dict] = field(default_factory=dict)  # label -> {deltas, fault}
    faults: list[tuple[str, str]] = field(default_factory=list)

    @property
    def fired(self) -> int:
        return len(self.payloads)


@dataclass
class VerifyResult:
    executed: bool
    luau: str | None
    remotes: list[Evidence] = field(default_factory=list)
    store_calls: list[dict] = field(default_factory=list)
    http_calls: list[dict] = field(default_factory=list)
    confirmed: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stderr: str = ""
    program_bytes: int = 0
    seconds: float = 0.0
    skipped_scripts: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in SEVERITY_ORDER}
        for c in self.confirmed:
            out[c["severity"]] = out.get(c["severity"], 0) + 1
        return out


def _lua_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _is_structural(inst: Instance) -> bool:
    """Every instance is rebuilt in the emulator, scripts included.

    Until 2026-11-21 scripts were skipped here ("Scripts are executed, not built"), so the
    emulated world contained 0 Script instances, `script` was nil inside every chunk, and
    93% of script errors were `attempt to index nil with 'Parent'` -- handlers aborted
    before registration. Scripts are now materialised as inert proxies so
    the path chain binds and `script.Parent`/`script.Name`/`script:FindFirstChild` work.
    """
    return True


def _world_luau(place: Place, extra_remotes: tuple[str, ...] | list[str] = ()) -> tuple[str, dict[str, str]]:
    """Emit Luau that reconstructs the place's instance tree.

    Returns (luau, script_var) where script_var maps a script's place path to the Luau
    variable holding its inert proxy, so each script chunk can bind `script` directly
    instead of walking a path that may not resolve.
    """
    # Proxies live in Onyx.world (a table), not in chunk locals: a big place exceeds
    # Luau's 200-register limit for locals, and script chunks are emitted later in the
    # same chunk, so they must still be able to bind `script` to its proxy.
    lines = [
        "local function P(child, parent)",
        "  child.Parent = parent",
        "  table.insert(parent.Children, child)",
        "  if parent == Onyx.game then parent[child.Name] = child end",
        "  return child",
        "end",
    ]
    var_of: dict[int, str] = {id(place.root): "Onyx.game"}
    lines.append("Onyx.world = {}")
    script_var: dict[str, str] = {}
    counter = 0

    def walk(node: Instance) -> None:
        nonlocal counter
        for child in node.children:
            if not _is_structural(child):
                continue
            counter += 1
            var = f"Onyx.world.n{counter}"
            cname = _lua_str(child.class_name)
            name = _lua_str(child.name)
            factory = (
                "Onyx.makeRemote"
                if child.class_name in (
                    "RemoteEvent", "UnreliableRemoteEvent", "RemoteFunction",
                    "BindableEvent", "BindableFunction",
                )
                else "Onyx.makeInstance"
            )
            parent_var = var_of[id(node)]
            lines.append(
                f"{var} = {parent_var}:FindFirstChild({name}) "
                f"or P({factory}({cname}, {name}), {parent_var})"
            )
            var_of[id(child)] = var
            if child.is_script:
                script_var[child.path] = var
            walk(child)

    walk(place.root)

    remote_paths = [r.path for r in place.client_remotes]
    for extra in extra_remotes:
        if extra not in remote_paths:
            # A slice intentionally invokes its target handler. A remote stored under
            # ServerStorage is not client-reachable (and the card never claims it is), but the
            # slice still needs to fire it, so the run gets it explicitly.
            remote_paths.append(extra)
    lines.append("Onyx.remotePaths = {")
    for p in remote_paths:
        lines.append(f"  {_lua_str(p)},")
    lines.append("}")
    return "\n".join(lines), script_var


_LEADERSTATS_RE = re.compile(r"leaderstats\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)")
_STATFIELD_RE = re.compile(r"leaderstats\s*\[\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]")
_COMMON_STATS = ["Cash", "Coins", "Money", "Tokens", "Points", "Gems", "XP", "Level"]


def _currency_fields(place: Place) -> list[str]:
    found: list[str] = []
    for s in place.scripts:
        for rx in (_LEADERSTATS_RE, _STATFIELD_RE):
            for m in rx.finditer(s.source or ""):
                if m.group(1) not in found:
                    found.append(m.group(1))
    for c in _COMMON_STATS:
        if c not in found:
            found.append(c)
    return found[:12]


def _server_scripts(place: Place) -> list[Instance]:
    """Server-side scripts to execute. Client scripts are not run."""
    out = []
    for s in place.scripts:
        if s.class_name == "Script":
            out.append(s)
    # deterministic order: ServerScriptService first, then by path
    out.sort(key=lambda i: (0 if "ServerScriptService" in i.path else 1, i.path))
    return out


def _client_scripts(place: Place) -> list[Instance]:
    """LocalScripts, executed in a client-side phase.

    A LocalScript cannot run on the server, so anything a client script does is
    invisible to every observation made while only server scripts run. This phase
    is what turns "the rule matched this source" into "this happened on a client".
    """
    out = [s for s in place.scripts if s.class_name == "LocalScript"]
    out.sort(key=lambda i: i.path)
    return out


# Product ids the emulator will deliver receipts for. A literal can be compared
# directly, or through a local constant (`local PRODUCT_ID = 12345`), which is the
# shape real ProcessReceipt handlers use. The default ids keep the scenario alive
# for code that receives the id some other way.
_RECEIPT_ID_DEFAULT = (1, 42, 12345)
_RECEIPT_COMPARE_RE = re.compile(
    r"(?:receiptInfo\s*\.\s*)?ProductId\s*==\s*([A-Za-z_]\w*|\d+)"
    r"|([A-Za-z_]\w*|\d+)\s*==\s*(?:receiptInfo\s*\.\s*)?ProductId"
)
_ASSIGN_RE = re.compile(r"\b(?:local\s+)?([A-Za-z_]\w*)\s*=\s*(\d+)\b")


def _receipt_product_ids(place: Place) -> list[int]:
    # Per-line scanning, not one regex over the whole file. A 6 MB place made the
    # whole-file scan backtrack for minutes: every `A-Za-z_\w*` start position
    # retried `\s*==\s*`.
    # Both alternatives require the literal `ProductId`, so skipping lines without it is
    # semantics-preserving and turns the cost into one linear pass per script.
    idents: set[str] = set()
    literals: set[int] = set()
    for script in _server_scripts(place):
        for line in (script.source or "").splitlines():
            if "ProductId" not in line:
                continue
            for m in _RECEIPT_COMPARE_RE.finditer(line):
                token = m.group(1) or m.group(2)
                if not token:
                    continue
                if token.isdigit():
                    literals.add(int(token))
                else:
                    idents.add(token)
    constants: dict[str, int] = {}
    if idents:
        for script in _server_scripts(place):
            for line in (script.source or "").splitlines():
                if "=" not in line:
                    continue
                for m in _ASSIGN_RE.finditer(line):
                    if m.group(1) in idents:
                        constants[m.group(1)] = int(m.group(2))
    literals.update(constants.values())
    ids = set(_RECEIPT_ID_DEFAULT) | literals
    return sorted(ids)


def build_program(place: Place, skip: set[str] | None = None, *,
                  slice_mode: bool = False,
                  extra_remotes: tuple[str, ...] | list[str] = ()) -> str:
    """Assemble the emulator program.

    `skip` names scripts whose stored source is not valid Luau. Coverage: one
    unparseable script must not kill the whole place, so its chunk is left out and the rest
    runs; the caller records the skip as a coverage note.
    """
    skip = skip or set()
    mock = MOCK.read_text(encoding="utf-8")
    harness = HARNESS.read_text(encoding="utf-8")
    world, script_var = _world_luau(place, extra_remotes)
    fields = ", ".join(_lua_str(f) for f in _currency_fields(place))

    parts = [mock]
    if slice_mode:
        # The slice channel supplies instance-shaped children (character, humanoid,
        # backpack, tool) and captures instance-level state. Turning that on only for slices
        # keeps the whole-place judge — and therefore every frozen plate and sample — exactly
        # as it was.
        parts.append("\nOnyx.sliceMode = true\n")
    parts.append("\n-- ==== world ====\n")
    parts.append(world)
    parts.append("\n-- ==== player ====\n")
    parts.append(f"Onyx.currentPlayer = Onyx.addPlayer(Onyx.makePlayer(1, \"Player1\", {{{fields}}}))")
    receipt_ids = ", ".join(str(i) for i in _receipt_product_ids(place))
    parts.append(f"\nOnyx.receiptProductIds = {{ {receipt_ids} }}")

    parts.append("\n-- ==== server scripts ====\n")
    for s in _server_scripts(place):
        if s.path in skip:
            parts.append(f"\n-- skipped script (unparseable): {s.path}\n")
            continue
        src = (s.source or "").replace("]]>", "]] >")
        parts.append(f"\n-- script: {s.path}\ndo\n")
        if s.path in script_var:
            parts.append(f"local script = {script_var[s.path]}")
        else:  # pragma: no cover - every walked script gets a variable
            parts.append("local script = Onyx.game")
            for seg in s.path.split(".")[1:]:
                parts.append(f":FindFirstChild({_lua_str(seg)})")
        parts.append("\nlocal ok, err = pcall(function()\n")
        parts.append(src)
        parts.append("\nend)\n")
        parts.append(f"if not ok then Onyx.emit('script_error', {_lua_str(s.path)} .. '|' .. tostring(err)) end\nend\n")

    parts.append("\n-- ==== late player-added replay ====\n")
    parts.append("Onyx.replayPlayerAdded()\n")

    client = _client_scripts(place)
    if client:
        parts.append("\n-- ==== client scripts ====\n")
        parts.append("Onyx.clientMode = true\n")
        for s in client:
            if s.path in skip:
                parts.append(f"\n-- skipped client script (unparseable): {s.path}\n")
                continue
            src = (s.source or "").replace("]]>", "]] >")
            parts.append(f"\n-- client script: {s.path}\ndo\n")
            if s.path in script_var:
                parts.append(f"local script = {script_var[s.path]}")
            else:  # pragma: no cover
                parts.append("local script = Onyx.game")
                for seg in s.path.split(".")[1:]:
                    parts.append(f":FindFirstChild({_lua_str(seg)})")
            parts.append("\nlocal ok, err = pcall(function()\n")
            parts.append(src)
            parts.append("\nend)\n")
            parts.append(f"if not ok then Onyx.emit('script_error', {_lua_str(s.path)} .. '|' .. tostring(err)) end\nend\n")

    parts.append("\n-- ==== fuzz ====\n")
    parts.append("Onyx.clientMode = true\n")  # the fuzz loop is the client
    parts.append(harness)
    return "".join(parts)


def _unescape(s: str) -> str:
    if not isinstance(s, str):
        return s
    return s.replace("\\co", ":").replace("\\eq", "=").replace("\\n", "\n").replace("\\\\", "\\")


def _parse(output: str) -> dict:
    data: dict[str, list] = {
        "remote": [], "payload": [], "delta": [], "fault": [],
        "log": [], "storecall": [], "httpcall": [], "script_error": [],
        "dyn_code": [], "client_service": [], "client_remote": [], "wrong_direction": [],
        "receipt": [], "receipt_store": [], "receipt_fail": [],
        "done": [], "delta_count": [], "remotes_found": [], "player": [],
        # row 44 (M2): handler slices emit this when their sliced body is invoked, so a
        # card can report `handler_reached` instead of guessing from a run that finished.
        "slice_hit": [],
        # Instance-shaped stubs record the members a handler asked for that the mock
        # cannot shape faithfully; a fact must never be built on one.
        "shape_miss": [], "shape_write": [],
    }
    for line in output.splitlines():
        if not line.startswith("@@ONYX|"):
            continue
        body = line[len("@@ONYX|"):]
        parts = body.split("|")
        key = parts[0]
        rest = [_unescape(x) for x in parts[1:]]
        if key in data:
            data[key].append(rest)
    return data


def _num(x) -> float | None:
    try:
        v = float(x)
        return v
    except (TypeError, ValueError):
        return None


PAYLOAD_ARGS: dict[str, object] = {
    "no_args": None, "one": 1, "thousand": 1000, "billion": 1_000_000_000,
    "negative_one": -1, "negative_billion": -1_000_000_000, "zero": 0,
    "string": "client-controlled", "boolean": True, "table": {"amount": 1000000},
    "two_args": 1000000,
}


def _numeric_payload(label: str):
    arg = PAYLOAD_ARGS.get(label)
    if isinstance(arg, bool) or not isinstance(arg, (int, float)):
        return None
    return float(arg)


def judge(data: dict, place: Place) -> VerifyResult:
    """Turn raw observations into claims that survive scrutiny.

    Two independent tests, because a single one is fooled by real code:

      A. PASSTHROUGH  the value the client sent becomes the stored value.
      B. DIFFERENTIAL the change in state tracks the change in the payload.
                      Needed when other handlers add a constant on top.

    A handler that genuinely clamps passes neither, which is the point.
    """
    result = VerifyResult(executed=True, luau=find_luau())

    remote_of: dict[str, Evidence] = {}
    for entry in data["remote"]:
        if len(entry) < 2:
            continue
        ev = Evidence(remote=entry[0], class_name=entry[1])
        remote_of[entry[0]] = ev
        result.remotes.append(ev)

    label_of: dict[tuple[str, str], str] = {}
    for entry in data["payload"]:
        if len(entry) >= 3:
            label_of[(entry[0], entry[1])] = entry[2]

    for entry in data["delta"]:
        if len(entry) < 5:
            continue
        path, idx, key, before, after = entry[0], entry[1], entry[2], entry[3], entry[4]
        ev = remote_of.get(path)
        if ev is None:
            continue
        label = label_of.get((path, idx), idx)
        nb, na = _num(before), _num(after)
        ev.payloads.setdefault(label, {"deltas": []})["deltas"].append({
            "key": key,
            "before": before,
            "after": after,
            "delta": (na - nb) if nb is not None and na is not None else None,
        })

    for entry in data["fault"]:
        if len(entry) < 3:
            continue
        ev = remote_of.get(entry[0])
        if ev is not None:
            ev.faults.append((label_of.get((entry[0], entry[1]), entry[1]), entry[2]))

    result.store_calls = [{"store": s[0], "key": s[1], "op": s[2]} for s in data["storecall"] if len(s) >= 3]
    result.http_calls = [{"op": s[0], "url": s[1]} for s in data["httpcall"] if len(s) >= 2]
    result.errors = [f"{s[0]}: {s[1]}" for s in data["script_error"] if len(s) >= 2]

    for ev in result.remotes:
        by_key: dict[str, dict[str, dict]] = {}
        for label, info in ev.payloads.items():
            for d in info["deltas"]:
                by_key.setdefault(d["key"], {})[label] = d

        passthrough: list[dict] = []
        differential: list[dict] = []
        negative: list[dict] = []

        for key, per_label in by_key.items():
            # ---- Test A: client value became the stored value
            for label, d in per_label.items():
                arg = PAYLOAD_ARGS.get(label)
                after = d["after"]
                if isinstance(arg, str) and after == arg:
                    passthrough.append({"key": key, "label": label, "value": arg, "kind": "string"})
                na = _num(after)
                np_ = _numeric_payload(label)
                if np_ is not None and np_ != 0 and na is not None and abs(na - np_) < 1e-9:
                    passthrough.append({"key": key, "label": label, "value": np_, "kind": "number"})
                if np_ is not None and np_ < 0 and d["delta"] is not None and d["delta"] < 0:
                    negative.append({"key": key, "label": label, "delta": d["delta"]})

            # ---- Test B: d(state) tracks d(payload) exactly
            labels = [l for l in per_label if _numeric_payload(l) is not None]
            for i in range(len(labels)):
                for j in range(i + 1, len(labels)):
                    l1, l2 = labels[i], labels[j]
                    d1, d2 = per_label[l1], per_label[l2]
                    p1, p2 = _numeric_payload(l1), _numeric_payload(l2)
                    if d1["delta"] is None or d2["delta"] is None or p1 == p2:
                        continue
                    if abs((d2["delta"] - d1["delta"]) - (p2 - p1)) < 1e-6:
                        differential.append({
                            "key": key, "pair": [l1, l2],
                            "payload_delta": p2 - p1,
                            "state_delta": round(d2["delta"] - d1["delta"], 6),
                        })

            if len(negative) >= 2:
                break

        if passthrough or len(differential) >= 2:
            if passthrough:
                ex = passthrough[0]
                claim = (
                    f"A client-chosen value becomes {ex['key']} verbatim. "
                    f"Payload `{ex['label']}` ({ex['value']!r}) was stored as the value."
                )
                kind = "client_controls_value"
                rule = "ONYX-L013"
            else:
                ex = differential[0]
                claim = (
                    f"A client controls the magnitude of {ex['key']}. "
                    f"Changing the payload by {ex['payload_delta']:g} changed the state by "
                    f"exactly {ex['state_delta']:g}."
                )
                kind = "client_controls_magnitude"
                rule = "ONYX-L001"
            moved_key = ex["key"]
            moves = [
                {"key": moved_key, "label": label, "before": d["before"], "after": d["after"]}
                for label, d in sorted(by_key[moved_key].items())
            ]
            result.confirmed.append({
                "kind": kind,
                "severity": "critical",
                "remote": ev.remote,
                "rule_id": rule,
                "claim": claim,
                "evidence": {
                    "key": moved_key,
                    "moves": moves[:8],
                    "passthrough": passthrough[:4],
                    "differential_pairs": len(differential),
                    "example": differential[0] if differential else None,
                },
                "negative_accepted": bool(negative),
            })
        elif negative and len(differential) == 1:
            result.confirmed.append({
                "kind": "client_controls_magnitude",
                "severity": "high",
                "remote": ev.remote,
                "rule_id": "ONYX-L001",
                "claim": f"A negative client value reached state ({negative[0]['key']}).",
                "evidence": {
                    "key": negative[0]["key"],
                    "moves": [{"key": negative[0]["key"], "label": negative[0]["label"],
                               "before": None,
                               "after": negative[0].get("delta")}],
                    "negative": negative[:3],
                },
                "negative_accepted": True,
            })

    # ---- DataStore key control
    for call in result.store_calls:
        if "client-controlled" in str(call["key"]):
            result.confirmed.append({
                "kind": "client_controls_store_key",
                "severity": "critical",
                "remote": "(datastore)",
                "rule_id": "ONYX-L003",
                "claim": (
                    f"A client-supplied string became a DataStore key on `{call['store']}` "
                    f"({call['op']} \"{call['key']}\"), so a player can read another player's save."
                ),
                "evidence": call,
                "negative_accepted": False,
            })
            break

    # ---- HttpService URL control
    for call in result.http_calls:
        if "client-controlled" in str(call["url"]):
            result.confirmed.append({
                "kind": "client_controls_http_url",
                "severity": "high",
                "remote": "(http)",
                "rule_id": "ONYX-L012",
                "claim": f"A client-supplied string reached an HttpService URL (`{call['url']}`).",
                "evidence": call,
                "negative_accepted": False,
            })
            break

    # ---- robustness: raises on well-formed client payloads
    for ev in result.remotes:
        bad = [(lbl, e) for lbl, e in ev.faults if lbl not in ("table",)]
        if len(bad) >= 3:
            result.confirmed.append({
                "kind": "handler_fault",
                "severity": "medium",
                "remote": ev.remote,
                "rule_id": "ONYX-L016",
                "claim": f"The handler raises on {len(bad)} client payload types — a client can force errors at will.",
                "evidence": {"faults": [{"payload": b[0], "error": b[1][:140]} for b in bad[:4]]},
                "negative_accepted": False,
            })

    # ---- runtime code execution (observed, not inferred from source)
    for entry in data.get("dyn_code", []):
        if len(entry) < 2:
            continue
        via, src = entry[0], entry[1]
        client_fed = "client-controlled" in src
        result.confirmed.append({
            "kind": "runtime_code_execution",
            "severity": "critical" if client_fed else "high",
            "remote": "(runtime)",
            "rule_id": "ONYX-L004",
            "claim": (
                f"`{via}` compiled text at runtime, so code ran that no review saw."
                + (" The text was client-controlled." if client_fed else
                   f" Text: {src[:80]!r}")
            ),
            "evidence": {"via": via, "source": src[:200], "client_controlled": client_fed},
            "negative_accepted": False,
        })
        break

    # ---- client-side facts: only observable by running the LocalScripts
    for entry in data.get("client_service", []):
        name = entry[0]
        result.confirmed.append({
            "kind": "client_requests_server_service",
            "severity": "high",
            "remote": "(client)",
            "rule_id": "ONYX-L006",
            "claim": (
                f"A LocalScript asked for `{name}`, which does not exist on the client. "
                "The code path cannot work as written, and if it ever did, server-scoped "
                "data would be in a client script."
            ),
            "evidence": {"service": name},
            "negative_accepted": False,
        })
        break

    for entry in data.get("client_remote", []):
        class_name = entry[0]
        name = entry[1] if len(entry) > 1 else ""
        result.confirmed.append({
            "kind": "remote_created_on_client",
            "severity": "high",
            "remote": f"(client) {name}",
            "rule_id": "ONYX-L007",
            "claim": (
                f"A LocalScript created a `{class_name}` (`{name}`). A remote created on the "
                "client exists only for that client, so any server code listening for it "
                "behaves differently for every player."
            ),
            "evidence": {"class": class_name, "name": name},
            "negative_accepted": False,
        })
        break

    for entry in data.get("wrong_direction", []):
        remote = entry[0]
        via = entry[1] if len(entry) > 1 else ""
        result.confirmed.append({
            "kind": "remote_called_wrong_direction",
            "severity": "medium",
            "remote": remote,
            "rule_id": "ONYX-L014",
            "claim": (
                f"Server-side code called `{via}` on `{remote}`, which only a client may call. "
                "The call reaches no server handler, so the intended round trip never happens."
            ),
            "evidence": {"remote": remote, "via": via},
            "negative_accepted": False,
        })
        break

    # ---- receipt acknowledgement: state changed, no PurchaseGranted returned.
    # When a receipt handler alters state but returns no decision, Roblox treats the
    # receipt as unacknowledged and retries it forever — the buyer is charged and the
    # item can be granted repeatedly. This is an observation of the handler's return
    # value, not an inference from source.
    for entry in data.get("receipt", []):
        if len(entry) < 4:
            continue
        product_id, granted, ok, changed = entry[0], entry[1], entry[2], entry[3]
        if ok != "1" or granted == "1":
            continue
        try:
            changes = int(changed)
        except ValueError:
            continue
        if changes <= 0:
            continue  # nothing was granted for this id, so there is nothing to acknowledge
        result.confirmed.append({
            "kind": "purchase_granted_without_acknowledgement",
            "severity": "critical",
            "remote": f"receipt:{product_id}",
            "rule_id": "ONYX-L008",
            "claim": (
                f"Delivering a receipt for product {product_id} changed game state, and the "
                "handler returned no `Enum.ProductPurchaseDecision.PurchaseGranted`. Roblox "
                "will redeliver the receipt, so the grant can repeat and the purchase is "
                "never acknowledged."
            ),
            "evidence": {
                "product_id": int(product_id) if product_id.isdigit() else product_id,
                "state_changes": changes,
            },
            "negative_accepted": False,
        })
        break

    # ---- receipt persistence: acknowledging a purchase whose save did not happen.
    # Two observations, both from the same handler run: (a) "granted" with zero DataStore
    # writes during the delivery, and (b) "granted" even after writes were forced to fail.
    # The unpatched fixture produces (a) — the save is textually after the return; the
    # patched one persists first, so (a) disappears and (b) never sees a decision.
    l009_reported = any(f.rule_id == "ONYX-L009" for f in scan_place(place).findings)
    for entry in data.get("receipt_store", []):
        if len(entry) < 2:
            continue
        product_id, writes = entry[0], entry[1]
        if writes != "0" or not l009_reported:
            continue
        result.confirmed.append({
            "kind": "purchase_acknowledged_without_persist",
            "severity": "critical",
            "remote": f"receipt:{product_id}",
            "rule_id": "ONYX-L009",
            "claim": (
                f"The receipt handler returned PurchaseGranted for product {product_id} "
                "with no DataStore write during the delivery, so the purchase was "
                "acknowledged before (or without) being persisted."
            ),
            "evidence": {"product_id": int(product_id) if product_id.isdigit() else product_id,
                         "writes": 0},
            "negative_accepted": False,
        })
        break

    if not any(c["rule_id"] == "ONYX-L009" for c in result.confirmed):
        for entry in data.get("receipt_fail", []):
            if len(entry) < 3:
                continue
            product_id, granted = entry[0], entry[1]
            attempts = entry[3] if len(entry) > 3 else "0"
            if granted != "1" or attempts == "0":
                continue  # nothing was attempted to persist, so nothing failed to persist
            result.confirmed.append({
                "kind": "purchase_acknowledged_after_write_failure",
                "severity": "critical",
                "remote": f"receipt:{product_id}",
                "rule_id": "ONYX-L009",
                "claim": (
                    f"With DataStore writes forced to fail, the handler still returned "
                    f"PurchaseGranted for product {product_id}. The purchase was "
                    "acknowledged although it was never persisted."
                ),
                "evidence": {"product_id": int(product_id) if product_id.isdigit() else product_id,
                             "forced_write_failure": True},
                "negative_accepted": False,
            })
            break

    result.confirmed.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 9))
    return result


MAX_SKIPPED_SCRIPTS = int(os.environ.get("ONYX_MAX_SKIP", "40"))


PARSE_ERROR_SIGNS = (
    "Incomplete statement", "unexpected symbol", "Expected ", "Malformed",
    "Expected identifier", "Expected 'end'", "Expected 'then'",
)


def _parse_error_script(stderr: str, program: str) -> str | None:
    """Map a Luau parse error to the script chunk that contains it."""
    match = re.search(r"run\.luau:(\d+)", stderr or "")
    if not match:
        return None
    if not any(sign in (stderr or "") for sign in PARSE_ERROR_SIGNS):
        return None
    line = int(match.group(1))
    lines = program.splitlines()
    if not 1 <= line <= len(lines):
        return None
    for i in range(line - 1, -1, -1):
        marker = lines[i]
        if marker.startswith("-- script: ") or marker.startswith("-- client script: "):
            return marker.split(": ", 1)[1].strip()
        if marker.startswith("-- ===="):
            return None  # the error is inside the mock/harness/world, not a place script
    return None


def execute_place(place: Place, binary: str | None = None, *,
                  timeout: float = RUN_TIMEOUT_S, slice_mode: bool = False,
                  extra_remotes: tuple[str, ...] | list[str] = ()) -> tuple[object, list[str], str, dict]:
    """Run the place, skipping unparseable scripts one at a time.

    Returns (run, skipped, program, parsed_markers). The caller decides what an
    incomplete run means; a skip is coverage, never a rule verdict.
    """
    bin_path = binary or find_luau()
    skipped: list[str] = []
    program = ""
    data: dict = {}
    run = None
    for _ in range(MAX_SKIPPED_SCRIPTS + 1):
        program = build_program(place, skip=set(skipped), slice_mode=slice_mode,
                                extra_remotes=extra_remotes)
        with tempfile.TemporaryDirectory() as td:
            run = sandbox.run(program, td, binary=bin_path, timeout=timeout)
        data = _parse(run.stdout)
        if data["done"]:
            return run, skipped, program, data
        bad = _parse_error_script(run.stderr or "", program)
        if not bad or bad in skipped:
            return run, skipped, program, data
        skipped.append(bad)
    return run, skipped, program, data


def verify_place(path: str | Path, luau_bin: str | None = None) -> VerifyResult:
    if sandbox.is_windows():
        raise VerifyError(sandbox.WINDOWS_VERIFY_UNSUPPORTED)
    bin_path = luau_bin or find_luau()
    if not bin_path:
        raise VerifyError(luau_missing_hint())

    try:
        from .scan import load_input
        place = load_input(path)
    except Exception as exc:  # noqa: BLE001
        raise VerifyError(str(exc)) from exc

    try:
        run, skipped, program, data = execute_place(place, bin_path, timeout=RUN_TIMEOUT_S)
    except sandbox.SandboxError as exc:
        raise VerifyError(str(exc)) from exc
    out = run.stdout
    err = run.stderr
    if not data["done"]:
        if run.truncated:
            raise VerifyError(
                "the place printed more output than the emulator will read "
                f"({sandbox.MAX_OUTPUT_BYTES // 1024 // 1024} MB) before finishing, so the "
                "run is unreadable. A print loop in the place will do this. Nothing was judged."
            )
        skip_note = (f" skipped unparseable script(s): {', '.join(skipped)}."
                     if skipped else "")
        raise VerifyError(
            "the place did not finish executing under the emulator. "
            f"stderr: {err.strip()[:400] or '(empty)'}{skip_note}"
        )

    result = judge(data, place)
    result.stderr = err.strip()[:2000]
    result.skipped_scripts = skipped
    for bad in skipped:
        result.errors.append(f"{bad}: skipped — its stored source is not valid Luau")
    result.program_bytes = len(program)
    result.seconds = run.seconds
    return result


def to_findings(report: dict) -> list[dict]:
    """Map confirmed exploits into the finding shape the replay renderer expects."""
    out = []
    for c in report.get("confirmed", []):
        out.append({
            "rule_id": c["rule_id"],
            "severity": c["severity"],
            "title": f"CONFIRMED — {c['kind'].replace('_', ' ')}",
            "consequence": c["claim"],
            "path": c["remote"],
            "line": 1,
            "snippet": json.dumps(c.get("evidence", {}), indent=2)[:600],
            "fix": "See the corresponding static finding for the required change.",
            "confidence": "high",
            "confirmed": True,
        })
    return out


def to_report(result: VerifyResult, scan_report: dict, place_path: str) -> dict:
    # Separate a confirmed *claim* (the static rule still claims a
    # trust break) from a confirmed *fact* (an info note whose statement the emulator
    # reproduces). "1 confirmed" must never conflate the two.
    claim_rules = {f.get("rule_id") for f in scan_report.get("findings", [])
                   if f.get("severity") in ("critical", "high", "medium")}
    confirmed = []
    for c in result.confirmed:
        c = dict(c)
        # Row 44 (M2): every confirmation carries its execution mode. Whole-place runs are
        # "whole-place"; handler slices are "handler-sliced/stubbed". They are never pooled.
        c.setdefault("mode", "whole-place")
        c["claim"] = c.get("rule_id") in claim_rules
        confirmed.append(c)
    return {
        "replay_id": scan_report.get("replay_id", ""),
        "kind": "verification",
        "engine": "onyx-static+emulator",
        "engine_version": "0.3.0",
        "language": "luau",
        "place_file": place_path,
        "executed": result.executed,
        "luau": result.luau,
        "skipped_scripts": list(result.skipped_scripts),
        "skipped_script_count": len(result.skipped_scripts),
        "remotes_fuzzed": len(result.remotes),
        "payloads_per_remote": 11,
        "counts": result.counts(),
        "confirmed": confirmed,
        "confirmed_claims": sum(1 for c in confirmed if c["claim"]),
        "confirmed_facts": sum(1 for c in confirmed if not c["claim"]),
        "static_findings": len(scan_report.get("findings", [])),
        "static_unconfirmed": [
            f["rule_id"] for f in scan_report.get("findings", [])
            if f["rule_id"] not in {c["rule_id"] for c in result.confirmed}
        ],
        "errors": result.errors,
        "provenance": {
            "method": "emulation against documented Roblox API contract",
            "executed": True,
            "note": (
                "Confirmed means: this source, run against a mock of the documented "
                "Roblox API, let a client-chosen value reach server state. It is not a "
                "claim that a live server was attacked."
            ),
        },
    }
