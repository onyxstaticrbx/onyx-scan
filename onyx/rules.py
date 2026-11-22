"""Static exploit rules for Roblox/Luau places.

Design rules for this module:

1. Report the CODE FACT, not the exploit claim.
   "This handler grants currency from an argument with no validation" is a
   fact about the source. "You are being exploited" is a claim we cannot make
   from static analysis. The consequence text states the implication; the
   evidence states the fact. That distinction is the whole trust model.

2. Fail closed. When unsure, prefer no finding. A false "critical" destroys
   credibility faster than a missed medium.

3. Deterministic and free. No model calls, no token spend, no GPU.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .lexer import Token, tokenize
from .place import Instance, Place

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

CURRENCY_NAMES = frozenset(
    {
        "leaderstats",
        "coins",
        "cash",
        "money",
        "tokens",
        "gems",
        "credits",
        "points",
        "xp",
        "level",
        "balance",
        "currency",
        "robux",
        "gold",
        "gems",
        "diamonds",
        "scrap",
        "bux",
    }
)

#: Properties whose client-controlled write is cosmetic/visual, never an economy amount.
#: 2026-11-21 (order 50): L016 never had a sink gate, so a tool's own
#: `TransparencyEvent` handler (`v.Transparency = value`) fired as "client number used
#: without a clamp" — twelve cosmetic claims in one place. A client changing its own
#: model's looks is not a vulnerability; these targets are refused unconditionally.
COSMETIC_PROPERTIES = frozenset({
    "transparency", "color", "color3", "brickcolor", "material", "materialvariant",
    "reflectance", "texture", "textureid", "mesh", "meshid", "image", "imagecolor3",
    "imagesize", "size", "cframe", "position", "orientation", "velocity",
    "assemblylinearvelocity", "assemblyangularvelocity", "rotation", "cancollide",
    "formfactor", "bodysize", "heightscale", "widthscale", "depthscale", "headscale",
})

#: Properties that hold an *object reference*, not a scalar. `model.Parent = building`
#: means the client chose the target object; `sound.Volume = volume` means it chose the
#: written number (order 50).
_OBJECT_SLOTS = frozenset({"parent", "adornee", "part0", "part1", "attachment0",
                           "attachment1", "primarypart", "humanoidrootpart"})

#: Calls whose second argument is the value written (first argument is the key/name).
ATTR_WRITERS = frozenset({"SetAttribute", "SetValue"})
STORE_WRITERS = frozenset({"SetAsync", "UpdateAsync", "IncrementAsync", "RemoveAsync"})

#: The three sinks L001 may claim about. A client value reaching any other state write is
#: an info note (`_L002_NOTE`), not a claim — this is what ties the claim sentence to the
#: write it names (order 50; four of the six post-M1 L001 claims named a currency write
#: that the client value never reached).
_CLAIM_SINK_TEXT = {
    "currency": "a currency value",
    "attribute": "an instance attribute",
    "datastore": "a DataStore record",
}

CURRENCY_TYPE_WRITERS = frozenset({":IncrementAsync", ":SetAsync", ":UpdateAsync"})

SERVER_ONLY_SERVICES = frozenset(
    {
        "DataStoreService",
        "ServerStorage",
        "ServerScriptService",
        "NetworkServer",
        "MemoryStoreService",
        "MessagingService",
        "ServerScriptService",
    }
)

GUARD_CALLS = frozenset(
    {
        "typeof",
        "type",
        "assert",
        "math.clamp",
        "math.min",
        "math.max",
        "GetRankInGroup",
        "GetRoleInGroup",
        "IsInGroup",
        "UserOwnsGamePassAsync",
        "PlayerOwnsAsset",
        "os.clock",
        "os.time",
        "tick",
        "Wait",
        "GetPlayerByUserId",
        "GetPlayerFromCharacter",
    }
)

COMPARISON_OPS = frozenset({"<", ">", "<=", ">=", "==", "~="})

OPENERS = frozenset({"function", "if", "for", "while", "do", "repeat"})
CLOSERS = frozenset({"end", "until"})


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    consequence: str
    path: str
    line: int
    snippet: str
    fix: str
    confidence: str = "high"  # high | medium
    confirmed: bool = False  # only true after execution-verified
    #: The concrete sink an L001 claim resolved to (currency | attribute | datastore | state).
    #: The scanner computes it and the claim title names it; the render needs it so two L001
    #: findings do not print the same disjunction. Empty for rules without a sink.
    sink: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "consequence": self.consequence,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "fix": self.fix,
            "confidence": self.confidence,
            "confirmed": self.confirmed,
            "sink": self.sink,
        }


@dataclass
class ScriptContext:
    inst: Instance
    tokens: list[Token]
    lines: list[str]
    role: str  # server | client | module

    def snippet(self, line: int, span: int = 1) -> str:
        lo = max(0, line - 1)
        hi = min(len(self.lines), lo + span)
        return "\n".join(l.rstrip() for l in self.lines[lo:hi]).strip()


@dataclass
class Handler:
    """A connected remote handler.

    Three connection shapes are represented (order 43, M1):

    * inline — `Remote.OnServerEvent:Connect(function(...) ... end)` (original form);
    * named — `...:Connect(handleThing)` / `...:Connect(Module.Trade.Accept)` where the
      function is defined in the same script (resolved through the named-function table);
    * returned — `...:Connect(makeHandler(player))`, a call that returns a function literal
      from a same-script factory (the module-return-closure crossing).

    `handler_name` is the resolved path, `site_line` is the line of the `Connect(` call (which
    may differ from the `function` line for named handlers); rules keep using `line` for the
    snippet, which is the `Connect` site for inline and named alike.
    """

    remote_expr: str
    event: str
    params: list[str]
    body_lo: int
    body_hi: int
    line: int
    handler_name: str = ""
    site_line: int = 0


@dataclass
class ScanResult:
    place_summary: dict
    findings: list[Finding] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "critical"]

    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


# --------------------------------------------------------------------------
# token helpers
# --------------------------------------------------------------------------


def _is(tok: Token, value: str) -> bool:
    return tok.value == value


def _openers_minus_do(tokens: list[Token], i: int) -> bool:
    """True if tokens[i] opens a block (with `do` counted only when standalone)."""
    t = tokens[i]
    if t.value == "do":
        # `while c do` / `for ... do` — the do belongs to the loop
        j = i - 1
        depth = 0
        while j >= 0:
            v = tokens[j].value
            if v in (")", "]"):
                depth += 1
            elif v in ("(", "["):
                depth -= 1
            elif depth == 0 and v in ("while", "for"):
                return False
            elif depth == 0 and v in ("do", "then", "end", ";", ")"):
                break
            j -= 1
        return True
    return t.value in OPENERS


def block_end(tokens: list[Token], start: int) -> int:
    """Index of the token closing the block opened at `start`."""
    depth = 0
    i = start
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t.kind == "eof":
            return n - 1
        if _openers_minus_do(tokens, i):
            depth += 1
        elif t.value in CLOSERS:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def call_span(tokens: list[Token], open_idx: int) -> tuple[int, int]:
    """Given index of '(' return (close_idx, [arg token indices])."""
    depth = 0
    i = open_idx
    n = len(tokens)
    while i < n:
        v = tokens[i].value
        if v in ("(", "[", "{"):
            depth += 1
        elif v in (")", "]", "}"):
            depth -= 1
            if depth == 0:
                return i, list(range(open_idx + 1, i))
        i += 1
    return n - 1, []


def _expr_before(tokens: list[Token], idx: int, lookback: int = 8) -> str:
    """Approximate the expression immediately left of tokens[idx]."""
    parts: list[str] = []
    j = idx - 1
    start = max(-1, idx - lookback)
    while j > start:
        t = tokens[j]
        if t.value in (".", ":"):
            parts.append(t.value)
        elif t.kind in ("name", "string") or t.value in ("]", ")"):
            parts.append(t.value if t.kind != "string" else f'"{t.text}"')
        else:
            break
        j -= 1
    return "".join(reversed(parts))


def _path_text(tokens: list[Token], lo: int, hi: int) -> str | None:
    """`tokens[lo:hi]` as a dotted path (`M.func`, `network:newEvent`), else None."""
    if lo >= hi:
        return None
    parts: list[str] = []
    expect_name = True
    for tok in tokens[lo:hi]:
        if expect_name:
            if tok.kind != "name":
                return None
            parts.append(tok.value)
            expect_name = False
        else:
            if tok.value not in (".", ":"):
                return None
            parts.append(tok.value)
            expect_name = True
    if expect_name:
        return None
    return "".join(parts)


def _normalise_path(path: str) -> str:
    return path.replace(":", ".")


def _path_before(tokens: list[Token], idx: int) -> str | None:
    """The dotted path immediately left of tokens[idx] (`local M.f = ...` -> `M.f`)."""
    parts: list[str] = []
    j = idx - 1
    while j >= 0 and (tokens[j].kind == "name" or tokens[j].value in (".", ":")):
        parts.append(tokens[j].value)
        j -= 1
    if not parts:
        return None
    parts.reverse()
    while parts and parts[0] in ("local", "function"):
        parts = parts[1:]
    path = "".join(parts)
    return path or None


def _function_def_path(tokens: list[Token], fn_idx: int) -> str | None:
    """`function M.f(...)` at fn_idx -> `M.f`."""
    j = fn_idx + 1
    n = len(tokens)
    start = j
    while j < n and (tokens[j].kind == "name" or tokens[j].value in (".", ":")):
        j += 1
    if j >= n or tokens[j].value != "(":
        return None
    return _path_text(tokens, start, j)


def _find_function_by_path(tokens: list[Token], path: str) -> int | None:
    """Index of the `function` token defining `path` in this script, or None."""
    want = _normalise_path(path)
    n = len(tokens)
    for k, tok in enumerate(tokens):
        if tok.value != "function":
            continue
        if tokens[k - 1].value == "=":  # the `function` half of an assignment
            continue
        got = _function_def_path(tokens, k)
        if got is not None and _normalise_path(got) == want:
            return k
    for k, tok in enumerate(tokens):
        if tok.value != "=" or k + 1 >= n or tokens[k + 1].value != "function":
            continue
        got = _path_before(tokens, k)
        if got is not None and _normalise_path(got) == want:
            return k + 1
    return None


def _returned_function(tokens: list[Token], fn_idx: int) -> int | None:
    """The `function` literal a factory returns: `return function(...) ... end`."""
    hi = block_end(tokens, fn_idx)
    for k in range(fn_idx + 1, hi):
        if tokens[k].value != "return":
            continue
        j = k + 1
        while j < hi and tokens[j].value in (",",):
            j += 1
        if j < hi and tokens[j].value == "function":
            return j
    return None


def _call_arg_groups(tokens: list[Token], args: list[int]) -> list[list[int]]:
    """Split the token-index list from `call_span` into one list per argument."""
    groups: list[list[int]] = [[]]
    depth = 0
    for a in args:
        v = tokens[a].value
        if v in ("(", "[", "{"):
            depth += 1
        elif v in (")", "]", "}"):
            depth -= 1
        if v == "," and depth == 0:
            groups.append([])
            continue
        groups[-1].append(a)
    return [g for g in groups if g]


def _handler_from_args(tokens: list[Token], args: list[int]) -> tuple[int, str] | None:
    """Resolve `Connect(<expr>)` to (function token index, human name).

    Handles a named function (`handleThing`, `Module.Trade.Accept`) and a factory call
    that returns a function literal (`makeHandler(player)` — closure crossing). Anonymous
    `function(...)` arguments are handled by the caller before this runs.
    """
    groups = _call_arg_groups(tokens, args)
    if len(groups) != 1:
        return None
    args = groups[0]
    path = _path_text(tokens, args[0], args[-1] + 1)
    if path is not None:
        fn_idx = _find_function_by_path(tokens, path)
        if fn_idx is None:
            return None
        return fn_idx, path
    # call expression: callee path, then `(`; take the function the callee returns.
    open_idx = next((a for a in args if tokens[a].value == "("), None)
    if open_idx is None or open_idx == args[0]:
        return None
    callee = _path_text(tokens, args[0], open_idx)
    if callee is None:
        return None
    fn_idx = _find_function_by_path(tokens, callee)
    if fn_idx is None:
        return None
    inner = _returned_function(tokens, fn_idx)
    if inner is None:
        return None
    return inner, callee + "()"


def _proxy_connect_functions(tokens: list[Token]) -> dict[str, int]:
    """Same-script wrapper functions that connect one of their arguments to a remote.

    `function Net:Connect(name, callback) self.event.OnServerEvent:Connect(callback) end`
    is the wrapper-module crossing in its same-script form; a call `Net:Connect("x", f)`
    then registers `f` as a handler. Cross-script wrappers (a ModuleScript export consumed
    by another script) need the place's require graph and are out of scope for M1 — see
    `scanner/docs/TAINT-SPEC.md`.
    """
    out: dict[str, int] = {}
    n = len(tokens)
    for k, tok in enumerate(tokens):
        if tok.value != "function":
            continue
        path = _function_def_path(tokens, k)
        if path is None:
            continue
        params = set(_function_params(tokens, k))
        if not params:
            continue
        hi = block_end(tokens, k)
        for j in range(k + 1, hi):
            if tokens[j].value not in ("OnServerEvent", "OnServerInvoke"):
                continue
            m = j + 1
            if m < n and tokens[m].value in (":", "."):
                m += 1
            if m >= n or tokens[m].value not in ("Connect", "connect"):
                continue
            close, args = call_span(tokens, m + 1)
            if not args:
                continue
            if any(tokens[a].value in params for a in args):
                out[_normalise_path(path)] = k
                break
    return out


def _proxy_handler_sites(tokens: list[Token], proxies: dict[str, int]) -> list[Handler]:
    """Calls into a same-script wrapper: `Net:Connect("event", handler)` -> Handler."""
    out: list[Handler] = []
    if not proxies:
        return out
    by_tail: dict[str, list[str]] = {}
    for path in proxies:
        by_tail.setdefault(path.rsplit(".", 1)[-1], []).append(path)
    n = len(tokens)
    for i, tok in enumerate(tokens):
        if tok.kind != "name" or tok.value not in by_tail:
            continue
        if i + 1 >= n or tokens[i + 1].value != "(":
            continue
        if i == 0 or tokens[i - 1].value not in (".", ":"):
            continue
        before = _path_before(tokens, i)
        if before is None:
            continue
        call_path = _normalise_path(before + tok.value)
        if call_path not in proxies:
            continue
        close, args = call_span(tokens, i + 1)
        groups = _call_arg_groups(tokens, args)
        if len(groups) < 2:
            continue
        resolved = _handler_from_args(tokens, groups[1])
        if resolved is None:
            continue
        fn_idx, name = resolved
        out.append(
            Handler(
                remote_expr=call_path,
                event="OnServerEvent",
                params=_function_params(tokens, fn_idx),
                body_lo=fn_idx,
                body_hi=block_end(tokens, fn_idx),
                line=tok.line,
                handler_name=name,
                site_line=tok.line,
            )
        )
    return out


def find_handlers(tokens: list[Token]) -> list[Handler]:
    """Locate remote handler connections and their function bodies.

    Inline, named and returned handlers (see `Handler`); plus same-script wrapper calls.
    A named handler defined in another script/ModuleScript cannot be resolved here and is
    deliberately not guessed at — a guessed taint is a false claim.
    """
    handlers: list[Handler] = []
    n = len(tokens)
    for i, t in enumerate(tokens):
        if t.kind != "name" or t.value not in (
            "OnServerEvent",
            "OnClientEvent",
            "OnServerInvoke",
            "OnClientInvoke",
        ):
            continue

        # form A: .OnServerEvent:Connect(...)   form B: :OnServerEvent(...)
        j = i + 1
        if j < n and tokens[j].value in (":", "."):
            j += 1
            if j < n and tokens[j].value in ("Connect", "connect"):
                j += 1
            elif tokens[j - 1].value == ":":  # :OnServerEvent( — malformed but seen
                pass
        if j >= n or tokens[j].value != "(":
            continue
        close, args = call_span(tokens, j)
        if not args:
            continue
        first = tokens[args[0]]
        if first.value == "function":
            body_lo = args[0]
            body_hi = block_end(tokens, body_lo)
            params = _function_params(tokens, body_lo)
            handlers.append(
                Handler(
                    remote_expr=_expr_before(tokens, i),
                    event=t.value,
                    params=params,
                    body_lo=body_lo,
                    body_hi=body_hi,
                    line=t.line,
                    site_line=t.line,
                )
            )
            continue
        resolved = _handler_from_args(tokens, args)
        if resolved is None:
            continue
        fn_idx, name = resolved
        handlers.append(
            Handler(
                remote_expr=_expr_before(tokens, i),
                event=t.value,
                params=_function_params(tokens, fn_idx),
                body_lo=fn_idx,
                body_hi=block_end(tokens, fn_idx),
                line=t.line,
                handler_name=name,
                site_line=t.line,
            )
        )

    handlers.extend(_proxy_handler_sites(tokens, _proxy_connect_functions(tokens)))
    return handlers


def _function_params(tokens: list[Token], fn_idx: int) -> list[str]:
    n = len(tokens)
    i = fn_idx + 1
    while i < n and tokens[i].value != "(":
        i += 1
    if i >= n:
        return []
    close, args = call_span(tokens, i)
    params: list[str] = []
    for idx in args:
        tk = tokens[idx]
        if tk.kind == "name" and tk.value not in ("self",):
            params.append(tk.value)
    return params


def _body_tokens(tokens: list[Token], h: Handler) -> list[Token]:
    return tokens[h.body_lo : h.body_hi + 1]


def _calls_in(tokens: list[Token], h: Handler) -> list[tuple[int, str]]:
    """(absolute token index, name) for every call in the handler body."""
    out: list[tuple[int, str]] = []
    body = _body_tokens(tokens, h)
    for k, t in enumerate(body):
        if t.kind == "name" and k + 1 < len(body) and body[k + 1].value in ("(", "."):
            out.append((h.body_lo + k, t.value))
    return out


def _early_return_branch(body: list[Token]) -> bool:
    """`if <anything> then ... return ... end` — an explicit rejection path."""
    n = len(body)
    for k, t in enumerate(body):
        if t.value != "if":
            continue
        depth = 0
        then_at = None
        for j in range(k + 1, min(n, k + 80)):
            value = body[j].value
            if value in ("(", "["):
                depth += 1
            elif value in (")", "]"):
                depth -= 1
            elif value == "then" and depth <= 0:
                then_at = j
                break
        if then_at is None:
            continue
        for j in range(then_at + 1, min(n, then_at + 60)):
            value = body[j].value
            if value == "return":
                return True
            if value == "end":
                break
    return False


def _lookup_on_param(body: list[Token], data_params: set[str]) -> bool:
    """`if Table[param] then` — an allowlist/dictionary keyed by client input.

    Only a lookup *used as a condition* counts. `dialogs[npc](...)` is a dispatch
    table: it chooses which handler runs, it does not reject a bad key, and treating it
    as a guard is the same mistake as counting `if data.Type == "Hurt"` as validation.
    """
    if not data_params:
        return False
    # ranges of the condition part of every `if ... then` in the body
    conditions: list[tuple[int, int]] = []
    for k, t in enumerate(body):
        if t.value != "if":
            continue
        depth = 0
        for j in range(k + 1, len(body)):
            value = body[j].value
            if value in ("(", "["):
                depth += 1
            elif value in (")", "]"):
                depth -= 1
            elif value == "then" and depth <= 0:
                conditions.append((k, j))
                break
    for k, t in enumerate(body):
        if t.value != "[":
            continue
        if not any(lo < k < hi for lo, hi in conditions):
            continue
        for j in range(k + 1, min(len(body), k + 8)):
            value = body[j].value
            if value == "]":
                break
            if value in data_params:
                return True
    return False


def _guard_strength(tokens: list[Token], h: Handler) -> str:
    """How much the handler's own code argues that client input is checked.

    `strong` — a value-level check: `typeof`, `type`, `assert`, `math.clamp/min/max`,
    an ownership or group lookup, or a comparison against a parameter. Treat as
    checked and say nothing: a scanner that reports working code is noise.

    `weak` — evidence of *intent* to validate without proof that it covers the payload:
    an early `if ... then return end`, a dictionary keyed by the parameter, a `:Kick`,
    a rate limit. Worth one quiet note, never a critical.

    `none` — nothing between the event and the write. That is the critical case.
    """
    body = _body_tokens(tokens, h)
    names = {t.value for t in body if t.kind in ("name", "keyword")}
    dotted = set()
    for k in range(len(body) - 2):
        if body[k].kind == "name" and body[k + 1].value == "." and body[k + 2].kind == "name":
            dotted.add(f"{body[k].value}.{body[k + 2].value}")

    data_params = set(h.params) - {"player", "plr", "self"}

    # strong: something actually checks a value — and it must be *called*. 2026-11-21
    # (order 50): a script that declares `type = "Points"` made the identical unguarded
    # donate handler read as "strong", so one of two identical onDonate/onGive shapes was
    # silently withdrawn while the other was critical. A bare name is data, not a check.
    def _called(names_to_find: set[str]) -> bool:
        for k, t in enumerate(body):
            if (t.kind == "name" and t.value in names_to_find
                    and k + 1 < len(body) and body[k + 1].value == "("):
                return True
        return False

    if _called({"typeof", "type", "assert"}):
        return "strong"
    if dotted & {"math.clamp", "math.min", "math.max"}:
        return "strong"
    if _called({"GetRankInGroup", "GetRoleInGroup", "IsInGroup"}):
        return "strong"
    if _called({"UserOwnsGamePassAsync", "PlayerOwnsAsset"}):
        return "strong"
    # A comparison is only a guard when it *constrains* the value. `data["Type"] ==
    # "Hurt"` is a dispatch, not a check — treating it as validation is how a dispatch
    # table with no type check reads as "guarded". Lengths, numeric bounds and
    # tonumber() do constrain.
    for k, t in enumerate(body):
        if t.value not in COMPARISON_OPS or not data_params:
            continue
        window = body[max(0, k - 3) : k + 4]
        values = {x.value for x in window}
        if not (values & data_params):
            continue
        has_number = any(x.kind == "number" for x in window)
        nearby = {x.value for x in body[max(0, k - 8) : k + 8]}
        nearby_call = any(
            body[j].value in ("typeof", "type", "tonumber", "assert")
            and j + 1 < len(body) and body[j + 1].value == "("
            for j in range(max(0, k - 8), min(len(body) - 1, k + 8))
        )
        if has_number or "#" in nearby or nearby_call:
            return "strong"

    # weak: intent, without proof it covers the payload
    if _early_return_branch(body):
        return "weak"
    if _lookup_on_param(body, data_params):
        return "weak"
    if "Kick" in names:
        return "weak"
    for k in range(len(body) - 2):
        if body[k].value == "os" and body[k + 2].value in ("clock", "time", "difftime"):
            return "weak"
        if body[k].value == "tick":
            return "weak"
    return "none"


def _has_guard(tokens: list[Token], h: Handler) -> bool:
    """True when the handler argues, however weakly, that input is checked."""
    return _guard_strength(tokens, h) != "none"


def _mutates_state(tokens: list[Token], h: Handler) -> tuple[bool, str]:
    """Does the handler write to currency / values / datastore?"""
    body = _body_tokens(tokens, h)
    for k in range(len(body) - 1):
        t = body[k]
        if t.value in ("=", "+=", "-=") and k > 0 and body[k - 1].value == "Value":
            # Use the whole written target, not a 6-token lookback: a long path
            # (`Workspace.Settings.PlayerMoney:FindFirstChild(Player.Name).Value`) kept
            # "money" out of the window and withdrew a real claim (order 50).
            if _currency_target(_write_target_text(body, k)):
                return True, "a currency value"
        if t.kind == "name" and t.value in ("IncrementAsync", "SetAsync", "UpdateAsync"):
            return True, "a DataStore record"
        if t.kind == "name" and t.value in ("SetAttribute", "SetValue"):
            return True, "an instance attribute"
    # 2026-11-21 (claim fix): the old body-text match -- "the body mentions a currency
    # name and contains an `=`" -- labelled unrelated writes as currency writes and was the
    # source of L001's 7/14 measured false positives. The claim is now only made when a
    # real write's value is client-derived (`_client_taint_hits`), and the written target
    # is named in the finding.
    return False, ""


def _truncated_function(tokens: list[Token]) -> bool:
    """True when the source ends inside a `function` block.

    A labelled snippet is a window around one line; it usually cuts a handler in half.
    Rules that reason about the *absence* of a return (L008) must not read a window as
    proof that the rest of the handler does not exist.
    """
    for k, tk in enumerate(tokens):
        if tk.value != "function":
            continue
        close = block_end(tokens, k)
        if close >= len(tokens) - 1:  # only the eof sentinel means "no closing end"
            return True
    return False


#: Call names whose verb means "this changes state". A client value reaching one of
#: these with no guard is the L002 case: the write happens inside the callee, but the
#: trust boundary is crossing right here. Curated, not exhaustive: a false negative
#: costs one missed finding, a false positive costs the user's trust.
MUTATING_VERBS = (
    "set", "setvalue", "setattribute", "increment", "decrement", "update", "remove",
    "delete", "destroy", "take", "damage", "kill", "kick", "ban", "grant", "give",
    "reward", "award", "purchase", "buy", "unlock", "spawn", "complete", "perform",
    "apply", "teleport", "equip", "unequip", "save", "wipe", "clear", "heal",
    "respawn", "swap", "place", "move",
)


def _mutating_name(name: str) -> bool:
    lowered = name.lower()
    return any(verb in lowered for verb in MUTATING_VERBS)


def _taint_names(body: list[Token], client: list[str]) -> set[str]:
    """Client-supplied names, plus local names assigned from them (one fixpoint pass).

    `local amount = args[1]` then `Cash.Value += amount` is the same bug as writing
    `args[1]` directly; the 2026-11-20 batch showed the direct-only test misses it.
    """
    tainted = set(client)
    changed = True
    while changed:
        changed = False
        for k in range(1, len(body)):
            if body[k].value != "=":
                continue
            target = body[k - 1]
            if target.kind != "name" or target.value in tainted:
                continue
            # A dotted/indexed write (`Cash.Value = amount`) must not taint its own last
            # name (`Value`): only a plain local receives the client value.
            if k >= 2 and body[k - 2].value in (".", "]", "["):
                continue
            hi = k + 1
            while (hi < len(body) and body[hi].value not in (";", "end")
                   and body[hi].line == body[k].line):
                hi += 1
            if any(body[j].value in tainted for j in range(k + 1, hi)):
                tainted.add(target.value)
                changed = True
        # `for i, v in pairs(newData) do ... store[i] = v` — the loop variable carries
        # the client value (2026-11-21, order 50: two real "save my data" handlers were
        # dropped because only `=` assignments propagated taint).
        for k, t in enumerate(body):
            if t.value != "for":
                continue
            names: list[str] = []
            in_idx: int | None = None
            j = k + 1
            while j < len(body) and body[j].value != "do":
                if body[j].value == "in":
                    in_idx = j
                elif in_idx is None and body[j].kind == "name":
                    names.append(body[j].value)
                j += 1
            if in_idx is None:
                continue
            rhs = {body[x].value for x in range(in_idx + 1, j) if body[x].kind == "name"}
            for name in names:
                if name not in tainted and rhs & tainted:
                    tainted.add(name)
                    changed = True
    return tainted


def _write_target_text(body: list[Token], eq_idx: int) -> str:
    """The written target as source text (`player.leaderstats.Coins.Value`).

    Walks back only inside one dotted/indexed chain; crossing a call parenthesis would
    merge the previous statement into the target (order 50: a `TakeDamage(...)` call
    leaked into the target text of the following currency write).
    """
    j = eq_idx - 1
    depth = 0
    while j > 0:
        value = body[j].value
        if value in (")", "]"):
            depth += 1
        elif value in ("(", "["):
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and not (body[j].kind in ("name", "string", "number")
                                 or value in (".", ":")):
            break
        j -= 1
    text = "".join(t.value for t in body[j + 1:eq_idx + 1])
    return text[:80]


def _value_use(body: list[Token], name: str, lo: int = 0, hi: int | None = None) -> bool:
    """True when `name` occurs in [lo, hi) as a value, not as an object or callee.

    `skipped:SetAttribute(...)` is a target; `amount * 2` is a value. Mirrors the
    object-use test in `_param_used_as_number` (order 50).
    """
    hi = len(body) if hi is None else hi
    for k in range(max(0, lo), min(len(body), hi)):
        if body[k].kind != "name" or body[k].value != name:
            continue
        prev = body[k - 1].value if k >= 1 else ""
        nxt = body[k + 1].value if k + 1 < len(body) else ""
        # `data["Damage"]` / `data[i]` is a value read out of a client payload table;
        # `skipped:SetAttribute` and `troop.Config` are object/property paths, not values.
        if nxt in (".", ":", "(") or prev in (".", ":", "["):
            continue
        return True
    return False


def _any_value_use(body: list[Token], names: set[str], lo: int, hi: int) -> bool:
    return any(_value_use(body, body[k].value, k, k + 1)
               for k in range(max(0, lo), min(len(body), hi))
               if body[k].value in names)


def _bare_names_only(body: list[Token], lo: int, hi: int) -> bool:
    """True when the expression is just names/commas (`building`, `a, b`)."""
    for k in range(max(0, lo), min(len(body), hi)):
        if body[k].kind == "name" or body[k].value == ",":
            continue
        return False
    return True


def _cosmetic_target(target: str) -> bool:
    low = target.lower()
    return any(prop in low for prop in COSMETIC_PROPERTIES)


def _currency_target(target: str) -> bool:
    low = target.lower()
    return ".value" in low and any(c in low for c in CURRENCY_NAMES)


def _client_taint_hits(tokens: list[Token], h: Handler) -> list[tuple[int, str, str, str]]:
    """Every place a client-supplied value reaches a state change in this handler.

    Returns `(line, what, kind, sink)`:

    * `kind == "value"` — the client chose the *written value* (`Cash.Value = amount`,
      `Store:SetAsync(uid, clientTable)`, `part:SetAttribute("X", amount)`).
    * `kind == "target"` — the client chose only the *object* the state write happens on
      (`skipped:SetAttribute("Skipped", true)`, `queueFolder.Parent = building`). 2026-11-21
      order 50: L001's claim text says the client chose the written value, so a target-only
      hit is a context note, never a claim.
    * `sink` is `currency`, `attribute`, `datastore` or `state`.

    Client-supplied means: a named parameter after the player, or a value read out of one
    (`data["Victim"]`, `data.Victim`) — the payload-table shape the first real-code
    measurement found the old rule missing. A state change means: a call whose name implies
    mutation, or an assignment into server-owned state (a dotted/indexed target, not
    `local x =`). Forwarding a parameter to a signal (`Loopback:Fire(...)`) and delegating a
    display id are therefore not hits, which is the point.
    """
    body = _body_tokens(tokens, h)
    client = list(h.params[1:])
    if not client:
        return []
    client_set = _taint_names(body, client)
    hits: list[tuple[int, str, str, str]] = []
    # Tables the handler persists: `store[i] = v` then `Store:SetAsync(uid, store)` is a
    # DataStore write of client data even though the table itself is not a client
    # argument (order 50; two "save my data" handlers were lost without this).
    store_args: set[str] = set()
    for k, t in enumerate(body):
        if t.kind != "name" or t.value not in STORE_WRITERS:
            continue
        if k + 1 < len(body) and body[k + 1].value == "(":
            close_arg, _ = call_span(body, k + 1)
            store_args |= {body[j].value for j in range(k + 2, min(close_arg, len(body)))
                           if body[j].kind == "name"}

    def tainted(lo: int, hi: int) -> bool:
        for k in range(max(0, lo), min(len(body), hi)):
            if body[k].value in client_set:
                return True
        return False

    def arg_ranges(open_idx: int) -> tuple[int, list[tuple[int, int]]]:
        close, _ = call_span(body, open_idx)
        return close, _top_level_args(body, open_idx)

    # calls: name ( args )
    for k in range(len(body) - 1):
        if body[k].kind != "name" or body[k + 1].value != "(":
            continue
        close, args = call_span(body, k + 1)
        if not args:
            continue
        name = body[k].value
        receiver_tainted = False
        if k >= 2 and body[k - 1].value in (":", "."):
            receiver = body[k - 2]
            if receiver.value in client_set:
                receiver_tainted = True
            elif receiver.value == "]" and tainted(max(0, k - 10), k - 2):
                receiver_tainted = True
        groups = _top_level_args(body, k + 1)
        value_groups = groups[1:] if len(groups) > 1 else []
        value_tainted = any(_any_value_use(body, client_set, lo, hi) for lo, hi in value_groups)

        if name in ATTR_WRITERS:
            # (name, value): the value slot is the second argument.
            if value_tainted:
                hits.append((body[k].line, f"`{name}()`", "value", "attribute"))
            elif receiver_tainted or (groups and tainted(groups[0][0], groups[0][1])):
                hits.append((body[k].line, f"`{name}()`", "target", "attribute"))
            continue
        if name in STORE_WRITERS:
            # (key, value) / (key, transform): a tainted value or a tainted transform body
            # is value-control; only the receiver/key tainted is target-control.
            if (value_tainted
                    or any(tainted(lo, hi) for lo, hi in value_groups)
                    or (value_groups and any(
                        t.kind == "name" and t.value in client_set
                        for t in body[value_groups[0][0]:value_groups[-1][1]]))):
                hits.append((body[k].line, f"`{name}()`", "value", "datastore"))
            elif receiver_tainted or (groups and tainted(groups[0][0], groups[0][1])):
                hits.append((body[k].line, f"`{name}()`", "target", "datastore"))
            continue
        if not (_mutating_name(name)
                and (receiver_tainted or tainted(args[0], close)
                     or any(body[a].value in client_set for a in args))):
            continue
        # A generic mutating verb: a tainted value argument is value-control; a tainted
        # receiver with only literal/derived arguments is the client picking the object.
        arg_value = any(_any_value_use(body, client_set, lo, hi)
                        for lo, hi in groups if groups)
        if arg_value:
            hits.append((body[k].line, f"`{name}()`", "value", "state"))
        elif receiver_tainted or tainted(args[0], close):
            hits.append((body[k].line, f"`{name}()`", "target", "state"))

    # assignments into server-owned state
    for k in range(1, len(body)):
        if body[k].value not in ("=", "+=", "-="):
            continue
        target = k - 1
        dotted = (target >= 2 and body[target].kind == "name"
                  and body[target - 1].value in (".", "]"))
        if not dotted and target >= 1 and body[target].value == "]":
            dotted = True  # `self[key] = value`: an indexed write, same rule
        is_local = (target >= 1 and body[target - 1].value == "local")
        if is_local:
            continue
        rhs_hi = k + 1
        statement_end = rhs_hi
        while statement_end < len(body) and body[statement_end].value not in (";", "end"):
            if body[statement_end].line != body[k].line:
                break
            statement_end += 1
        if not (dotted and tainted(max(0, k - 8), statement_end)):
            continue
        text = _write_target_text(body, k)
        root = text.split(".")[0].split("[")[0]
        if _currency_target(text):
            sink = "currency"
        elif root in store_args:
            sink = "datastore"
        else:
            sink = "state"
        rhs_value = _any_value_use(body, client_set, rhs_hi, statement_end)
        if rhs_value:
            # `part.Parent = building` (bare instance into an object slot) is
            # target-control; `Cash.Value = amount` is value-control even when bare,
            # because the sink is the number.
            object_slot = any(prop in text.lower() for prop in _OBJECT_SLOTS)
            bare = _bare_names_only(body, rhs_hi, statement_end)
            kind = "target" if (bare and object_slot) else "value"
            hits.append((body[k].line, f"`{text}`", kind, sink))
        elif tainted(rhs_hi, statement_end):
            # client chooses the object whose data is read: `Price.Value = ... item.Cost`
            hits.append((body[k].line, f"`{text}` (client-chosen object)", "target", sink))
        elif tainted(max(0, k - 8), k):
            # state written *through* a client-chosen key: model[audio].Pitch = ...
            hits.append((body[k].line, f"`{text}` (client-chosen key)", "target", sink))
    return hits


@dataclass
class LocalFunction:
    """A function defined in the same script, by name, with its parameter list."""

    name: str
    params: list[str]
    body_lo: int
    body_hi: int
    line: int


def _local_functions(tokens: list[Token]) -> list[LocalFunction]:
    """Every named function in the script, in source order.

    Local taint propagation needs this: the client value usually reaches the sink one
    call away (`FunctionModule[6](...)`, `shoot(...)`, `dialogs[npc](...)`), and the
    callee is defined in the same file. Anonymous functions are skipped — they have no
    call site we can reason about.
    """
    out: list[LocalFunction] = []
    n = len(tokens)
    for k, t in enumerate(tokens):
        if t.value != "function":
            continue
        j = k + 1
        while j < n and tokens[j].value != "(" and j < k + 8:
            j += 1
        if j >= n or tokens[j].value != "(" or tokens[j - 1].kind != "name":
            continue  # anonymous function, or a call named `function`
        close = block_end(tokens, k)
        if close <= k:
            continue
        out.append(
            LocalFunction(
                name=tokens[j - 1].value,
                params=_function_params(tokens, k),
                body_lo=k,
                body_hi=close,
                line=t.line,
            )
        )
    return out


def _table_slot_functions(tokens: list[Token]) -> dict[str, list[LocalFunction]]:
    """Functions stored into a local table, keyed by the table's identifier.

    Real places dispatch through tables constantly: `FunctionModule[6](Sound, ...)`,
    `dialogs[npcName](player, ...)`, `handlers[action](...)`. The call site names a
    table, not a function, so the one-hop pass has to resolve the table's slots first.
    Two forms are collected: `Table[...] = function(...)` / `Table.name = function(...)`
    assignments, and `Table = { a = function(...) }` literals.
    """
    out: dict[str, list[LocalFunction]] = {}
    n = len(tokens)

    def register(table: str, fn_idx: int) -> None:
        close = block_end(tokens, fn_idx)
        if close <= fn_idx:
            return
        out.setdefault(table, []).append(
            LocalFunction(
                name=table,
                params=_function_params(tokens, fn_idx),
                body_lo=fn_idx,
                body_hi=close,
                line=tokens[fn_idx].line,
            )
        )

    for k in range(2, n):
        if tokens[k].value != "=":
            continue
        nxt = tokens[k + 1] if k + 1 < n else None
        if nxt is None or nxt.value != "function":
            continue
        # Table[...] = function / Table.name = function
        if tokens[k - 1].value == "]":
            depth = 0
            j = k - 1
            while j >= 0:
                if tokens[j].value == "]":
                    depth += 1
                elif tokens[j].value == "[":
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            if j >= 1 and tokens[j - 1].kind == "name":
                register(tokens[j - 1].value, k + 1)
        elif tokens[k - 1].kind == "name" and k >= 3 and tokens[k - 2].value == ".":
            if tokens[k - 3].kind == "name":
                register(tokens[k - 3].value, k + 1)
    return out


ONE_HOP_DEPTH = 1


def _one_hop_hits(
    tokens: list[Token],
    h: Handler,
    local_fns: list[LocalFunction],
    depth: int = ONE_HOP_DEPTH,
    seen: frozenset[str] = frozenset(),
    table_fns: dict[str, list[LocalFunction]] | None = None,
) -> list[tuple[int, str, str, str]]:
    """Client value handed to a local function whose body then reaches a sink.

    This is deliberately one hop: follow an argument into a function defined in the
    *same script*, and if that function's own parameters reach a mutating call or a
    write, the caller is at the trust boundary. Two hops is where a static triage
    scanner starts inventing findings from helpers it cannot resolve, so the depth is
    a constant and the finding text says how far it followed.
    """
    if depth <= 0:
        return []
    body = _body_tokens(tokens, h)
    client = set(h.params[1:])
    if not client:
        return []
    by_name: dict[str, list[LocalFunction]] = {}
    for fn in local_fns:
        if fn.name in seen:
            continue
        by_name.setdefault(fn.name, []).append(fn)
    if table_fns is None:
        table_fns = _table_slot_functions(tokens)

    hits: list[tuple[int, str]] = []
    for k in range(len(body) - 1):
        if body[k].kind != "name":
            continue
        if body[k + 1].value == "(":
            targets = by_name.get(body[k].value)
            open_idx = k + 1
        elif body[k + 1].value == "[":
            # Table dispatch: `FunctionModule[6](...)`, `dialogs[npcName](...)`.
            targets = table_fns.get(body[k].value)
            if not targets:
                continue
            bracket_depth = 0
            j = k + 1
            while j < len(body):
                if body[j].value == "[":
                    bracket_depth += 1
                elif body[j].value == "]":
                    bracket_depth -= 1
                    if bracket_depth == 0:
                        break
                j += 1
            if j + 1 >= len(body) or body[j + 1].value != "(":
                continue
            open_idx = j + 1
        else:
            continue
        if not targets:
            continue
        close, args = call_span(body, open_idx)
        if not args:
            continue
        tainted_arg = any(
            body[a].value in client
            for a in args
        ) or any(
            body[i].value in client for i in range(args[0], min(close, len(body)))
        )
        if not tainted_arg:
            continue
        for fn in targets:
            if fn.name in seen:
                continue
            fake = Handler(
                remote_expr="",
                event="",
                params=["__caller__"] + fn.params,
                body_lo=fn.body_lo,
                body_hi=fn.body_hi,
                line=fn.line,
            )
            inner = _client_taint_hits(tokens, fake)
            if not inner and depth > 1:
                inner = _one_hop_hits(tokens, fake, local_fns,
                                      depth=depth - 1, seen=seen | {fn.name})
            if inner:
                # Prefer the value-control hit: it is the one that can carry a claim.
                inner.sort(key=lambda x: 0 if x[2] == "value" else 1)
                what = inner[0][1]
                kind = inner[0][2]
                sink = inner[0][3]
                hops = "one call" if depth == ONE_HOP_DEPTH else f"{ONE_HOP_DEPTH - depth + 1} calls"
                hits.append((body[k].line, f"`{body[k].value}()` → {what} ({hops} away)",
                             kind, sink))
                break
    return hits


def _mentions_param_object(body: list[Token], params: set[str]) -> bool:
    for t in body:
        if t.kind == "name" and t.value in params:
            return True
    return False


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------


#: Demoted 2026-11-21 (order 7c): the post-fix batch measured this rule at 9/25 = 37.5% tp,
#: below the 60% line -- 15 of 25 were display/sound/aim or server-validated effects. The rule
#: had already been narrowed twice, so the claim is withdrawn rather than narrowed a third
#: time; the shape stays visible as a context note and does not enter a precision denominator.
_L002_NOTE = (
    "Context note, not a vulnerability claim: client input reaches a server state write. "
    "Measured 9/25 = 37.5% as a defect on the 2026-11-21 post-fix batch, below the 60% "
    "line; fifteen of the twenty-five were display/sound/aim or server-validated effects. "
    "The rule was narrowed twice before this and still could not carry the claim. Read it "
    "as 'confirm the callee validates', not as a defect. Demoted 2026-11-21."
)


_L002_TARGET_NOTE = (
    "Context note, not an L001 claim: the client chooses which instance/object the write "
    "lands on, but the written value is a constant or server-derived (e.g. "
    "`skipped:SetAttribute(\"Skipped\", true)`). That is a target-control/authority "
    "question, not the 'client chose the amount' claim L001 makes. Downgraded from a claim "
    "on 2026-11-21 (order 50) after four of six new L001 claims were measured to be this "
    "shape."
)


def rule_unvalidated_remote_handlers(ctx: ScriptContext, place: Place) -> list[Finding]:
    """Client input reaching server state.

    Three outcomes, in order of what the code actually shows:

    * **value-control, no guard** → critical. The rule's consequence text is literal: a
      player chooses their own values.
    * **value-control, weak guard** → one low-severity note. Something was intended to
      check the input; the scanner cannot prove it covers every path.
    * **target-control only** → a context note, never a claim (order 50, 2026-11-21). The
      claim text says the client chose the *written value*; `skipped:SetAttribute("Skipped",
      true)` has the client choosing the object and the value being a server constant.
    * **no client-supplied argument at all** → nothing: a handler that takes nothing cannot
      write "whatever arrives".
    """
    out: list[Finding] = []
    tokens = ctx.tokens
    local_fns = _local_functions(tokens)
    for h in find_handlers(tokens):
        if h.event not in ("OnServerEvent", "OnServerInvoke"):
            continue
        params = [p for p in h.params if p not in ("player", "plr", "self")]
        strength = _guard_strength(tokens, h)
        mutates, _what = _mutates_state(tokens, h)

        if mutates:
            hits = _client_taint_hits(tokens, h)
            value_hits = [x for x in hits
                          if x[2] == "value" and x[3] in _CLAIM_SINK_TEXT]
            target_hits = [x for x in hits if x[2] == "target"]
            hops: list[tuple[int, str, str, str]] = []
            if not value_hits:
                hops = [x for x in _one_hop_hits(tokens, h, local_fns)
                        if x[2] == "value" and x[3] in _CLAIM_SINK_TEXT]
            if value_hits:
                claim_what = _CLAIM_SINK_TEXT[value_hits[0][3]]
            elif hops:
                claim_what = _CLAIM_SINK_TEXT[hops[0][3]]
            else:
                claim_what = ""
            if claim_what and params:
                resolved_sink = value_hits[0][3] if value_hits else hops[0][3]
                if strength == "none":
                    out.append(Finding(
                        rule_id="ONYX-L001",
                        severity="critical",
                        title=f"Remote handler writes a client-chosen value into {claim_what}",
                        consequence=(
                            "Any client can fire this remote with arbitrary arguments. The "
                            f"handler writes {claim_what}, and the value written comes from the "
                            "client argument, so a player chooses it."
                        ),
                        path=ctx.inst.path, line=h.line, snippet=ctx.snippet(h.line),
                        fix="Validate every argument (typeof + clamp) before mutating, "
                            "or resolve the value server-side instead of accepting it.",
                        confidence="high", sink=resolved_sink,
                    ))
                elif strength == "weak":
                    out.append(Finding(
                        rule_id="ONYX-L001",
                        severity="low",
                        title=f"Remote handler writes a client-chosen value into {claim_what}",
                        consequence=(
                            "The handler writes " + claim_what + " from a client argument and does "
                            "contain a check, but the scanner cannot prove the check runs on "
                            "every path that reaches the write. A guard that misses one branch "
                            "is the same bug with a comment above it."
                        ),
                        path=ctx.inst.path, line=h.line, snippet=ctx.snippet(h.line),
                        fix="Confirm the check rejects every unexpected type and range "
                            "before the write, including the branch that does not return.",
                        confidence="low", sink=resolved_sink,
                    ))
            elif target_hits and target_hits[0][3] in ("currency", "attribute", "datastore"):
                # The shape used to be an L001 claim; it is now a note because the client
                # chose the target, not the written value.
                line, _what, _kind, _sink = target_hits[0]
                out.append(Finding(
                    rule_id="ONYX-L002",
                    severity="info",
                    title="Context note — client chooses the target instance, not the value",
                    consequence=_L002_TARGET_NOTE,
                    path=ctx.inst.path, line=line, snippet=ctx.snippet(line),
                    fix="Check ownership/authority for the instance the client names "
                        "(IsDescendantOf the player's character, a server-side lookup) — the "
                        "value written here is not client-controlled.",
                    confidence="low",
                ))
            # No client-supplied value and no target-control shape: ordinary game logic,
            # not a finding — a scanner that reported it would flag every shop on the
            # platform.
        else:
            hits = _client_taint_hits(tokens, h)
            hops: list[tuple[int, str, str, str]] = []
            if not hits:
                # One call away: the client value is handed to a function defined in
                # this script, and *that* function writes. Batch-3 misses were mostly
                # this shape (`shoot(...)`, `FunctionModule[n](...)`, `item[method](...)`).
                hops = _one_hop_hits(tokens, h, local_fns)
            if not hits and not hops:
                # Accepting arguments and forwarding them — a relay, a dispatcher, a
                # display delegation — is not a vulnerability. 2026-11-21: the info note
                # this used to emit is gone (the 324-finding batch showed it was noise on
                # every measured relay). Nothing is reported for this shape.
                continue
            if hops:
                line, what = hops[0][0], hops[0][1]
                out.append(Finding(
                    rule_id="ONYX-L002",
                    severity="info",
                    title=f"Context note — client input reaches {what}",
                    consequence=_L002_NOTE,
                    path=ctx.inst.path, line=line, snippet=ctx.snippet(line),
                    fix="Validate the argument at the boundary (typeof, bounds, ownership) "
                        "or resolve it server-side; passing it through does not move the "
                        "trust boundary.",
                    confidence="low",
                ))
                continue
            line, what = hits[0][0], hits[0][1]
            out.append(Finding(
                rule_id="ONYX-L002",
                severity="info",
                title=f"Context note — client input reaches {what}",
                consequence=_L002_NOTE,
                path=ctx.inst.path, line=line, snippet=ctx.snippet(line),
                fix="Validate every argument (typeof + clamp) before it reaches the call, "
                    "or resolve the value server-side instead of accepting it.",
                confidence="low",
            ))
    return out


def _top_level_args(tokens: list[Token], open_idx: int) -> list[tuple[int, int]]:
    """Token ranges (start, end-exclusive) of each top-level argument of a call."""
    close, _args = call_span(tokens, open_idx)
    ranges: list[tuple[int, int]] = []
    depth = 0
    start = open_idx + 1
    for i in range(open_idx + 1, close):
        v = tokens[i].value
        if v in ("(", "[", "{"):
            depth += 1
        elif v in (")", "]", "}"):
            depth -= 1
        elif v == "," and depth == 0:
            ranges.append((start, i))
            start = i + 1
    ranges.append((start, close))
    return ranges


def rule_datastore_key_from_client(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    tokens = ctx.tokens
    writes = ("GetAsync", "SetAsync", "UpdateAsync", "RemoveAsync", "IncrementAsync")
    for h in find_handlers(tokens):
        if h.event not in ("OnServerEvent", "OnServerInvoke"):
            continue
        client_params = set(h.params[1:])  # first param is the real player
        if not client_params:
            continue
        body = _body_tokens(tokens, h)
        for k in range(len(body) - 1):
            if body[k].value in writes:
                if k + 1 < len(body) and body[k + 1].value == "(":
                    # Only the KEY argument matters. A client-controlled value in the
                    # payload (`SetAsync(plr.UserId, clientTable)`) is not key injection:
                    # that is the L001/L018 class, and treating it as a critical key bug
                    # was 10 of 16 sampled L003 findings on the 2026-11-20 batch.
                    ranges = _top_level_args(body, k + 1)
                    if not ranges:
                        continue
                    key_lo, key_hi = ranges[0]
                    keynames = {body[a].value for a in range(key_lo, key_hi) if body[a].kind == "name"}
                    if keynames & client_params:
                        out.append(
                            Finding(
                                rule_id="ONYX-L003",
                                severity="critical",
                                title="DataStore key is built from client input",
                                consequence=(
                                    "The save key comes from an argument the client controls. "
                                    "A player can read or overwrite another player's save data."
                                ),
                                path=ctx.inst.path,
                                line=body[k].line,
                                snippet=ctx.snippet(body[k].line),
                                fix="Always derive the key from player.UserId, never from a passed value.",
                            )
                        )
                        break
    return out


def _literal_call_arg(tokens: list[Token], open_idx: int) -> bool:
    """True when the first argument of the call is built only from string literals.

    Accepts `"a"` and `"a" .. "b"`; anything with a name, number or call in it is not
    literal and the caller fires.
    """
    close, args = call_span(tokens, open_idx)
    if not args:
        return False
    first_end = close
    depth = 0
    for i in range(open_idx + 1, close):
        v = tokens[i].value
        if v in ("(", "[", "{"):
            depth += 1
        elif v in (")", "]", "}"):
            depth -= 1
        elif v == "," and depth == 0:
            first_end = i
            break
    for i in range(open_idx + 1, first_end):
        t = tokens[i]
        if t.kind == "string" or t.value == "..":
            continue
        return False
    return True


#: `getfenv`/`setfenv` reach around normal scope but execute nothing. Pre-2016 places use
#: them as ordinary idiom (549 hits on one archive place). They are context for a reader,
#: not a vulnerability claim, so they live under their own rule id and never enter a
#: precision denominator: ONYX-L004 is only the runtime-code-execution claim.
ENV_REFLECTION = {
    "getfenv": ("reads the current function environment",
                "`getfenv` reaches around normal scope. On its own it executes nothing; "
                "it matters only when combined with `loadstring` or a client-controlled "
                "function."),
    "setfenv": ("replaces a function's environment",
                "`setfenv` changes what a function can see. On its own it executes "
                "nothing; it matters only when combined with `loadstring` or a "
                "client-controlled function."),
}


def rule_loadstring(ctx: ScriptContext, place: Place) -> list[Finding]:
    """`loadstring` executes code built at runtime: critical on its own."""
    out: list[Finding] = []
    for k, t in enumerate(ctx.tokens):
        if t.kind != "name" or t.value != "loadstring":
            continue
        if k + 1 >= len(ctx.tokens) or ctx.tokens[k + 1].value != "(":
            continue
        if _literal_call_arg(ctx.tokens, k + 1):
            # `loadstring("a hardcoded string")` compiles fixed source, not
            # attacker-chosen code: the 2026-11-20 batch's one L004 false positive was
            # exactly this.
            continue
        close, _args = call_span(ctx.tokens, k + 1)
        if not _callsite_tainted(ctx.tokens, k, close):
            # The critical claim is gated on client
            # input reaching the loaded chunk. A fixed external source or a server-owned
            # constant is a review note (ONYX-L021), not a claim -- same standard that
            # demoted the obfuscated-loader promotion.
            out.append(_obfuscated_loader_note(ctx, t.line, "fixed"))
            continue
        out.append(
            Finding(
                rule_id="ONYX-L004",
                severity="critical",
                title="Client input reaches `loadstring`",
                consequence=(
                    "`loadstring` compiles and runs a string at runtime, and that string "
                    "is shaped by a client argument in this handler. A player chooses what "
                    "runs with server authority."
                ),
                path=ctx.inst.path,
                line=t.line,
                snippet=ctx.snippet(t.line),
                fix="Remove it; pass the data in as a parameter and validate it.",
            )
        )
    # A function name resolved at runtime and called is code loading even without
    # `loadstring`. The 2026-11-21 era slice found 576 of the 921 getfenv/setfenv notes
    # were one loader body: `getfenv()[string.reverse("\101\114\105\117\113\101\114")](id)`.
    # That IS execution, but a constant escaped `require` of a pinned asset is the author's
    # own obfuscation, not a reachable trust break. The critical claim is gated on client
    # input reaching the loaded chunk or the resolved
    # name; otherwise it is a review note under ONYX-L021, not a claim.
    for k, t in enumerate(ctx.tokens):
        if t.kind != "name":
            continue
        if t.value in ENV_REFLECTION and (_dynamic_env_call(ctx.tokens, k)
                                         or _env_alias_call(ctx.tokens, k)):
            span = _env_call_span(ctx.tokens, k) or (k, k)
            tainted = _callsite_tainted(ctx.tokens, span[0], span[1])
            if tainted:
                out.append(
                    Finding(
                        rule_id="ONYX-L004",
                        severity="critical",
                        title="Client input reaches a runtime function lookup",
                        consequence=(
                            "The script resolves a function name from the environment and "
                            "calls the result, and the name (or the chunk it loads) is "
                            "shaped by a client argument. A player chooses what runs with "
                            "server authority."
                        ),
                        path=ctx.inst.path, line=t.line, snippet=ctx.snippet(t.line),
                        fix="Resolve the function/asset server-side from a fixed table; "
                            "never build a callee name from client input.",
                        confidence="medium",
                    )
                )
            else:
                out.append(_obfuscated_loader_note(ctx, t.line))
        elif t.value == "require" and _obfuscated_require(ctx.tokens, k):
            close, _args = call_span(ctx.tokens, k + 1)
            tainted = _callsite_tainted(ctx.tokens, k, close)
            if tainted:
                out.append(
                    Finding(
                        rule_id="ONYX-L004",
                        severity="critical",
                        title="Client input reaches an obfuscated `require`",
                        consequence=(
                            "The module id is built from a client argument and escape "
                            "sequences; a player chooses which module runs with server "
                            "authority."
                        ),
                        path=ctx.inst.path, line=t.line, snippet=ctx.snippet(t.line),
                        fix="Pass the numeric asset id literally and never derive it from "
                            "client input.",
                        confidence="medium",
                    )
                )
            else:
                out.append(_obfuscated_loader_note(ctx, t.line, "hidden"))
    return out


def _obfuscated_loader_note(ctx: ScriptContext, line: int, shape: str = "hidden") -> Finding:
    """Runtime loading the client cannot reach: a review note, never a vulnerability claim.

    `shape` distinguishes the two cases so the note stays specific:
    - "hidden": a name hidden with escape sequences / `string.reverse` / `string.char`
      and a pinned asset id -- the author's own obfuscation.
    - "fixed": `loadstring` of a non-literal whose text is not client-derived (a fixed
      external URL, a constant table, another server script's output).
    """
    if shape == "fixed":
        consequence = (
            "`loadstring` compiles a runtime string that is not derived from client input "
            "in this script: a fixed external source or server-owned constant. Reviewing "
            "what that runtime code is and where it comes from is warranted; it is not a "
            "reachable client trust break, so this is a note, not a claim."
        )
        fix = "Prefer a checked-in module over runtime code loading; pin and review the source."
    else:
        consequence = (
            "Code is loaded through an obfuscated name (escape sequences, "
            "`string.reverse`/`string.char`) and a pinned asset id, and no client input "
            "reaches the expression in this script. That is the author's own obfuscation, "
            "not a reachable trust break this scanner can demonstrate; the review question "
            "is what the pinned asset contains and whether it is kept in review."
        )
        fix = ("Pin the asset id, keep that asset in code review, and drop the obfuscation "
               "if there is no reason for it.")
    return Finding(
        rule_id="ONYX-L021",
        severity="info",
        title="Runtime code loading outside client reach (review note)",
        consequence=consequence,
        path=ctx.inst.path,
        line=line,
        snippet=ctx.snippet(line),
        fix=fix,
        confidence="low",
    )


def _env_call_span(tokens: list[Token], k: int) -> tuple[int, int] | None:
    """Token span of a getfenv/setfenv call-through, direct or through a local alias."""
    n = len(tokens)
    if _dynamic_env_call(tokens, k):
        close, _args = call_span(tokens, k + 1)
        if close + 1 < n and tokens[close + 1].value == "[":
            depth = 0
            for m in range(close + 1, n):
                if tokens[m].value == "[":
                    depth += 1
                elif tokens[m].value == "]":
                    depth -= 1
                    if depth == 0:
                        if m + 1 < n and tokens[m + 1].value == "(":
                            end, _ = call_span(tokens, m + 1)
                            return k, end
                        return k, m
        return k, min(n - 1, close)
    if _env_alias_call(tokens, k):
        if k < 2:
            return None
        alias = tokens[k - 2].value
        for j in range(k + 1, n):
            if tokens[j].kind == "name" and tokens[j].value == alias and j + 1 < n \
                    and tokens[j + 1].value == "[":
                depth = 0
                for m in range(j + 1, n):
                    if tokens[m].value == "[":
                        depth += 1
                    elif tokens[m].value == "]":
                        depth -= 1
                        if depth == 0:
                            if m + 1 < n and tokens[m + 1].value == "(":
                                end, _ = call_span(tokens, m + 1)
                                return k, end
                            return k, m
    return None


def _callsite_tainted(tokens: list[Token], lo: int, hi: int) -> bool:
    """True when a client-supplied value appears inside tokens[lo:hi] of its handler body."""
    handlers = find_handlers(tokens)
    for h in handlers:
        if not (h.body_lo <= lo <= h.body_hi):
            continue
        body = _body_tokens(tokens, h)
        client = list(h.params[1:])
        if not client:
            return False
        client_set = _taint_names(body, client)
        base = h.body_lo
        for j in range(max(lo, base), min(hi + 1, len(tokens))):
            if tokens[j].value in client_set:
                return True
        return False
    return False


def _dynamic_env_call(tokens: list[Token], k: int) -> bool:
    """`getfenv(...)[<expr>](...)`: a function looked up by a runtime string and called."""
    if k + 1 >= len(tokens) or tokens[k + 1].value != "(":
        return False
    close, _args = call_span(tokens, k + 1)
    return close + 1 < len(tokens) and tokens[close + 1].value == "[" 


def _env_alias_call(tokens: list[Token], k: int) -> bool:
    """`local e = getfenv(); e[<expr>](...)` -- the same dynamic invoke, via an alias.

    The smalln census found this alias form in 2 places / ~550 instances, and L020's
    context claim was wrong for it: it calls a function named at runtime.
    """
    if k < 2 or tokens[k - 1].value != "=" or tokens[k - 2].kind != "name":
        return False
    alias = tokens[k - 2].value
    n = len(tokens)
    for j in range(k + 1, n):
        if tokens[j].kind == "name" and tokens[j].value == alias:
            if j + 1 < n and tokens[j + 1].value == "[":
                depth = 0
                for m in range(j + 1, n):
                    if tokens[m].value == "[":
                        depth += 1
                    elif tokens[m].value == "]":
                        depth -= 1
                        if depth == 0:
                            return m + 1 < n and tokens[m + 1].value == "("
            return False  # the alias is used for something else
    return False


def _obfuscated_require(tokens: list[Token], k: int) -> bool:
    """`require(` whose argument is hidden: string escapes, `string.reverse`, `string.char`."""
    if k + 1 >= len(tokens) or tokens[k + 1].value != "(":
        return False
    close, _args = call_span(tokens, k + 1)
    window = [t.value for t in tokens[k + 2:close]]
    text = "".join(window)
    if "string.reverse" in text or "string.char" in text:
        return True
    import re as _re
    return any(_re.search(r"\\\d{1,3}", t.value)
               for t in tokens[k + 2:close] if t.kind == "string")


def rule_env_reflection(ctx: ScriptContext, place: Place) -> list[Finding]:
    """`getfenv`/`setfenv` are context notes (ONYX-L020), never a vulnerability claim."""
    out: list[Finding] = []
    seen: set[str] = set()
    for k, t in enumerate(ctx.tokens):
        if t.kind != "name" or t.value not in ENV_REFLECTION:
            continue
        if k + 1 >= len(ctx.tokens) or ctx.tokens[k + 1].value != "(":
            continue
        key = f"{t.value}:{t.line}"
        if key in seen:
            continue
        if t.value in ("getfenv", "setfenv") and (_dynamic_env_call(ctx.tokens, k)
                                                 or _env_alias_call(ctx.tokens, k)):
            continue  # the call-through shape is ONYX-L004: it executes, it is not context
        seen.add(key)
        verb, consequence = ENV_REFLECTION[t.value]
        out.append(
            Finding(
                rule_id="ONYX-L020",
                severity="info",
                title=f"`{t.value}` {verb} (context, not a vulnerability)",
                consequence=consequence,
                path=ctx.inst.path,
                line=t.line,
                snippet=ctx.snippet(t.line),
                fix="Nothing to fix unless it is combined with runtime code generation; "
                    "then remove that first.",
            )
        )
    return out


def rule_require_numeric(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    toks = ctx.tokens
    for k, t in enumerate(toks):
        if t.kind == "name" and t.value == "require" and k + 2 < len(toks) and toks[k + 1].value == "(":
            arg = toks[k + 2]
            if arg.kind == "number":
                out.append(
                    Finding(
                        rule_id="ONYX-L005",
                        severity="high",
                        title="require() by numeric asset id",
                        consequence=(
                            f"`require({arg.value})` loads an external module by asset id. "
                            "Whoever controls that asset controls code running in your game."
                        ),
                        path=ctx.inst.path,
                        line=t.line,
                        snippet=ctx.snippet(t.line),
                        fix="Require by instance path and keep the module inside the place.",
                        confidence="medium",
                    )
                )
    return out


def rule_client_server_service(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    if ctx.role not in ("client",):
        return out
    toks = ctx.tokens
    for k, t in enumerate(toks):
        if t.kind == "string" and t.text in SERVER_ONLY_SERVICES:
            # Only a service *lookup* is the claim: `game:GetService("ServerStorage")`.
            # A plain string that happens to equal the service name (the batch's one
            # false positive was `WaitForChild("ServerStorage")`) is not an access.
            if not (k >= 2 and toks[k - 1].value == "("
                    and toks[k - 2].value in ("GetService", "FindService")):
                continue
            out.append(
                Finding(
                    rule_id="ONYX-L006",
                    severity="info",
                    title=f"Client script requests server-only service `{t.text}` (context note)",
                    consequence=(
                        f"A LocalScript is asking for `{t.text}`. This is a client-local fact: "
                        "the lookup returns nil and nothing server-side is reached, so it is not "
                        "a trust break the client can exploit. It is still the wrong side of the "
                        "boundary to build on."
                    ),
                    path=ctx.inst.path,
                    line=t.line,
                    snippet=ctx.snippet(t.line),
                    fix="Move the call into a server Script and expose only the result via a RemoteEvent.",
                )
            )
    for k, t in enumerate(toks):
        if t.kind == "name" and t.value in ("ServerStorage", "ServerScriptService"):
            if k >= 2 and toks[k - 1].value == "." and toks[k - 2].value == "game":
                out.append(
                    Finding(
                        rule_id="ONYX-L006",
                        severity="info",
                        title=f"Client script indexes `game.{t.value}` (context note)",
                        consequence=(
                            f"`game.{t.value}` is not replicated to clients: the lookup returns "
                            "nil and the surrounding logic silently breaks. That is a client-local "
                            "fact, not a reachable trust break."
                        ),
                        path=ctx.inst.path,
                        line=t.line,
                        snippet=ctx.snippet(t.line),
                        fix="Move the logic to the server.",
                        confidence="medium",
                    )
                )
    return out


def rule_remote_created_on_client(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    if ctx.role != "client":
        return out
    toks = ctx.tokens
    for k, t in enumerate(toks):
        if t.kind == "name" and t.value == "Instance" and k + 5 < len(toks):
            window = [x.value for x in toks[k : k + 6]]
            joined = " ".join(window)
            is_new = window[1:3] == [".", "new"]
            if is_new and ("RemoteEvent" in joined or "RemoteFunction" in joined):
                out.append(
                    Finding(
                        rule_id="ONYX-L007",
                        severity="info",
                        title="Remote object created on the client (context note)",
                        consequence=(
                            "A client-created remote exists only for that client. The emulator "
                            "reproduces this fact, but nothing client-triggerable reaches server "
                            "state through it, so it is a context note, not a claim."
                        ),
                        path=ctx.inst.path,
                        line=t.line,
                        snippet=ctx.snippet(t.line),
                        fix="Create remotes once on the server and reference them by name.",
                    )
                )
    return out


def rule_process_receipt(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    toks = ctx.tokens
    text = " ".join(t.value for t in toks)
    if "ProcessReceipt" not in text:
        return out
    receipt_line = next((t.line for t in toks if t.value == "ProcessReceipt"), 1)
    has_grant = "PurchaseGranted" in text
    # `ProcessReceipt = handlerName` hands the callback to a function defined elsewhere.
    # The scanner cannot see that body, so it cannot claim the decision is missing —
    # the handler itself is scanned on its own, where the evidence actually is.
    wiring_only = False
    for k, tk in enumerate(toks):
        if tk.value != "ProcessReceipt":
            continue
        j = k + 1
        if j < len(toks) and toks[j].value == "=":
            j += 1
            if j < len(toks) and toks[j].kind == "name" and toks[j].value != "function":
                wiring_only = True
        # Only claim "never returns a decision" when the whole handler is visible. A window
    # that ends mid-function says nothing about the return that follows it.
    if not has_grant and not wiring_only and not _truncated_function(toks):
        out.append(
            Finding(
                rule_id="ONYX-L008",
                severity="critical",
                title="ProcessReceipt never returns PurchaseGranted",
                consequence=(
                    "Roblox retries uncredited receipts indefinitely. Without an explicit "
                    "`Enum.ProductPurchaseDecision.PurchaseGranted`, buyers can be charged "
                    "without receiving the item — chargebacks and account risk follow."
                ),
                path=ctx.inst.path,
                line=receipt_line,
                snippet=ctx.snippet(receipt_line),
                fix="Return PurchaseGranted only after the grant is persisted; NotProcessedYet otherwise.",
            )
        )
    for lo, hi in _receipt_handler_bodies(toks):
        line = _ack_before_save(toks, lo, hi)
        if line is None:
            continue
        out.append(
            Finding(
                rule_id="ONYX-L009",
                severity="critical",
                title="Purchase granted before the save is persisted",
                consequence=(
                    "PurchaseGranted is returned before the DataStore write. If the write fails, "
                    "the purchase is recorded as delivered but the player's item is lost."
                ),
                path=ctx.inst.path,
                line=line,
                snippet=ctx.snippet(line),
                fix="Persist first, then return PurchaseGranted; otherwise return NotProcessedYet.",
            )
        )
    return out


def _receipt_handler_bodies(tokens: list[Token]) -> list[tuple[int, int]]:
    """Token span of the body of every `ProcessReceipt` handler defined in this script.

    L009 used to compare the position of the first `PurchaseGranted` against the first
    `SetAsync` in the whole file. That fires whenever an acknowledgement and a save exist
    anywhere in the script, in either order of definition -- including an idempotency early
    return and a save that belongs to a different function. The claim is about ordering
    *inside one handler*, so the rule now reads one handler body at a time.
    """
    bodies: list[tuple[int, int]] = []
    n = len(tokens)
    for k, t in enumerate(tokens):
        if t.kind != "name" or t.value != "ProcessReceipt":
            continue
        fn_idx = -1
        if k + 2 < n and tokens[k + 1].value == "=" and tokens[k + 2].value == "function":
            fn_idx = k + 2                      # MPS.ProcessReceipt = function(...)
        elif k >= 2 and tokens[k - 2].value == "function":
            fn_idx = k - 2                      # function MPS.ProcessReceipt(...)
        elif k >= 1 and tokens[k - 1].value == "function":
            fn_idx = k - 1                      # function ProcessReceipt(...)
        if fn_idx < 0:
            continue                            # `= handlerName` wiring: body is elsewhere
        j = fn_idx + 1
        while j < n and tokens[j].value != "(":
            j += 1
        if j >= n:
            continue
        close, _args = call_span(tokens, j)
        end = block_end(tokens, fn_idx)
        if close >= n - 1 or end >= n - 1:
            continue                            # a window cannot prove what the rest does
        bodies.append((close + 1, end - 1))
    return bodies


def _ack_before_save(tokens: list[Token], lo: int, hi: int) -> int | None:
    """Line of a returned PurchaseGranted that precedes every save in the same body.

    Two conditions keep this honest, both measured against real places:
    - a save must exist in the same body (a save in another function does not persist the
      acknowledgement, so the old claim was not decidable there);
    - the *last* acknowledgement must come before the *first* save, so the idempotency
      early return (`if history then return PurchaseGranted end` ... save ... return
      PurchaseGranted) never fires: its final acknowledgement is already after the save.
    """
    grants = [i for i in range(lo, hi + 1) if tokens[i].value == "PurchaseGranted"]
    writes = [
        i
        for i in range(lo, hi + 1)
        if tokens[i].value in ("SetAsync", "UpdateAsync", "IncrementAsync")
    ]
    if not grants or not writes:
        return None
    last_grant = max(grants)
    if last_grant >= min(writes):
        return None
    if not any(tokens[i].value == "return" for i in range(max(lo, last_grant - 6), last_grant)):
        return None
    return tokens[last_grant].line


def rule_receipt_not_idempotent(ctx: ScriptContext, place: Place) -> list[Finding]:
    """A developer-product receipt is granted with no record of *which* receipt it was.

    Roblox redelivers receipts that were not acknowledged, and can retry across servers,
    so the documented contract is to key the grant on `receiptInfo.PurchaseId`. A handler
    that grants without ever naming PurchaseId pays twice for one purchase. This is the
    dupe that shows up as negative revenue rather than as an exploit.
    """
    toks = ctx.tokens
    names = {t.value for t in toks if t.kind in ("name", "keyword")}
    if "ProcessReceipt" not in names:
        return []
    if "PurchaseGranted" not in names:
        return []  # L008 owns the "never acknowledges" case
    if "PurchaseId" in names:
        return []
    line = next((t.line for t in toks if t.value == "ProcessReceipt"), 1)
    return [
        Finding(
            rule_id="ONYX-L017",
            severity="high",
            title="Developer-product receipt is granted without keying on the receipt id",
            consequence=(
                "Roblox redelivers an unacknowledged receipt and can retry across servers. "
                "Nothing here records `receiptInfo.PurchaseId`, so a redelivery runs the "
                "grant again: the player is paid twice for one purchase."
            ),
            path=ctx.inst.path,
            line=line,
            snippet=ctx.snippet(line),
            fix="Record granted PurchaseIds (UpdateAsync on a receipt key) and return "
                "PurchaseGranted only once that record reads true.",
            confidence="medium",
        )
    ]


def _function_spans(tokens: list[Token]) -> list[tuple[int, int]]:
    """(open, close) token indices of every complete `function ... end` block."""
    spans: list[tuple[int, int]] = []
    for k, t in enumerate(tokens):
        if t.value == "function":
            close = block_end(tokens, k)
            if close < len(tokens) - 1:  # the eof sentinel means "truncated window"
                spans.append((k, close))
    return spans


def _unit_span(spans: list[tuple[int, int]], idx: int, n: int) -> tuple[int, int]:
    """Innermost function span containing idx, else the whole script body."""
    best = (0, n - 1)
    for lo, hi in spans:
        if lo < idx < hi and (hi - lo) < (best[1] - best[0]):
            best = (lo, hi)
    return best


def _pcall_index_before(tokens: list[Token], idx: int) -> int | None:
    """Index of the `pcall` token whose argument list contains the call at idx, if any."""
    for j in range(idx - 1, max(-1, idx - 40), -1):
        v = tokens[j].value
        if v in (";", "then", "do", "end"):
            return None
        if v == "pcall":
            return j
    return None


def _pcall_success_flag(tokens: list[Token], pcall_idx: int) -> int | None:
    """Token index of the success flag assigned from `pcall(...)`, if any."""
    for k in range(pcall_idx - 1, max(-1, pcall_idx - 8), -1):
        if tokens[k].value == "=":
            if tokens[k - 1].kind == "name":
                # `local ok, value = pcall(...)` -> ok is the token before the comma
                if k - 3 >= 0 and tokens[k - 2].value == "," and tokens[k - 3].kind == "name":
                    return k - 3
                return k - 1  # `local ok = pcall(...)`
            return None
        if tokens[k].value in (";", "end", "do"):
            return None
    return None


def _branches_on_flag(tokens: list[Token], lo: int, hi: int, flag_idx: int) -> bool:
    """True when the unit tests the pcall success flag (either polarity) in an `if`."""
    flag = tokens[flag_idx].value
    for i in range(lo, hi):
        if tokens[i].value != "if":
            continue
        for j in range(i + 1, min(hi, i + 6)):
            if tokens[j].value == flag:
                return True
            if tokens[j].value in ("then", "do"):
                break
    return False


def _blank_literal_payload(tokens: list[Token], write_idx: int) -> bool:
    """True when the value argument of this SetAsync is a blank/default literal."""
    if write_idx + 1 >= len(tokens) or tokens[write_idx + 1].value != "(":
        return False
    ranges = _top_level_args(tokens, write_idx + 1)
    if len(ranges) < 2:
        return False
    lo, hi = ranges[1]
    if lo >= hi:
        return False
    if hi - lo == 2 and tokens[lo].value == "{" and tokens[lo + 1].value == "}":
        return True  # empty table
    if hi - lo != 1:
        return False
    t = tokens[lo]
    if t.kind == "number":
        return float(t.value) == 0
    if t.kind == "string":
        return t.value == ""
    return t.value in ("false", "nil")


def _is_literal(t: Token) -> bool:
    return t.kind in ("number", "string") or t.value in ("true", "false", "nil", "{")


def _defaulted_names(tokens: list[Token]) -> set[str]:
    """Names whose value is defaulted with `or <literal>` after a DataStore read.

    Returns the variable names, not just a flag: the 2026-11-21 data-link fix needs to know
    *which* defaulted value reaches a write. A default that is only returned, logged or
    discarded does not cause a wipe and must not fire ONYX-L018.
    """
    n = len(tokens)
    read_names: set[str] = set()
    for i, t in enumerate(tokens):
        if t.value != "=":
            continue
        has_read = False
        for k in range(i + 1, min(n, i + 60)):
            v = tokens[k].value
            if v in (";", "then", "do", "end"):
                break
            if v in ("GetAsync", "pcall"):
                has_read = True
        if not has_read:
            continue
        if i - 1 >= 0 and tokens[i - 1].kind == "name":
            read_names.add(tokens[i - 1].value)
        if i - 3 >= 0 and tokens[i - 2].value == "," and tokens[i - 3].kind == "name":
            read_names.add(tokens[i - 3].value)
    names: set[str] = set()
    for k, t in enumerate(tokens):
        if t.value != "or" or k == 0 or k + 1 >= n:
            continue
        prev = tokens[k - 1]
        nxt = tokens[k + 1]
        if not _is_literal(nxt):
            continue
        if prev.kind == "name" and prev.value in read_names:
            names.add(prev.value)
        if prev.value == ")":
            # `GetAsync(...) or 100` / `pcall(...) or {}`: the assigned names carry the
            # default, so every read name is a defaulted name.
            names |= read_names
    return names


def _defaulted_read(tokens: list[Token]) -> bool:
    return bool(_defaulted_names(tokens))


def _key_tokens(tokens: list[Token], call_idx: int) -> set[str]:
    """The literal/name tokens of a call's first argument (the DataStore key text)."""
    if call_idx + 1 >= len(tokens) or tokens[call_idx + 1].value != "(":
        return set()
    ranges = _top_level_args(tokens, call_idx + 1)
    if not ranges:
        return set()
    lo, hi = ranges[0]
    return {t.value for t in tokens[lo:hi] if t.kind in ("name", "string", "number")}


def rule_datastore_wipe_on_failed_load(ctx: ScriptContext, place: Place) -> list[Finding]:
    """A failed load is indistinguishable from an empty one, and the defaults get saved.

    Narrowed 2026-11-21 from a script-level co-occurrence test, after the 2026-11-20 batch
    measured 33.3% precision. A finding now requires the actual wipe shape, not merely a read
    and a write in the same script:
    - the load result is defaulted (`data or {}`), or the default is written back literally
      (`SetAsync(key, 0)`) inside the same function as the read; and
    - the defaulting is not protected by a distinct failure branch (`if not ok then ...`),
      which is the correct pcall shape.
    """
    toks = ctx.tokens
    names = {t.value for t in toks if t.kind in ("name", "keyword")}
    if "GetAsync" not in names or "SetAsync" not in names:
        return []
    flat = "".join(t.value for t in toks).lower()
    loaded_flag_tokens = ("loadedplayers", "playerloaded", "dataloaded", "isloaded",
                          "loaded[", "loaded=true", "isloaded[")
    if any(marker in flat for marker in loaded_flag_tokens):
        return []

    def guarded(idx: int) -> bool:
        """True when this call sits inside a `pcall(...)` expression on the same statement."""
        return _pcall_index_before(toks, idx) is not None

    reads = [i for i, t in enumerate(toks) if t.kind == "name" and t.value == "GetAsync"]
    writes = [i for i, t in enumerate(toks) if t.kind == "name" and t.value == "SetAsync"]
    if not reads or not writes:
        return []
    if all(guarded(i) for i in reads) and all(guarded(i) for i in writes):
        return []  # the wrapper shape: (ok, value) is returned and the caller decides

    spans = _function_spans(toks)
    failure_path = False
    for r in reads:
        pidx = _pcall_index_before(toks, r)
        if pidx is None:
            continue
        flag = _pcall_success_flag(toks, pidx)
        if flag is not None:
            unit = _unit_span(spans, pidx, len(toks))
            if _branches_on_flag(toks, unit[0], unit[1], flag):
                failure_path = True

    wipe = False
    if not failure_path:
        # Data-link (2026-11-21): a defaulted read only wipes if that default actually
        # reaches a write. A default that is returned, logged or discarded is harmless --
        # the ProfileService-shaped false positives were exactly that.
        defaulted = _defaulted_names(toks)
        if defaulted:
            for w in writes:
                if w + 1 >= len(toks) or toks[w + 1].value != "(":
                    continue
                lo, hi = _top_level_args(toks, w + 1)[-1] if _top_level_args(toks, w + 1) else (0, 0)
                arg_tokens = {t.value for t in toks[lo:hi]}
                if defaulted & arg_tokens:
                    wipe = True
                    break
    if not wipe:
        for r in reads:
            unit = _unit_span(spans, r, len(toks))
            rkey = _key_tokens(toks, r)
            if not rkey:
                continue
            for w in writes:
                if w <= r or _unit_span(spans, w, len(toks)) != unit:
                    continue
                if not _blank_literal_payload(toks, w):
                    continue
                if rkey & _key_tokens(toks, w):
                    # the blank is saved back to the same record the read tried to load
                    wipe = True
                    break
            if wipe:
                break
    if not wipe:
        return []

    line = toks[reads[0]].line
    return [
        Finding(
            rule_id="ONYX-L018",
            severity="high",
            title="A failed DataStore load can be written back as blank data",
            consequence=(
                "`GetAsync` returns nil for a failed request exactly as it does for a new "
                "player, and the nil is replaced with a default that the game then saves. "
                "Nothing records that the load succeeded, so a failed read overwrites the "
                "player's real progress. Players report this as a wipe."
            ),
            path=ctx.inst.path,
            line=line,
            snippet=ctx.snippet(line),
            fix="Set a per-player loaded flag only when the pcall returned true, and skip "
                "saving any player whose data never loaded.",
            confidence="medium",
        )
    ]


def rule_gamepass_prompt(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    if ctx.role != "server":
        # Client scripts prompt by design, and a ModuleScript can be either side at
        # runtime. Only a server-side prompt is a shape this static pass can judge.
        # (Measured 2026-11-19 on a real place: the module/client cases were false
        # positives, and developer products are consumables — they are meant to be
        # re-purchased, so an "ownership check" is the wrong expectation there.)
        return out
    toks = ctx.tokens
    for k, t in enumerate(toks):
        if t.kind == "name" and t.value == "PromptGamePassPurchase":
            text = " ".join(x.value for x in toks)
            if "UserOwnsGamePassAsync" not in text and "PlayerOwnsAsset" not in text:
                out.append(
                    Finding(
                        rule_id="ONYX-L010",
                        severity="info",
                        title="Game-pass prompt with no ownership check (context note)",
                        consequence=(
                            "The server prompts a game pass without an ownership check in this "
                            "script. On a real product that can prompt an owner again; in the "
                            "measured shapes it is a no-op or a prompt the platform already "
                            "guards, so it is a context note, not a claim."
                        ),
                        path=ctx.inst.path,
                        line=t.line,
                        snippet=ctx.snippet(t.line),
                        fix="Check MarketplaceService:UserOwnsGamePassAsync before prompting.",
                        confidence="medium",
                    )
                )
            break
    return out


def rule_kick_from_client(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    toks = ctx.tokens
    for h in find_handlers(toks):
        if h.event not in ("OnServerEvent", "OnServerInvoke"):
            continue
        client_params = set(h.params[1:])
        body = _body_tokens(toks, h)
        for k, t in enumerate(body):
            if t.kind == "name" and t.value == "Kick" and k + 1 < len(body) and body[k + 1].value == "(":
                close, args = call_span(body, k + 1)
                argnames = {body[a].value for a in args if body[a].kind == "name"}
                if argnames & client_params:
                    out.append(
                        Finding(
                            rule_id="ONYX-L011",
                            severity="info",
                            title="Kick reason taken from client input (context note)",
                            consequence=(
                                "The kick message is client-controlled text. The measured shapes "
                                "are display-only or admin-gated, so this is a context note: "
                                "spoofed log text is worth knowing about, not a claim."
                            ),
                            path=ctx.inst.path,
                            line=t.line,
                            snippet=ctx.snippet(t.line),
                            fix="Build the reason server-side from a fixed set of strings.",
                        )
                    )
    return out


def _http_aliases(tokens: list[Token]) -> set[str]:
    """Names bound to HttpService, e.g. local http = game:GetService("HttpService")."""
    aliases = {"HttpService"}
    n = len(tokens)
    for k, t in enumerate(tokens):
        if t.kind != "name" or t.value != "HttpService":
            continue
        # walk backwards for  local X = game:GetService("HttpService")
        j = k - 1
        while j > max(0, k - 14):
            if tokens[j].value == "=":
                if j - 1 >= 0 and tokens[j - 1].kind == "name":
                    aliases.add(tokens[j - 1].value)
                break
            if tokens[j].value in (";", "end", "then"):
                break
            j -= 1
    return aliases


def rule_http_with_client_data(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    toks = ctx.tokens
    http_aliases = _http_aliases(toks)
    for h in find_handlers(toks):
        if h.event not in ("OnServerEvent", "OnServerInvoke"):
            continue
        client_params = set(h.params[1:])
        body = _body_tokens(toks, h)
        for k, t in enumerate(body):
            if t.kind == "name" and t.value in ("GetAsync", "PostAsync", "RequestAsync"):
                recv = _expr_before(body, k).split(":")[-1].split(".")[-1].strip()
                if recv not in http_aliases:
                    continue
                if k + 1 < len(body) and body[k + 1].value == "(":
                    close, args = call_span(body, k + 1)
                    argnames = {body[a].value for a in args if body[a].kind == "name"}
                    if argnames & client_params:
                        out.append(
                            Finding(
                                rule_id="ONYX-L012",
                                severity="high",
                                title="HttpService call built from client input",
                                consequence=(
                                    "The request URL or body comes from the client. That turns your "
                                    "server into an open proxy — attackers can send arbitrary "
                                    "requests from your game's IP and quota."
                                ),
                                path=ctx.inst.path,
                                line=t.line,
                                snippet=ctx.snippet(t.line),
                                fix="Never pass client values into HttpService. Use fixed endpoints.",
                            )
                        )
    return out


#: Attribute names that are input flags by convention (Mouse1Held, Move, AutoMove, ...):
#: the client writing a boolean "I pressed this" flag is the intended design, and the
#: 2026-11-21 modern slice measured all 24 hits of that shape as false positives.
_INPUT_FLAG_ATTR = re.compile(
    r"(?i)(mouse|held|input|move|automove|walk|jump|key|button|click|aim|"
    r"orientation|throttle|steer|cursor|speed|dash|sprint|fire|shoot)")


def _boolean_write(args_text: str) -> bool:
    """True when the written value is a boolean literal/expression, not a chosen value."""
    text = args_text.strip().lower()
    if text in ("true", "false"):
        return True
    if text.startswith("not "):
        return True
    return any(op in text for op in ("==", "~=", ">=", "<=", ">", "<"))


def rule_setattribute_from_client(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    toks = ctx.tokens
    for h in find_handlers(toks):
        if h.event not in ("OnServerEvent", "OnServerInvoke"):
            continue
        client_params = set(h.params[1:])
        body = _body_tokens(toks, h)
        for k, t in enumerate(body):
            if t.kind == "name" and t.value in ("SetAttribute",) and k + 1 < len(body):
                if body[k + 1].value == "(":
                    close, args = call_span(body, k + 1)
                    argnames = {body[a].value for a in args if body[a].kind == "name"}
                    if not (argnames & client_params):
                        continue
                    # Narrow by shape. A boolean/input-flag
                    # write is the intended "I pressed this" design, not a chosen value.
                    ranges = _top_level_args(body, k + 1)
                    attr_text = "".join(body[a].value for a in range(ranges[0][0], ranges[0][1]))
                    if _INPUT_FLAG_ATTR.search(attr_text):
                        continue
                    if len(ranges) > 1:
                        val_text = "".join(body[a].value
                                           for a in range(ranges[1][0], ranges[1][1]))
                        if _boolean_write(val_text):
                            continue
                    if True:
                        out.append(
                            Finding(
                                rule_id="ONYX-L013",
                                severity="info",
                                title="Attribute written from client input (context note)",
                                consequence=(
                                    "A client-supplied non-boolean value is written onto an "
                                    "instance attribute. In both measured cohorts every hit of "
                                    "this shape was an intended input flag, so this is a context "
                                    "note, not a claim."
                                ),
                                path=ctx.inst.path,
                                line=t.line,
                                snippet=ctx.snippet(t.line),
                                fix="Validate or derive the value server-side before setting it.",
                                confidence="medium",
                            )
                        )
    return out


def rule_wrong_direction(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    if ctx.role == "module":
        # A module executes on whichever side requires it, so neither direction is
        # wrong in a module. Public-code measurement produced a false alarm on
        # exactly this shape (a networking library calling FireClient).
        return out
    toks = ctx.tokens
    want = {"FireServer", "InvokeServer"} if ctx.role == "server" else {"FireClient", "FireAllClients"}
    for k, t in enumerate(toks):
        if t.kind == "name" and t.value in want:
            out.append(
                Finding(
                    rule_id="ONYX-L014",
                    severity="info",
                    title=f"Remote called in the wrong direction (`{t.value}` in a {ctx.role} script) — context note",
                    consequence=(
                        f"A {ctx.role} script is calling `{t.value}`, which only exists on the other "
                        "side. This either errors silently or does nothing — the feature it belongs "
                        "to is not running."
                    ),
                    path=ctx.inst.path,
                    line=t.line,
                    snippet=ctx.snippet(t.line),
                    fix="Move the call to the correct script type.",
                    confidence="medium",
                )
            )
            break
    return out


#: The debug library is mostly diagnostics. Only these can rewrite state or reach
#: outside the sandbox; `traceback`, `info`, `setmemorycategory` and the profiler
#: are ordinary production tools and flagging them was a measured false alarm.
SENSITIVE_DEBUG = frozenset({
    "setupvalue", "getupvalue", "setmetatable", "getmetatable", "setfenv", "getfenv",
    "setidentity", "setthreadidentity", "getregistry", "loadmodule", "dumpheap",
    "setstackdepth", "resetmemorycategory",
})


def rule_debug_library(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    toks = ctx.tokens
    for k, t in enumerate(toks):
        if t.kind == "name" and t.value == "debug" and k + 1 < len(toks) and toks[k + 1].value == ".":
            if k + 2 < len(toks) and toks[k + 2].value in SENSITIVE_DEBUG:
                out.append(
                    Finding(
                        rule_id="ONYX-L015",
                        severity="medium",
                        title=f"`debug.{toks[k + 2].value}` used at runtime",
                        consequence=(
                            "The debug library can inspect and mutate internal state. Left in "
                            "production it is a privilege-escalation surface if any argument to it "
                            "is ever client-influenced."
                        ),
                        path=ctx.inst.path,
                        line=t.line,
                        snippet=ctx.snippet(t.line),
                        fix="Remove debug calls before publishing.",
                        confidence="medium",
                    )
                )
            break
    return out


#: Comparison operators that count as a bound on a client-supplied number.
_COMPARE_OPS = frozenset({"<", ">", "<=", ">=", "==", "~="})


_LOG_CALLS = frozenset({"print", "warn", "error", "write", "log", "logservice",
                        "appendlog", "notify", "logtofile", "setlogging"})
_ARITH_OPS = frozenset({"+", "-", "*", "/", "%", "^", "..", "<", ">", "<=", ">=",
                        "==", "~=", "and", "or"})
_RANK_GATES = ("GetRankInGroup", "GetRoleInGroup", "IsInGroup", "GetRank", ":GetRole")


def _param_used_as_number(body: list[Token], param: str) -> bool:
    """True when the value is used as a number, not only as an object or a log entry.

    2026-11-21, per surviving L016 false positive: `value.Value = true` (the client sends
    an object, the handler writes a flag), UI replication writes and log-only uses were all
    counted as "an unclamped amount" but are not numbers at all. A finding now needs at
    least one occurrence of the parameter in an arithmetic/comparison/to-number context.
    """
    n = len(body)
    for k, t in enumerate(body):
        if t.kind != "name" or t.value != param:
            continue
        prev = body[k - 1].value if k >= 1 else ""
        nxt = body[k + 1].value if k + 1 < n else ""
        if nxt in (".", ":", "[", "(") or prev in (".", ":", "["):
            continue  # object use: p.Value, p:Method(), p[i], p(args)
        if prev in _ARITH_OPS or nxt in _ARITH_OPS:
            return True
        # tostring(p) / tonumber(p) / math.floor(p) as a nested argument
        if prev == "(" and k >= 2 and body[k - 2].value in ("tonumber", "tostring",
                                                            "floor", "abs", "round"):
            return True
        if prev == "," and k >= 3 and body[k - 3].value in _LOG_CALLS:
            continue
        return True  # a call argument or a value: treat as used numerically
    return False


def _param_only_logged(body: list[Token], param: str) -> bool:
    """True when every occurrence of the parameter is an argument to a logging call."""
    n = len(body)
    seen = False
    for k, t in enumerate(body):
        if t.kind != "name" or t.value != param:
            continue
        seen = True
        prev = body[k - 1].value if k >= 1 else ""
        if prev in (".", ":", "[", "(", ",", "="):
            # find the nearest enclosing call name before this occurrence
            j = k - 1
            while j >= 0 and body[j].value not in ("(", ",", "=", ";", "do", "then"):
                j -= 1
            if j >= 0 and body[j].value in ("(", ","):
                m = j - 1
                while m >= 0 and body[m].value not in ("(", ",", "=", ";", "do", "then",
                                                       "if", "return"):
                    m -= 1
                if m >= 1 and body[m].value == "(" and body[m - 1].value.lower() in _LOG_CALLS:
                    continue
        return False
    return seen


def _rank_gated(body: list[Token]) -> bool:
    """True when the handler gates on group rank: an admin/cheat menu, not a defect."""
    flat = "".join(t.value for t in body)
    return any(gate in flat for gate in _RANK_GATES)


def _amount_is_guarded(body: list[Token], param: str) -> bool:
    """True when the body visibly bounds this client number: comparison, typeof, min/max.

    Narrowed 2026-11-21 (batch 66.7% with 7 uncertain): a comparison guard (`qty <= 0`,
    `balance >= price`), a `typeof(x) == "number"` check or a min/max clamp all mean the
    value is checked. The rule's claim is "used without a clamp", so any of those answers
    it. Bare `if qty then` is not a bound (0 is truthy in Lua) and still fires.
    """
    n = len(body)
    for k, t in enumerate(body):
        if t.kind != "name" or t.value != param:
            continue
        lo, hi = max(0, k - 2), min(n, k + 3)
        for j in range(lo, hi):
            if body[j].value in _COMPARE_OPS:
                return True
        # typeof(x) == "number" / type(x) == 'number'
        if k >= 1 and body[k - 1].value == "(" and k >= 2 and body[k - 2].value in ("typeof", "type"):
            return True
    return False


def _economy_sink_written_with(body: list[Token], param: str) -> str:
    """The economy sink this client number is written into, or "" (order 50).

    L016 never had a sink gate. "Used without a clamp" is only a vulnerability when the
    number feeds economy/data state a player would exploit; a client setting its own
    tool's `Transparency` is cosmetic no matter how unclamped it is, and twelve of those
    were the rule's new claims on 2026-11-21. Cosmetic/visual targets are refused
    unconditionally here (not merely deprioritised).
    """
    n = len(body)
    for k in range(1, n):
        if body[k].value not in ("=", "+=", "-="):
            continue
        target_idx = k - 1
        dotted = ((target_idx >= 2 and body[target_idx].kind == "name"
                   and body[target_idx - 1].value in (".", "]"))
                  or (target_idx >= 1 and body[target_idx].value == "]"))
        if not dotted:
            continue
        if target_idx >= 1 and body[target_idx - 1].value == "local":
            continue
        hi = k + 1
        while hi < n and body[hi].value not in (";", "end"):
            if body[hi].line != body[k].line:
                break
            hi += 1
        if not _value_use(body, param, k + 1, hi):
            continue
        text = _write_target_text(body, k)
        if _cosmetic_target(text):
            continue
        if _currency_target(text):
            return "a currency value"
    for k in range(n - 1):
        if body[k].kind != "name" or body[k + 1].value != "(":
            continue
        name = body[k].value
        if name not in ATTR_WRITERS and name not in STORE_WRITERS:
            continue
        groups = _top_level_args(body, k + 1)
        if not groups or not any(_value_use(body, param, lo, hi) for lo, hi in groups[1:]):
            continue
        if name in STORE_WRITERS:
            return "a DataStore record"
        key = "".join(t.value for t in body[groups[0][0]:groups[0][1]]).strip('"\'')
        if any(c in key.lower() for c in CURRENCY_NAMES):
            return f"an instance attribute ({key})"
    return ""


def rule_unclamped_amount(ctx: ScriptContext, place: Place) -> list[Finding]:
    out: list[Finding] = []
    toks = ctx.tokens
    for h in find_handlers(toks):
        if h.event not in ("OnServerEvent", "OnServerInvoke"):
            continue
        client_params = set(h.params[1:])
        body = _body_tokens(toks, h)
        text = {t.value for t in body}
        if not (text & {"math.clamp", "math.min", "math.max", "clamp"}):
            for p in client_params:
                if p.lower() not in {"amount", "qty", "count", "value", "num", "n", "price", "cost"}:
                    continue
                if _amount_is_guarded(body, p):
                    continue
                if not _param_used_as_number(body, p) or _param_only_logged(body, p):
                    continue  # an object/UI write or a log entry, not a number
                if not _economy_sink_written_with(body, p):
                    # 2026-11-21 (order 50): no economy/data sink → cosmetic or
                    # non-economy write. L016 had no sink gate before this, so its 69.2%
                    # was measured on the pre-M1 hit set only.
                    continue
                if _rank_gated(body) or _guard_strength(toks, h) != "none":
                    continue  # an admin/cheat menu or an allowlisted/whitelisted handler
                out.append(
                    Finding(
                        rule_id="ONYX-L016",
                        # Row 56 (2026-11-21): one claim in 506 places cannot carry a claim
                        # class — a claim class needs a measurable rate and this rule's
                        # population is 1/1. Demoted to info like L002; the detector and the
                        # finding are kept (never deleted), only the severity label changes.
                        severity="info",
                        title=f"Client-supplied `{p}` is used without a clamp",
                        consequence=(
                            f"`{p}` arrives from the client and is never bounded; a client "
                            "can send a negative or absurd value (e.g. -1e9). Whether that "
                            "inverts an economy depends on what the write feeds, which this "
                            "finding names in the snippet."
                        ),
                        path=ctx.inst.path,
                        line=h.line,
                        snippet=ctx.snippet(h.line),
                        fix="math.clamp(amount, 1, MAX) before use, and reject non-numbers.",
                    )
                )
                break
    return out


# --------------------------------------------------------------------------
# place-level rules
# --------------------------------------------------------------------------


def place_rule_orphan_remotes(place: Place, all_text: str) -> list[Finding]:
    orphans = [r for r in place.client_remotes if not (r.name and r.name in all_text)]
    if not orphans:
        return []
    if len(orphans) > 5:
        # One row per orphan turned a real 242-script place into 44 low findings, nearly
        # all of them names built at runtime by a networking module. Aggregate instead of
        # pretending each name is an independent finding.
        sample = ", ".join(f"`{r.name}`" for r in orphans[:5])
        return [
            Finding(
                rule_id="ONYX-P001",
                severity="low",
                title=f"{len(orphans)} client-reachable remotes are never referenced in this pass",
                consequence=(
                    f"{len(orphans)} remotes are replicated to every client and no script text "
                    "references them by name in this static pass (first: " + sample + "). "
                    "That usually means the names are built at runtime by a networking module, "
                    "or the instances were renamed by an export. Confirm in Studio before "
                    "deleting anything; this is one aggregated row, not a claim about each name."
                ),
                # Point at the service, not one arbitrary remote: the aggregate is about
                # the set, and a single instance path would imply that instance is special.
                path=".".join(orphans[0].path.split(".")[:-1]) or orphans[0].path,
                line=1,
                snippet=f"<{orphans[0].class_name} name=\"{orphans[0].name}\">",
                fix="Open the place in Studio and check the remote registry; delete only what nothing uses.",
                confidence="low",
            )
        ]
    out: list[Finding] = []
    for remote in orphans:
        out.append(
            Finding(
                rule_id="ONYX-P001",
                severity="low",
                title=f"Remote `{remote.name}` is client-reachable but never referenced",
                consequence=(
                    "This remote is replicated to every client and no script in the place references "
                    "it. It is either dead weight or a handler loaded at runtime that this static "
                    "pass cannot see — worth confirming."
                ),
                path=remote.path,
                line=1,
                snippet=f"<{remote.class_name} name=\"{remote.name}\">",
                fix="Remove it, or document where it is handled.",
                confidence="medium",
            )
        )
    return out


def place_rule_bindable_in_repstorage(place: Place) -> list[Finding]:
    out: list[Finding] = []
    for remote in place.instances:
        if remote.class_name in ("BindableEvent", "BindableFunction") and remote.is_client_reachable():
            out.append(
                Finding(
                    rule_id="ONYX-P002",
                    severity="info",
                    title=f"`{remote.class_name}` in a replicated container",
                    consequence=(
                        "Bindables never cross the client/server boundary, so this one only works "
                        "inside the context that created it. That is a legitimate pattern for "
                        "client-side module communication — this is a note about where the "
                        "instance lives, not a security defect."
                    ),
                    path=remote.path,
                    line=1,
                    snippet=f"<{remote.class_name} name=\"{remote.name}\">",
                    fix="If a client/server round trip was intended, use a RemoteEvent; otherwise "
                        "move the bindable into the context that uses it.",
                    confidence="low",
                )
            )
    return out


# --------------------------------------------------------------------------
# orchestrator
# --------------------------------------------------------------------------

SCRIPT_RULES = (
    rule_unvalidated_remote_handlers,
    rule_datastore_key_from_client,
    rule_loadstring,
    rule_env_reflection,
    rule_require_numeric,
    rule_client_server_service,
    rule_remote_created_on_client,
    rule_process_receipt,
    rule_receipt_not_idempotent,
    rule_datastore_wipe_on_failed_load,
    rule_gamepass_prompt,
    rule_kick_from_client,
    rule_http_with_client_data,
    rule_setattribute_from_client,
    rule_wrong_direction,
    rule_debug_library,
    rule_unclamped_amount,
)


def _role(inst: Instance) -> str:
    if inst.class_name == "LocalScript":
        return "client"
    if inst.class_name == "Script":
        return "server"
    return "module"


def scan_place(place: Place) -> ScanResult:
    findings: list[Finding] = []
    texts: list[str] = []

    for inst in place.scripts:
        src = inst.source or ""
        texts.append(src)
        lines = src.splitlines() or [""]
        ctx = ScriptContext(inst=inst, tokens=tokenize(src), lines=lines, role=_role(inst))
        for rule in SCRIPT_RULES:
            findings.extend(rule(ctx, place))

    all_text = "\n".join(texts)
    findings.extend(place_rule_orphan_remotes(place, all_text))
    findings.extend(place_rule_bindable_in_repstorage(place))

    # dedupe by (rule, path, line, title)
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    unique.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line))

    handled_remotes = sum(
        1
        for r in place.client_remotes
        if r.name and r.name in all_text
    )
    total_remotes = len(place.client_remotes)
    unvalidated = sum(1 for f in unique if f.rule_id in ("ONYX-L001", "ONYX-L002", "ONYX-L016"))

    coverage = {
        "client_reachable_remotes": total_remotes,
        "remotes_referenced": handled_remotes,
        "handlers_without_validation": unvalidated,
        "scripts_scanned": len(place.scripts),
        "lines_scanned": sum(len((s.source or "").splitlines()) for s in place.scripts),
    }

    return ScanResult(place_summary=place.summary(), findings=unique, coverage=coverage)
