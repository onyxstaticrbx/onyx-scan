"""Resolve ``require`` edges and module functions across scripts.

The token engine cannot see a handler that calls a function in another file. This module
builds a small module graph from the AST, resolves the simple path forms studios actually
use, and counts everything it cannot resolve. Unresolved is not safe: it is a coverage
fact, and the scan report must say so.

Scope is deliberately conservative:

* resolved: ``script.Parent.X``, ``script.Parent:WaitForChild("X")``,
  ``script:FindFirstChild("X")``, ``game.ReplicatedStorage...``,
  ``game:GetService("Service").X``, and simple local aliases;
* unresolved: numeric/asset/string requires, dynamic expressions, aliases it cannot
  follow, and any path that does not name a ModuleScript.

The graph is one hop for findings: a handler calls a resolved module function, and the
function summary reaches a sink with a client argument. It does not pretend to follow
arbitrary call chains.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .luau_ast import (
    Assign,
    BinOp,
    Block,
    CallExpr,
    Chunk,
    FunctionDecl,
    FunctionExpr,
    IfExpr,
    IfStmt,
    IndexExpr,
    Literal,
    LocalAssign,
    LocalFunction,
    NameExpr,
    Node,
    Paren,
    ReturnStmt,
    BreakStmt,
    ContinueStmt,
    TableExpr,
    TypeAssert,
    UnOp,
    Vararg,
    walk,
    parse,
    ParseError,
)
from .place import Instance, Place

#: Sinks the existing L001 claim can name, matching rules.py.
_CLAIM_SINKS = ("currency", "attribute", "datastore")

#: Mutating call names the summary treats as side effects. Kept small on purpose.
_WRITE_CALLS = frozenset(
    {"SetAsync", "UpdateAsync", "IncrementAsync", "RemoveAsync", "SetAttribute", "SetValue"}
)


@dataclass
class Binding:
    """A name bound to an instance or a module path."""

    name: str
    instance: Instance | None = None
    module_path: str | None = None
    line: int = 0


@dataclass
class RequireRef:
    source: str
    target: str | None
    line: int
    raw: str
    resolved: bool
    reason: str = ""


@dataclass
class FunctionSummary:
    name: str
    module_path: str
    params: list[str]
    line: int
    sink: str = ""
    param_index: int = -1
    target: str = ""
    reason: str = ""
    guarded: bool = False


@dataclass
class CrossFileHit:
    line: int
    what: str
    kind: str
    sink: str
    module_path: str
    function: str
    guarded: bool = False

    def as_tuple(self) -> tuple[int, str, str, str]:
        return (self.line, self.what, self.kind, self.sink)


@dataclass
class ScriptAST:
    inst: Instance
    chunk: Chunk | None
    error: str = ""
    bindings: dict[str, Binding] = field(default_factory=dict)
    requires: list[RequireRef] = field(default_factory=list)


@dataclass
class RequireAnalysis:
    modules: dict[str, ScriptAST] = field(default_factory=dict)
    summaries: dict[str, dict[str, FunctionSummary]] = field(default_factory=dict)
    requires: list[RequireRef] = field(default_factory=list)
    parse_failures: list[str] = field(default_factory=list)
    unresolved: int = 0
    resolved: int = 0
    time_budget_exceeded: bool = False
    scripts_not_analyzed: int = 0
    #: Resolved/unresolved counts per syntactic require shape. The counts exist so a
    #: partial read is explainable: "these forms resolve, those do not" instead of a
    #: single unresolved number with no pattern behind it.
    by_pattern: dict[str, dict[str, int]] = field(default_factory=dict)

    def record(self, pattern: str, resolved: bool) -> None:
        row = self.by_pattern.setdefault(pattern, {"resolved": 0, "unresolved": 0})
        row["resolved" if resolved else "unresolved"] += 1

    def module_for(self, path: str) -> ScriptAST | None:
        return self.modules.get(path)

    def summary_for(self, module_path: str, function: str) -> FunctionSummary | None:
        return self.summaries.get(module_path, {}).get(function)

    def coverage(self) -> dict:
        return {
            "modules_parsed": sum(1 for m in self.modules.values() if m.chunk is not None),
            "module_parse_failures": len(self.parse_failures),
            "require_edges": len(self.requires),
            "require_resolved": self.resolved,
            "require_unresolved": self.unresolved,
            "module_analysis_time_budget_exceeded": self.time_budget_exceeded,
            "module_analysis_scripts_not_analyzed": self.scripts_not_analyzed,
            "require_by_pattern": {k: dict(v) for k, v in sorted(self.by_pattern.items())},
        }


# ---------------------------------------------------------------------------
# expression resolution
# ---------------------------------------------------------------------------


def _child(inst: Instance, name: str) -> Instance | None:
    for child in inst.children:
        if child.name == name:
            return child
    return None


def _source_text(chunk: Chunk, node: Node) -> str:
    try:
        return chunk.source[node.start:node.end].strip()
    except (AttributeError, IndexError):
        return ""


def _resolve_expr(node: Node | None, inst: Instance, place: Place,
                  bindings: dict[str, Binding], chunk: Chunk,
                  depth: int = 0) -> tuple[Instance | None, str]:
    """Resolve an expression to an Instance, or return (None, reason)."""
    if node is None or depth > 30:
        return None, "expression too deep"
    if isinstance(node, Paren):
        return _resolve_expr(node.expr, inst, place, bindings, chunk, depth + 1)
    if isinstance(node, TypeAssert):
        return _resolve_expr(node.expr, inst, place, bindings, chunk, depth + 1)
    if isinstance(node, NameExpr):
        name = node.name
        if name == "script":
            return inst, ""
        if name == "game":
            return place.root, ""
        b = bindings.get(name)
        if b is None:
            return None, f"unknown name {name!r}"
        if b.instance is not None:
            return b.instance, ""
        if b.module_path is not None:
            return place.by_path(b.module_path), ""
        return None, f"binding {name!r} is not an instance"
    if isinstance(node, IndexExpr):
        base, reason = _resolve_expr(node.obj, inst, place, bindings, chunk, depth + 1)
        if base is None:
            return None, reason
        if node.dot:
            if not isinstance(node.index, str):
                return None, "non-literal dot index"
            if node.index == "Parent":
                if base.parent is None:
                    return None, f"{base.path} has no parent"
                return base.parent, ""
            child = _child(base, node.index)
            if child is None:
                return None, f"{base.path} has no child {node.index!r}"
            return child, ""
        if isinstance(node.index, Literal) and node.index.kind == "string":
            child = _child(base, node.index.value)
            if child is None:
                return None, f"{base.path} has no child {node.index.value!r}"
            return child, ""
        return None, "dynamic index"
    if isinstance(node, CallExpr):
        return _resolve_call(node, inst, place, bindings, chunk, depth + 1)
    if isinstance(node, Literal):
        if node.kind == "string":
            return None, f"string require {node.value!r} is an external asset"
        return None, "literal is not an instance"
    return None, f"unsupported expression {type(node).__name__}"


def _resolve_call(node: CallExpr, inst: Instance, place: Place,
                  bindings: dict[str, Binding], chunk: Chunk,
                  depth: int) -> tuple[Instance | None, str]:
    if node.method and node.method_name:
        base, reason = _resolve_expr(node.func, inst, place, bindings, chunk, depth + 1)
        if base is None:
            return None, reason
        method = node.method_name
        if method in ("GetService", "FindService"):
            if not node.args:
                return None, f"{method} without a service name"
            arg = node.args[0]
            if not isinstance(arg, Literal) or arg.kind != "string":
                return None, f"{method} with a dynamic service name"
            child = _child(base, arg.value)
            if child is None:
                return None, f"no service named {arg.value!r}"
            return child, ""
        if method in ("WaitForChild", "FindFirstChild"):
            if not node.args:
                return None, f"{method} without a name"
            arg = node.args[0]
            if not isinstance(arg, Literal) or arg.kind != "string":
                return None, f"{method} with a dynamic child name"
            child = _child(base, arg.value)
            if child is None:
                return None, f"{base.path} has no child {arg.value!r}"
            return child, ""
        return None, f"unsupported method {method!r}"
    func = node.func
    if not isinstance(func, IndexExpr) or not isinstance(func.index, str):
        return None, "dynamic call target"
    base, reason = _resolve_expr(func.obj, inst, place, bindings, chunk, depth + 1)
    if base is None:
        return None, reason
    method = func.index
    if method in ("GetService", "FindService"):
        if not node.args:
            return None, f"{method} without a service name"
        arg = node.args[0]
        if not isinstance(arg, Literal) or arg.kind != "string":
            return None, f"{method} with a dynamic service name"
        child = _child(base, arg.value)
        if child is None:
            return None, f"no service named {arg.value!r}"
        return child, ""
    if method in ("WaitForChild", "FindFirstChild"):
        if not node.args:
            return None, f"{method} without a name"
        arg = node.args[0]
        if not isinstance(arg, Literal) or arg.kind != "string":
            return None, f"{method} with a dynamic child name"
        child = _child(base, arg.value)
        if child is None:
            return None, f"{base.path} has no child {arg.value!r}"
        return child, ""
    return None, f"unsupported method {method!r}"


def _require_call(call: CallExpr) -> bool:
    return isinstance(call.func, NameExpr) and call.func.name == "require"


def _is_require_expr(node: Node) -> bool:
    return isinstance(node, CallExpr) and _require_call(node)


# ---------------------------------------------------------------------------
# summaries
# ---------------------------------------------------------------------------


def _dotted_target(node: Node | None) -> str:
    """`a.b.c` text for a target expression, or empty when dynamic."""
    if isinstance(node, NameExpr):
        return node.name
    if isinstance(node, IndexExpr):
        if node.dot and isinstance(node.index, str):
            base = _dotted_target(node.obj)
            return f"{base}.{node.index}" if base else ""
        if isinstance(node.index, Literal) and node.index.kind == "string":
            base = _dotted_target(node.obj)
            return f"{base}.{node.index.value}" if base else node.index.value
    return ""


def _currency_name(text: str) -> bool:
    low = text.lower()
    if ".value" not in low:
        return False
    names = ("leaderstats", "cash", "coins", "money", "tokens", "gems", "credits",
             "points", "balance", "currency", "robux", "gold", "diamonds", "bux", "xp")
    return any(n in low for n in names)


def _param_in(node: Node | None, params: set[str]) -> str | None:
    if node is None or not params:
        return None
    # Walk the expression, not only its immediate children: `amount` inside
    # `math.floor(amount)` or `amount * 2` is still the value written.
    for item in walk(node):
        if isinstance(item, NameExpr) and item.name in params:
            return item.name
    return None


def _summarise_function(name: str, fn: FunctionExpr, module_path: str) -> FunctionSummary:
    params = list(fn.params)
    # Any parameter can be the client-chosen value. Cross-file callers are matched
    # against the handler's arguments, so a one-parameter `Give(amount)` is visible
    # just as a `Give(player, amount)` is.
    client = set(params)
    line = fn.line
    guarded = False
    # Walk the body directly; the function may be nested, but the summary is one level.
    for node in walk(fn.body):
        if isinstance(node, IfStmt):
            # A check on a parameter that returns/breaks before the sink is a guard.
            for condition, body in node.branches:
                if _param_in(condition, client) and any(
                        isinstance(x, (ReturnStmt, BreakStmt, ContinueStmt))
                        for x in walk(body)):
                    guarded = True
                    break
        if isinstance(node, Assign):
            for target in node.targets:
                text = _dotted_target(target)
                if _currency_name(text):
                    p = _param_in(node.values[0] if node.values else None, client)
                    if p:
                        return FunctionSummary(name, module_path, params, line, "currency",
                                               params.index(p), text, guarded=guarded)
                if text and text.split(".")[0] in client and node.values:
                    # client-chosen key/object; never a value claim
                    pass
        elif isinstance(node, CallExpr):
            fname = node.method_name if node.method else ""
            if not fname:
                if isinstance(node.func, NameExpr):
                    fname = node.func.name
                elif isinstance(node.func, IndexExpr) and isinstance(node.func.index, str):
                    fname = node.func.index
            if fname in _WRITE_CALLS:
                # Different APIs put the value in different positions. `SetAttribute(name, value)`
                # has value at 1; `SetAsync(key, value)` has value at 1; `IncrementAsync(key, amount)`
                # has amount at 1. Keep the argument explicit rather than guessing the first one.
                if fname in ("SetAttribute", "SetValue", "SetAsync", "IncrementAsync"):
                    arg = node.args[1] if len(node.args) > 1 else None
                else:
                    arg = node.args[0] if node.args else None
                p = _param_in(arg, client)
                if p:
                    sink = "attribute" if fname in ("SetAttribute", "SetValue") else "datastore"
                    return FunctionSummary(name, module_path, params, line, sink,
                                           params.index(p), _dotted_target(node.func),
                                           guarded=guarded)
    return FunctionSummary(name, module_path, params, line, guarded=guarded)


def _function_fields(module_path: str, chunk: Chunk, inst: Instance) -> dict[str, FunctionSummary]:
    out: dict[str, FunctionSummary] = {}

    def register(name: str, fn: FunctionExpr) -> None:
        if not name:
            return
        short = name.split(".")[-1]
        out.setdefault(short, _summarise_function(short, fn, module_path))
        out.setdefault(name, out[short])

    for node in walk(chunk.body):
        if isinstance(node, FunctionDecl) and isinstance(node.func, FunctionExpr):
            register(node.name, node.func)
        elif isinstance(node, LocalFunction) and isinstance(node.func, FunctionExpr):
            register(node.name, node.func)
        elif isinstance(node, Assign):
            for target, value in zip(node.targets, node.values):
                if isinstance(value, FunctionExpr):
                    register(_dotted_target(target), value)
        elif isinstance(node, TableExpr):
            for field in node.fields:
                if isinstance(field.value, FunctionExpr):
                    key = field.key or (field.key_expr.value
                                        if isinstance(field.key_expr, Literal)
                                        and field.key_expr.kind == "string" else "")
                    if key:
                        register(str(key), field.value)
    return out


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------


def build_analysis(place: Place, *, deadline: float | None = None) -> RequireAnalysis:
    analysis = RequireAnalysis()
    paths = {inst.path: inst for inst in place.instances}
    for remaining, inst in enumerate(place.scripts):
        if deadline is not None and time.monotonic() > deadline:
            analysis.time_budget_exceeded = True
            analysis.scripts_not_analyzed = len(place.scripts) - remaining
            break
        if not (inst.source or "").strip():
            continue
        try:
            chunk = parse(inst.source or "", deadline=deadline)
            ast = ScriptAST(inst=inst, chunk=chunk)
        except ParseError as exc:
            ast = ScriptAST(inst=inst, chunk=None, error=str(exc))
            analysis.parse_failures.append(f"{inst.path}: {exc}")
            analysis.modules[inst.path] = ast
            continue
        analysis.modules[inst.path] = ast
        _collect_bindings(ast, place, paths, analysis)
        analysis.summaries[inst.path] = _function_fields(inst.path, chunk, inst)
    return analysis


def _require_chain(node: Node | None, depth: int = 0) -> tuple[str, list[str]]:
    """Root label and the operations applied to it, outermost last.

    The shape is what makes a require resolvable or not: `script.Parent.M` is a path
    lookup, `game:GetService("X").M` is a service lookup, a bare local alias is a name
    the scanner has to have bound earlier, `script.Parent:WaitForChild("M")` is a
    runtime lookup that only works if the child exists. The labels are the rows of the
    coverage table, so they name that shape rather than the resolved instance.
    """
    if depth > 24:
        return "other", []
    if isinstance(node, (Paren, TypeAssert)):
        return _require_chain(getattr(node, "expr", None), depth + 1)
    if isinstance(node, NameExpr):
        if node.name == "script":
            return "script", []
        if node.name == "game":
            return "game", []
        return "local alias", []
    if isinstance(node, IndexExpr):
        base, ops = _require_chain(node.obj, depth + 1)
        index = node.index
        if isinstance(index, str):
            op = ".Parent" if index == "Parent" else ".child"
        elif isinstance(index, Literal) and index.kind == "string":
            op = "[string]"
        else:
            op = "[dynamic]"
        return base, ops + [op]
    if isinstance(node, CallExpr):
        base, ops = _require_chain(node.func, depth + 1)
        name = node.method_name if node.method else (
            node.func.index if isinstance(node.func, IndexExpr) else "")
        if name in ("GetService", "FindService"):
            op = ":GetService"
        elif name in ("WaitForChild", "FindFirstChild"):
            op = ":WaitForChild"
        elif isinstance(name, str) and name:
            op = f":{name}"
        else:
            op = ":call"
        return base, ops + [op]
    return "other", []


def require_pattern(arg: Node | None) -> str:
    """Syntactic shape of one `require(...)` argument, used for the coverage table."""
    if arg is None:
        return "empty require()"
    if isinstance(arg, Literal):
        if arg.kind == "number":
            return "numeric asset id"
        if arg.kind == "string":
            return "string/asset id"
        return "other literal"
    if isinstance(arg, (Paren, TypeAssert)):
        return require_pattern(getattr(arg, "expr", None))
    base, ops = _require_chain(arg)
    if not ops:
        return "bare script" if base == "script" else (
            "bare game" if base == "game" else f"{base} (no path)")
    return base + "".join(ops)


def _collect_bindings(ast: ScriptAST, place: Place, paths: dict[str, Instance],
                      analysis: RequireAnalysis) -> None:
    assert ast.chunk is not None
    chunk = ast.chunk
    bindings = ast.bindings

    def bind(name: str, node: Node | None, line: int, *, is_require: bool = False) -> None:
        if not name:
            return
        resolved, reason = _resolve_expr(node, ast.inst, place, bindings, chunk)
        if resolved is not None:
            bindings[name] = Binding(name, resolved, resolved.path if resolved.is_script else None, line)
        elif is_require:
            # A require binding whose target is unresolved still exists; a later
            # `local f = M.func` will be treated as unresolved rather than guessed.
            ref = RequireRef(ast.inst.path, None, line, _source_text(chunk, node or ast.inst),
                             False, reason)
            ast.requires.append(ref)
            analysis.requires.append(ref)
            analysis.unresolved += 1

    for node in walk(chunk.body):
        if isinstance(node, LocalAssign):
            for name, value in zip(node.names, node.values):
                if _is_require_expr(value):
                    arg = value.args[0] if value.args else None
                    resolved, reason = _resolve_expr(arg, ast.inst, place, bindings, chunk)
                    raw = _source_text(chunk, value)
                    ref = RequireRef(ast.inst.path, resolved.path if resolved else None,
                                     value.line, raw, resolved is not None, reason)
                    ast.requires.append(ref)
                    analysis.requires.append(ref)
                    analysis.record(require_pattern(arg),
                                    resolved is not None
                                    and resolved.class_name == "ModuleScript")
                    if resolved is not None and resolved.class_name == "ModuleScript":
                        analysis.resolved += 1
                        bindings[name] = Binding(name, resolved, resolved.path, value.line)
                    else:
                        analysis.unresolved += 1
                    continue
                bind(name, value, value.line)
        elif isinstance(node, Assign) and len(node.targets) == 1 and len(node.values) == 1:
            target = node.targets[0]
            if isinstance(target, NameExpr):
                value = node.values[0]
                if _is_require_expr(value):
                    arg = value.args[0] if value.args else None
                    resolved, reason = _resolve_expr(arg, ast.inst, place, bindings, chunk)
                    raw = _source_text(chunk, value)
                    ref = RequireRef(ast.inst.path, resolved.path if resolved else None,
                                     value.line, raw, resolved is not None, reason)
                    ast.requires.append(ref)
                    analysis.requires.append(ref)
                    analysis.record(require_pattern(arg),
                                    resolved is not None
                                    and resolved.class_name == "ModuleScript")
                    if resolved is not None and resolved.class_name == "ModuleScript":
                        analysis.resolved += 1
                        bindings[target.name] = Binding(target.name, resolved, resolved.path, value.line)
                    else:
                        analysis.unresolved += 1
                else:
                    bind(target.name, value, value.line)

    # Direct require() calls not captured as a binding still count as edges. They are
    # often a one-line `require(script.Parent.X).f(...)`; add the edge, not a binding.
    for node in walk(chunk.body):
        if isinstance(node, CallExpr) and _require_call(node):
            # Captured by the binding paths above? Add only if not already seen at
            # the same line and raw text.
            raw = _source_text(chunk, node)
            if any(r.line == node.line and r.raw == raw for r in ast.requires):
                continue
            arg = node.args[0] if node.args else None
            resolved, reason = _resolve_expr(arg, ast.inst, place, bindings, chunk)
            ref = RequireRef(ast.inst.path, resolved.path if resolved else None,
                             node.line, raw, resolved is not None, reason)
            ast.requires.append(ref)
            analysis.requires.append(ref)
            analysis.record(require_pattern(arg),
                            resolved is not None
                            and resolved.class_name == "ModuleScript")
            if resolved is not None and resolved.class_name == "ModuleScript":
                analysis.resolved += 1
            else:
                analysis.unresolved += 1


def _line_in(node: Node, lo: int, hi: int) -> bool:
    return lo <= node.line <= hi


def cross_file_hits(place: Place, inst: Instance, handler: Any,
                    tokens: list[Any]) -> list[CrossFileHit]:
    """One-hop findings: handler calls a resolved module function that writes state.

    ``handler`` is rules.Handler; only its token range and parameter names are used so
    this module does not import the rules module (which imports this one lazily).
    """
    analysis = getattr(place, "analysis", None)
    if not isinstance(analysis, RequireAnalysis):
        return []
    ast = analysis.modules.get(inst.path)
    if ast is None or ast.chunk is None:
        return []
    chunk = ast.chunk
    lo = tokens[handler.body_lo].line if handler.body_lo < len(tokens) else handler.line
    hi = tokens[handler.body_hi].line if handler.body_hi < len(tokens) else handler.line
    client = list(handler.params[1:])
    if not client:
        return []
    hits: list[CrossFileHit] = []
    for node in walk(chunk.body):
        if not isinstance(node, CallExpr) or not _line_in(node, lo, hi):
            continue
        callee = node.func
        if not isinstance(callee, IndexExpr) or not isinstance(callee.index, str):
            continue
        base, reason = _resolve_expr(callee.obj, inst, place, ast.bindings, chunk)
        if base is None or base.class_name != "ModuleScript":
            continue
        summary = analysis.summary_for(base.path, callee.index)
        if summary is None or summary.sink not in _CLAIM_SINKS or summary.param_index < 0:
            continue
        # Method calls have an implicit self arg; dot calls do not.
        offset = 1 if node.method else 0
        idx = summary.param_index + offset
        if idx >= len(node.args):
            continue
        arg = node.args[idx]
        if not isinstance(arg, NameExpr) or arg.name not in client:
            continue
        hits.append(CrossFileHit(
            line=node.line,
            what=f"`{base.name}.{callee.index}()` → {summary.target}",
            kind="value",
            sink=summary.sink,
            module_path=base.path,
            function=callee.index,
            guarded=summary.guarded,
        ))
        break
    return hits


def attach(place: Place, *, deadline: float | None = None) -> RequireAnalysis:
    """Build and attach the analysis once; a second call is a no-op."""
    existing = getattr(place, "analysis", None)
    if isinstance(existing, RequireAnalysis):
        return existing
    analysis = build_analysis(place, deadline=deadline)
    place.analysis = analysis
    return analysis
