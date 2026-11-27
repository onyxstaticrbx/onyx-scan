"""A pure-Python Luau parser.

The token engine in ``lexer.py`` answers "which tokens are here"; this module answers
"what is the syntax". It is deliberately dependency-free: ``scan`` must keep working on
a machine that has Python and nothing else. The Luau compiler's own parser is used only
as a private test oracle, never at runtime.

The parser is not a reader of every historical Luau dialect. It supports the syntax that
appears in Roblox place scripts and returns a real AST with source positions. On syntax
it cannot parse it raises ``ParseError``; callers fall back to the token path and count
the fallback as coverage, never as a clean result.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------

KEYWORDS = frozenset(
    """
    and break do else elseif end false for function if in local nil not or
    repeat return then true until while continue type export declare
    """.split()
)

#: Untrusted source limits. The XML/Rojo readers cap source bytes before we get here; a
#: direct ``parse`` call or a malformed project can still hand the parser a hostile
#: string, so the parser refuses rather than recursing or allocating without end.
MAX_PARSE_BYTES = 8 * 1024 * 1024
MAX_TOKENS = 1_000_000
MAX_NODES = 250_000
MAX_PARSE_DEPTH = 160
MAX_PARSE_SECONDS = 15.0

#: Multi-character operators, longest first. Luau has no bitwise operators as syntax;
#: ``&`` and ``|`` are type operators, but they are still single tokens here.
OPERATORS = (
    "...", "..=", "//=", ">>=", "<<=", "==", "~=", "<=", ">=", "->", "::",
    "..", "//", "+=", "-=", "*=", "/=", "%=", "^=", "&&", "||",
)


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # name | keyword | number | string | op | eof
    value: str
    line: int
    col: int
    start: int
    end: int
    text: str = ""


_LONG_OPEN = re.compile(r"\[(=*)\[")
_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")


def _long_bracket(src: str, i: int) -> tuple[int, int] | None:
    """Return (content_start, content_end) for a long bracket, or None."""
    m = _LONG_OPEN.match(src, i)
    if not m:
        return None
    close = "]" + m.group(1) + "]"
    body_start = m.end()
    end = src.find(close, body_start)
    if end == -1:
        return body_start, len(src)
    return body_start, end


def tokenize(src: str) -> list[Token]:
    if len(src) > MAX_PARSE_BYTES:
        raise ParseError(f"source exceeds the {MAX_PARSE_BYTES / 1024 / 1024:.0f} MB parser limit")
    tokens: list[Token] = []
    i = 0
    n = len(src)
    line = 1
    line_start = 0

    def col(pos: int) -> int:
        return pos - line_start + 1

    def add(kind: str, value: str, start: int, end: int, text: str = "") -> None:
        if len(tokens) >= MAX_TOKENS:
            raise ParseError(f"source exceeds the {MAX_TOKENS:,}-token parser limit")
        tokens.append(Token(kind, value, line, col(start), start, end, text))

    while i < n:
        ch = src[i]
        if ch == "\n":
            i += 1
            line += 1
            line_start = i
            continue
        if ch in " \t\r\f\v":
            i += 1
            continue

        # Comments: -- line, --[=[ long ]=]
        if src.startswith("--", i):
            m = _LONG_OPEN.match(src, i + 2)
            if m:
                close = "]" + m.group(1) + "]"
                end = src.find(close, m.end())
                if end == -1:
                    end = n
                else:
                    end += len(close)
            else:
                end = src.find("\n", i)
                end = n if end == -1 else end
            for c in src[i:end]:
                if c == "\n":
                    line += 1
                    line_start = i + src[i:end].index("\n") + 1
            i = end
            continue

        # Long strings [[...]], [=[...]=]
        m = _LONG_OPEN.match(src, i)
        if m:
            level = m.group(1)
            close = "]" + level + "]"
            body_start = m.end()
            end = src.find(close, body_start)
            raw_end = n if end == -1 else end + len(close)
            text = src[body_start:end if end != -1 else n]
            add("string", src[i:raw_end], i, raw_end, text)
            for c in src[body_start:raw_end]:
                if c == "\n":
                    line += 1
                    line_start = body_start + src[body_start:raw_end].index("\n") + 1
            i = raw_end
            continue

        # Short strings
        if ch in "\"'":
            quote = ch
            start = i
            j = i + 1
            buf: list[str] = []
            while j < n:
                c = src[j]
                if c == "\\" and j + 1 < n:
                    nxt = src[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
                    j += 2
                    continue
                if c == quote:
                    j += 1
                    break
                if c == "\n":
                    # Unterminated; end at the newline so the parser reports it.
                    break
                buf.append(c)
                j += 1
            add("string", src[start:j], start, j, "".join(buf))
            i = j
            continue

        # Interpolated string. We keep the raw text here; the AST records it as a
        # literal. Cross-file resolution never resolves an interpolated require anyway.
        if ch == "`":
            start = i
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "`":
                    j += 1
                    break
                if src[j] == "\n":
                    line += 1
                    line_start = j + 1
                j += 1
            text = src[start + 1:j - 1] if j - 1 >= start else ""
            add("string", src[start:j], start, j, text)
            i = j
            continue

        # Numbers
        m = _NUMBER.match(src, i)
        if m:
            add("number", m.group(0), i, m.end())
            i = m.end()
            continue

        # Names / keywords
        if ch.isalpha() or ch == "_":
            start = i
            while i < n and (src[i].isalnum() or src[i] == "_"):
                i += 1
            word = src[start:i]
            kind = "keyword" if word in KEYWORDS else "name"
            add(kind, word, start, i)
            continue

        # Multi-character operators
        for op in OPERATORS:
            if src.startswith(op, i):
                add("op", op, i, i + len(op))
                i += len(op)
                break
        else:
            add("op", ch, i, i + 1)
            i += 1

    tokens.append(Token("eof", "", line, col(n), n, n))
    return tokens


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass
class Node:
    line: int = 0
    col: int = 0
    start: int = 0
    end: int = 0


@dataclass
class Block(Node):
    stmts: list[Node] = field(default_factory=list)


@dataclass
class Chunk(Node):
    body: Block | None = None
    source: str = ""


@dataclass
class LocalAssign(Node):
    names: list[str] = field(default_factory=list)
    types: list[str | None] = field(default_factory=list)
    values: list[Node] = field(default_factory=list)


@dataclass
class Assign(Node):
    targets: list[Node] = field(default_factory=list)
    values: list[Node] = field(default_factory=list)
    op: str = "="


@dataclass
class FunctionExpr(Node):
    params: list[str] = field(default_factory=list)
    vararg: bool = False
    body: Block | None = None
    name: str = ""
    param_types: list[str | None] = field(default_factory=list)
    return_type: str | None = None


@dataclass
class LocalFunction(Node):
    name: str = ""
    func: FunctionExpr | None = None


@dataclass
class FunctionDecl(Node):
    name: str = ""
    func: FunctionExpr | None = None


@dataclass
class CallStmt(Node):
    call: Node | None = None


@dataclass
class IfStmt(Node):
    branches: list[tuple[Node, Block]] = field(default_factory=list)
    else_body: Block | None = None


@dataclass
class WhileStmt(Node):
    cond: Node | None = None
    body: Block | None = None


@dataclass
class RepeatStmt(Node):
    body: Block | None = None
    cond: Node | None = None


@dataclass
class ForNumericStmt(Node):
    name: str = ""
    start: Node | None = None
    stop: Node | None = None
    step: Node | None = None
    body: Block | None = None


@dataclass
class ForGenericStmt(Node):
    names: list[str] = field(default_factory=list)
    iter: Node | None = None
    iters: list[Node] = field(default_factory=list)
    body: Block | None = None


@dataclass
class DoStmt(Node):
    body: Block | None = None


@dataclass
class ReturnStmt(Node):
    values: list[Node] = field(default_factory=list)


@dataclass
class BreakStmt(Node):
    pass


@dataclass
class ContinueStmt(Node):
    pass


@dataclass
class TypeAlias(Node):
    name: str = ""
    type_text: str = ""
    exported: bool = False


@dataclass
class AttributeStmt(Node):
    name: str = ""


@dataclass
class Literal(Node):
    kind: str = "nil"
    value: str = ""
    raw: str = ""


@dataclass
class NameExpr(Node):
    name: str = ""


@dataclass
class Vararg(Node):
    pass


@dataclass
class TableField(Node):
    key: str | None = None
    key_expr: Node | None = None
    value: Node | None = None


@dataclass
class TableExpr(Node):
    fields: list[TableField] = field(default_factory=list)


@dataclass
class BinOp(Node):
    op: str = ""
    left: Node | None = None
    right: Node | None = None


@dataclass
class UnOp(Node):
    op: str = ""
    operand: Node | None = None


@dataclass
class IndexExpr(Node):
    obj: Node | None = None
    index: Node | str | None = None
    dot: bool = False


@dataclass
class CallExpr(Node):
    func: Node | None = None
    args: list[Node] = field(default_factory=list)
    method: bool = False
    method_name: str = ""


@dataclass
class Paren(Node):
    expr: Node | None = None


@dataclass
class IfExpr(Node):
    branches: list[tuple[Node, Node]] = field(default_factory=list)
    else_expr: Node | None = None


class ParseError(Exception):
    def __init__(self, message: str, line: int = 0, col: int = 0) -> None:
        super().__init__(f"{message} (line {line}, col {col})")
        self.message = message
        self.line = line
        self.col = col


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

#: Binary operators and their precedence (higher binds tighter). ``and``/``or`` are
#: keywords, everything else is an op token. Right-associative operators are marked.
_BINARY = {
    "or": (1, False),
    "and": (2, False),
    "<": (3, False), ">": (3, False), "<=": (3, False), ">=": (3, False),
    "==": (3, False), "~=": (3, False),
    "..": (4, True),
    "+": (5, False), "-": (5, False),
    "*": (6, False), "/": (6, False), "//": (6, False), "%": (6, False),
    "^": (8, True),
}

_COMPOUND = frozenset({"+=", "-=", "*=", "/=", "//=", "%=", "^=", "..="})
_UNARY = frozenset({"not", "-", "#", "~"})


class Parser:
    def __init__(self, source: str, *, deadline: float | None = None,
                 max_seconds: float | None = None) -> None:
        if len(source) > MAX_PARSE_BYTES:
            raise ParseError(f"source exceeds the {MAX_PARSE_BYTES / 1024 / 1024:.0f} MB parser limit")
        self.source = source
        self.tokens = tokenize(source)
        self.pos = 0
        self.nodes = 0
        self.expr_depth = 0
        now = time.monotonic()
        own = now + (MAX_PARSE_SECONDS if max_seconds is None else max_seconds)
        self.deadline = own if deadline is None else min(own, deadline)

    def _tick(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise ParseError(f"source exceeds the {MAX_NODES:,}-node parser limit",
                             self.tok.line, self.tok.col)
        # Checking every node is cheap compared with parsing, but time.monotonic is not
        # free; sample it often enough to stop a runaway parse promptly.
        if self.nodes % 256 == 0 and time.monotonic() > self.deadline:
            raise ParseError("parser time limit exceeded", self.tok.line, self.tok.col)

    # -- token helpers -------------------------------------------------

    @property
    def tok(self) -> Token:
        return self.tokens[self.pos]

    def peek(self, k: int = 0) -> Token:
        return self.tokens[min(self.pos + k, len(self.tokens) - 1)]

    def at(self, value: str) -> bool:
        return self.tok.value == value

    def at_kind(self, kind: str) -> bool:
        return self.tok.kind == kind

    def advance(self) -> Token:
        t = self.tok
        if t.kind != "eof":
            self.pos += 1
        return t

    def expect(self, value: str) -> Token:
        if self.tok.value == value:
            return self.advance()
        raise ParseError(f"expected {value!r}, found {self.tok.value!r}",
                         self.tok.line, self.tok.col)

    def expect_name(self) -> str:
        # `type` and `continue` are contextual in Luau; legacy places use them as
        # variable names (`local continue = false`, `type(x)`). In a name position they
        # are names, not statements.
        if self.tok.kind == "name" or self.tok.value in {"type", "continue"}:
            return self.advance().value
        raise ParseError(f"expected a name, found {self.tok.value!r}", self.tok.line, self.tok.col)

    def _span(self, node: Node, start: Token, end: Token | None = None) -> Node:
        node.start = start.start
        node.line = start.line
        node.col = start.col
        node.end = (end.end if end is not None else self.tokens[self.pos - 1].end)
        return node

    # -- entry ---------------------------------------------------------

    def parse(self) -> Chunk:
        body = self.parse_block({"<eof>"})
        if not self.at_kind("eof"):
            raise ParseError(f"unexpected {self.tok.value!r}", self.tok.line, self.tok.col)
        chunk = Chunk(0, 1, 0, len(self.source), body, self.source)
        return chunk

    def parse_block(self, stop: set[str]) -> Block:
        start = self.tok
        stmts: list[Node] = []
        while not self.at_kind("eof") and self.tok.value not in stop:
            if self.at(";"):
                self.advance()
                continue
            stmts.append(self.parse_statement())
            if self.at(";"):
                self.advance()
        block = Block()
        block.stmts = stmts
        block.start = start.start
        block.line = start.line
        block.col = start.col
        block.end = stmts[-1].end if stmts else start.end
        return block

    # -- statements ----------------------------------------------------

    def parse_statement(self) -> Node:
        self._tick()
        t = self.tok
        if t.value == "local":
            return self.parse_local()
        if t.value == "function":
            return self.parse_function_decl()
        if t.value == "if":
            return self.parse_if_stmt()
        if t.value == "while":
            return self.parse_while()
        if t.value == "repeat":
            return self.parse_repeat()
        if t.value == "for":
            return self.parse_for()
        if t.value == "do":
            return self.parse_do()
        if t.value == "return":
            return self.parse_return()
        if t.value == "break":
            self.advance()
            return self._span(BreakStmt(), t)
        if t.value == "continue" and self.peek(1).value != "=":
            self.advance()
            return self._span(ContinueStmt(), t)
        if t.value == "type" and self.peek(1).kind == "name":
            return self.parse_type_alias(False)
        if t.value == "export" and self.peek(1).value == "type":
            return self.parse_type_alias(True)
        if t.value == "@":
            return self.parse_attribute()
        if t.value == ";":
            self.advance()
            return self._span(DoStmt(), t)

        start = t
        expr = self.parse_expr()
        # Multiple assignment: `a, b = 1, 2` and `a.b, c[1] = f()`.
        extra_targets: list[Node] = []
        while self.at(","):
            self.advance()
            extra_targets.append(self.parse_expr())
        if self.at("=") or self.tok.value in _COMPOUND:
            op = self.advance().value
            targets = [expr] + extra_targets
            values = self.parse_expr_list()
            node = Assign(targets=targets, values=values, op=op)
            return self._span(node, start)
        if extra_targets:
            raise ParseError(f"expected '=', found {self.tok.value!r}", self.tok.line, self.tok.col)
        if isinstance(expr, CallExpr):
            return self._span(CallStmt(call=expr), start)
        # Luau only allows call expressions as expression statements. Anything else
        # (including a bare name) is not a statement; report it rather than guess.
        raise ParseError(f"expression is not a statement: {self.tok.value!r}",
                         t.line, t.col)

    def parse_local(self) -> Node:
        start = self.expect("local")
        if self.at("function"):
            self.advance()
            name = self.expect_name()
            func = self.parse_function_body(start, name=name)
            return self._span(LocalFunction(name=name, func=func), start)
        names: list[str] = []
        types: list[str | None] = []
        while True:
            names.append(self.expect_name())
            if self.at(":"):
                self.advance()
                types.append(self.parse_type())
            else:
                types.append(None)
            if not self.at(","):
                break
            self.advance()
        values: list[Node] = []
        if self.at("="):
            self.advance()
            values = self.parse_expr_list()
        node = LocalAssign(names=names, types=types, values=values)
        return self._span(node, start)

    def parse_function_decl(self) -> Node:
        start = self.expect("function")
        # `function a.b.c(...)` names a nested table field; keep the dotted text.
        name_parts: list[str] = [self.expect_name()]
        while self.at(".") or self.at(":"):
            self.advance()
            name_parts.append(self.expect_name())
        name = ".".join(name_parts)
        func = self.parse_function_body(start, name=name)
        return self._span(FunctionDecl(name=name, func=func), start)

    def parse_function_body(self, start: Token, name: str = "") -> FunctionExpr:
        if self.at("<"):
            self._skip_generics()
        self.expect("(")
        params: list[str] = []
        types: list[str | None] = []
        vararg = False
        if not self.at(")"):
            while True:
                if self.at("..."):
                    self.advance()
                    vararg = True
                    break
                params.append(self.expect_name())
                if self.at(":"):
                    self.advance()
                    types.append(self.parse_type())
                else:
                    types.append(None)
                if not self.at(","):
                    break
                self.advance()
        self.expect(")")
        return_type = None
        if self.at(":"):
            self.advance()
            return_type = self.parse_type()
        body = self.parse_block({"end"})
        self.expect("end")
        node = FunctionExpr(params=params, vararg=vararg, body=body, name=name,
                            param_types=types, return_type=return_type)
        # Span from the `function` keyword to the closing `end`.
        node.start = start.start
        node.line = start.line
        node.col = start.col
        node.end = self.tokens[self.pos - 1].end
        return node

    def parse_if_stmt(self) -> Node:
        start = self.expect("if")
        branches: list[tuple[Node, Block]] = []
        cond = self.parse_expr()
        self.expect("then")
        body = self.parse_block({"elseif", "else", "end"})
        branches.append((cond, body))
        while self.at("elseif"):
            self.advance()
            cond = self.parse_expr()
            self.expect("then")
            body = self.parse_block({"elseif", "else", "end"})
            branches.append((cond, body))
        else_body = None
        if self.at("else"):
            self.advance()
            else_body = self.parse_block({"end"})
        self.expect("end")
        return self._span(IfStmt(branches=branches, else_body=else_body), start)

    def parse_while(self) -> Node:
        start = self.expect("while")
        cond = self.parse_expr()
        self.expect("do")
        body = self.parse_block({"end"})
        self.expect("end")
        return self._span(WhileStmt(cond=cond, body=body), start)

    def parse_repeat(self) -> Node:
        start = self.expect("repeat")
        body = self.parse_block({"until"})
        self.expect("until")
        cond = self.parse_expr()
        return self._span(RepeatStmt(body=body, cond=cond), start)

    def parse_for(self) -> Node:
        start = self.expect("for")
        names = [self.expect_name()]
        while self.at(","):
            self.advance()
            names.append(self.expect_name())
        if self.at("="):
            self.advance()
            first = self.parse_expr()
            self.expect(",")
            stop = self.parse_expr()
            step = None
            if self.at(","):
                self.advance()
                step = self.parse_expr()
            self.expect("do")
            body = self.parse_block({"end"})
            self.expect("end")
            return self._span(
                ForNumericStmt(name=names[0], start=first, stop=stop, step=step, body=body),
                start,
            )
        if self.at("in"):
            self.advance()
            # `for k, v in next, table do` is a generic-for expression list, not one expr.
            iters = [self.parse_expr()]
            while self.at(","):
                self.advance()
                iters.append(self.parse_expr())
            self.expect("do")
            body = self.parse_block({"end"})
            self.expect("end")
            return self._span(ForGenericStmt(names=names, iter=iters[0], iters=iters,
                                             body=body), start)
        raise ParseError("malformed for statement", self.tok.line, self.tok.col)

    def parse_do(self) -> Node:
        start = self.expect("do")
        body = self.parse_block({"end"})
        self.expect("end")
        return self._span(DoStmt(body=body), start)

    def parse_return(self) -> Node:
        start = self.expect("return")
        if self.at_kind("eof") or self.tok.value in {"end", "else", "elseif", "until", ";"}:
            return self._span(ReturnStmt(values=[]), start)
        values = self.parse_expr_list()
        return self._span(ReturnStmt(values=values), start)

    def parse_type_alias(self, exported: bool) -> Node:
        start = self.tok
        if exported:
            self.expect("export")
        self.expect("type")
        name = self.expect_name()
        if self.at("<"):
            self._skip_generics()
        self.expect("=")
        text = self.parse_type()
        return self._span(TypeAlias(name=name, type_text=text, exported=exported), start)

    def parse_attribute(self) -> Node:
        start = self.expect("@")
        name = self.expect_name()
        # Attributes are not modelled in detail; consume an optional call/args list.
        if self.at("("):
            self._skip_balanced("(", ")")
        return self._span(AttributeStmt(name=name), start)

    # -- expressions ---------------------------------------------------

    def parse_expr_list(self) -> list[Node]:
        values = [self.parse_expr()]
        while self.at(","):
            self.advance()
            values.append(self.parse_expr())
        return values

    def parse_expr(self, min_prec: int = 0) -> Node:
        self._tick()
        self.expr_depth += 1
        if self.expr_depth > MAX_PARSE_DEPTH:
            self.expr_depth -= 1
            raise ParseError(f"expression nesting exceeds {MAX_PARSE_DEPTH} levels",
                             self.tok.line, self.tok.col)
        try:
            return self._parse_expr_prec(min_prec)
        finally:
            self.expr_depth -= 1

    def _parse_expr_prec(self, min_prec: int = 0) -> Node:
        left = self.parse_unary()
        while True:
            op = self.tok.value
            if op == "::":
                self.advance()
                type_text = self.parse_type()
                left = self._span(TypeAssert(expr=left, type_text=type_text), self.tokens[self.pos - 1])
                continue
            info = _BINARY.get(op)
            if info is None or info[0] <= min_prec:
                # Right-associative operators use `<` rather than `<=` in the loop.
                if info is None or not (info[1] and info[0] == min_prec + 1):
                    break
            prec, right_assoc = info
            self.advance()
            next_min = prec if right_assoc else prec + 1
            right = self.parse_expr(next_min)
            node = BinOp(op=op, left=left, right=right)
            node.start = left.start
            node.end = right.end
            node.line = left.line
            node.col = left.col
            left = node
        return left

    def parse_unary(self) -> Node:
        t = self.tok
        if t.value in _UNARY:
            self.advance()
            operand = self.parse_unary()
            node = UnOp(op=t.value, operand=operand)
            node.start = t.start
            node.end = operand.end
            node.line = t.line
            node.col = t.col
            return node
        return self.parse_suffix(self.parse_primary())

    def parse_suffix(self, expr: Node) -> Node:
        while True:
            if self.at("."):
                self.advance()
                name = self.expect_name()
                node = IndexExpr(obj=expr, index=name, dot=True)
                node.start = expr.start
                node.end = self.tokens[self.pos - 1].end
                node.line = expr.line
                node.col = expr.col
                expr = node
            elif self.at("["):
                self.advance()
                index = self.parse_expr()
                self.expect("]")
                node = IndexExpr(obj=expr, index=index, dot=False)
                node.start = expr.start
                node.end = self.tokens[self.pos - 1].end
                node.line = expr.line
                node.col = expr.col
                expr = node
            elif (self.at(":") and self.peek(1).kind == "name"
                  and (self.peek(2).value in ("(", "{") or self.peek(2).kind == "string")):
                self.advance()
                name = self.advance().value
                args = self.parse_call_args()
                node = CallExpr(func=expr, args=args, method=True, method_name=name)
                node.start = expr.start
                node.end = self.tokens[self.pos - 1].end
                node.line = expr.line
                node.col = expr.col
                expr = node
            elif self.at("("):
                args = self.parse_call_args()
                node = CallExpr(func=expr, args=args, method=False)
                node.start = expr.start
                node.end = self.tokens[self.pos - 1].end
                node.line = expr.line
                node.col = expr.col
                expr = node
            elif self.tok.kind == "string" or self.at("{"):
                # Luau call sugar: f "text" / f { table }.
                args = self.parse_call_args()
                node = CallExpr(func=expr, args=args, method=False)
                node.start = expr.start
                node.end = self.tokens[self.pos - 1].end
                node.line = expr.line
                node.col = expr.col
                expr = node
            else:
                break
        return expr

    def parse_call_args(self) -> list[Node]:
        if self.at("("):
            self.advance()
            args: list[Node] = []
            if not self.at(")"):
                args = self.parse_expr_list()
            self.expect(")")
            return args
        if self.at("{"):
            return [self.parse_table()]
        if self.tok.kind == "string":
            t = self.advance()
            return [Literal(kind="string", value=t.text, raw=t.value, line=t.line, col=t.col,
                            start=t.start, end=t.end)]
        raise ParseError(f"expected call arguments, found {self.tok.value!r}",
                         self.tok.line, self.tok.col)

    def parse_primary(self) -> Node:
        t = self.tok
        if t.kind == "number":
            self.advance()
            return self._span(Literal(kind="number", value=t.value, raw=t.value), t)
        if t.kind == "string":
            self.advance()
            return self._span(Literal(kind="string", value=t.text, raw=t.value), t)
        if t.value in ("nil", "true", "false"):
            self.advance()
            return self._span(Literal(kind=t.value, value=t.value, raw=t.value), t)
        if t.value == "...":
            self.advance()
            return self._span(Vararg(), t)
        if t.value == "function":
            self.advance()
            return self.parse_function_body(t)
        if t.value == "{":
            return self.parse_table()
        if t.value == "(":
            self.advance()
            inner = self.parse_expr()
            self.expect(")")
            node = Paren(expr=inner)
            node.start = t.start
            node.end = self.tokens[self.pos - 1].end
            node.line = t.line
            node.col = t.col
            return node
        if t.kind == "name" or t.value in {"type", "continue"}:
            self.advance()
            return self._span(NameExpr(name=t.value), t)
        if t.value == "if":
            return self.parse_if_expr()
        raise ParseError(f"expected an expression, found {t.value!r}", t.line, t.col)

    def parse_table(self) -> Node:
        start = self.expect("{")
        fields: list[TableField] = []
        while not self.at("}"):
            if self.at("["):
                self.advance()
                key_expr = self.parse_expr()
                self.expect("]")
                self.expect("=")
                value = self.parse_expr()
                fields.append(TableField(key_expr=key_expr, value=value))
            elif self.tok.kind == "name" and self.peek(1).value == "=":
                key = self.advance().value
                self.advance()
                value = self.parse_expr()
                fields.append(TableField(key=key, value=value))
            else:
                value = self.parse_expr()
                fields.append(TableField(key=None, key_expr=None, value=value))
            if self.at(",") or self.at(";"):
                self.advance()
                continue
            if not self.at("}"):
                raise ParseError(f"expected ',' or '}}' in table, found {self.tok.value!r}",
                                 self.tok.line, self.tok.col)
        self.expect("}")
        node = TableExpr(fields=fields)
        node.start = start.start
        node.end = self.tokens[self.pos - 1].end
        node.line = start.line
        node.col = start.col
        return node

    def parse_if_expr(self) -> Node:
        start = self.expect("if")
        cond = self.parse_expr()
        self.expect("then")
        yes = self.parse_expr()
        branches: list[tuple[Node, Node]] = [(cond, yes)]
        else_expr = None
        if self.at("elseif"):
            # Recursive if-expression chain.
            self.advance()
            # Rebuild through a nested parse without the leading `if`.
            cond2 = self.parse_expr()
            self.expect("then")
            yes2 = self.parse_expr()
            branches.append((cond2, yes2))
            while self.at("elseif"):
                self.advance()
                cond3 = self.parse_expr()
                self.expect("then")
                yes3 = self.parse_expr()
                branches.append((cond3, yes3))
            if self.at("else"):
                self.advance()
                else_expr = self.parse_expr()
        elif self.at("else"):
            self.advance()
            else_expr = self.parse_expr()
        node = IfExpr(branches=branches, else_expr=else_expr)
        node.start = start.start
        node.end = (else_expr.end if else_expr else yes.end)
        node.line = start.line
        node.col = start.col
        return node

    # -- types ---------------------------------------------------------
    # Types are parsed to a source string, not a typed AST. That keeps the parser honest
    # about syntax while leaving type-aware rules for a later release.

    def parse_type(self) -> str:
        start = self.tok
        text = self._parse_type_expr()
        node_end = self.tokens[self.pos - 1].end
        return self.source[start.start:node_end].strip() or text

    def _parse_type_expr(self) -> str:
        # Union/intersection have low precedence; a function type is to the right of ->
        left = self._parse_type_primary()
        while self.tok.value in ("|", "&", "?"):
            op = self.advance().value
            if op == "?":
                left += "?"
                continue
            right = self._parse_type_primary()
            left += f" {op} {right}"
        if self.at("->"):
            self.advance()
            ret = self._parse_type_expr()
            return f"{left} -> {ret}"
        return left

    def _parse_type_primary(self) -> str:
        t = self.tok
        if t.value == "(":
            self.advance()
            parts: list[str] = []
            while not self.at(")") and not self.at_kind("eof"):
                # Named parameter in a function type: `(x: number) -> ...`.
                if self.tok.kind == "name" and self.peek(1).value == ":":
                    name = self.advance().value
                    self.expect(":")
                    parts.append(f"{name}: {self._parse_type_expr()}")
                else:
                    parts.append(self._parse_type_expr())
                if self.at(","):
                    self.advance()
                elif not self.at(")"):
                    break
            self.expect(")")
            return f"({', '.join(parts)})"
        if t.value == "{":
            self.advance()
            depth = 1
            start = self.pos
            while self.pos < len(self.tokens) and depth:
                if self.tok.value == "{":
                    depth += 1
                elif self.tok.value == "}":
                    depth -= 1
                    if depth == 0:
                        break
                self.advance()
            self.expect("}")
            return self.source[t.start:self.tokens[self.pos - 1].end]
        if t.value == "typeof":
            self.advance()
            self.expect("(")
            self.parse_expr()
            self.expect(")")
            return "typeof(...)"
        if t.kind == "string":
            self.advance()
            return t.value
        if t.kind == "name" or t.value in ("nil", "true", "false"):
            self.advance()
            text = t.value
            if self.at("<"):
                inner = self._parse_type_generics()
                text += f"<{inner}>"
            return text
        if t.value == "...":
            self.advance()
            return "..."
        raise ParseError(f"expected a type, found {t.value!r}", t.line, t.col)

    def _parse_type_list(self, stop: str) -> str:
        parts: list[str] = []
        while not self.at(stop) and not self.at_kind("eof"):
            parts.append(self._parse_type_expr())
            if self.at(","):
                self.advance()
            elif not self.at(stop):
                break
        return ", ".join(parts)

    def _parse_type_generics(self) -> str:
        self.expect("<")
        parts: list[str] = []
        while not self.at(">") and not self.at_kind("eof"):
            parts.append(self._parse_type_expr())
            if self.at(","):
                self.advance()
        self.expect(">")
        return ", ".join(parts)

    def _skip_generics(self) -> None:
        self.expect("<")
        depth = 1
        while depth and not self.at_kind("eof"):
            if self.at("<"):
                depth += 1
            elif self.at(">"):
                depth -= 1
            self.advance()

    def _skip_balanced(self, open_: str, close: str) -> None:
        self.expect(open_)
        depth = 1
        while depth and not self.at_kind("eof"):
            if self.tok.value == open_:
                depth += 1
            elif self.tok.value == close:
                depth -= 1
            self.advance()


# TypeAssert is appended here to keep the statement/expression classes in one section.
@dataclass
class TypeAssert(Node):
    expr: Node | None = None
    type_text: str = ""


def parse(source: str, *, deadline: float | None = None,
          max_seconds: float | None = None) -> Chunk:
    """Parse Luau source. Raises ParseError with line/column on syntax we cannot read.

    Resource limits (bytes, tokens, nodes, expression depth, wall-clock) also raise
    ``ParseError``; callers treat every ParseError as a counted fallback, never a crash.
    """
    try:
        return Parser(source, deadline=deadline, max_seconds=max_seconds).parse()
    except RecursionError as exc:
        raise ParseError("parser nesting exceeded the Python recursion guard") from exc


def walk(node: Node | None, *, _seen: set[int] | None = None) -> Iterable[Node]:
    """Yield every AST node depth-first. Cycles are impossible in the parsed tree."""
    if node is None:
        return
    seen = _seen if _seen is not None else set()
    if id(node) in seen:
        return
    seen.add(id(node))
    yield node
    for name in getattr(node, "__dataclass_fields__", {}):
        value = getattr(node, name)
        if isinstance(value, Node):
            yield from walk(value, _seen=seen)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, Node):
                    yield from walk(item, _seen=seen)
                elif isinstance(item, tuple):
                    for sub in item:
                        if isinstance(sub, Node):
                            yield from walk(sub, _seen=seen)
