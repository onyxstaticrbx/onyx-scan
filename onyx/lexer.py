"""Minimal Luau tokenizer.

Regex over raw source produces false positives from comments and strings.
This tokenizer strips both while preserving line/column positions, so every
rule sees only real code and can still report an accurate line number.

Not a full Luau parser. Deliberately small: a rule engine needs a reliable
token stream, not an AST.
"""

from __future__ import annotations

from dataclasses import dataclass

KEYWORDS = frozenset(
    """
    and break do else elseif end false for function if in local nil not or
    repeat return then true until while continue type export
    """.split()
)


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # name | keyword | number | string | op | eof
    value: str
    line: int
    col: int
    # For strings, the decoded-ish content without delimiters.
    text: str = ""

    @property
    def is_name(self) -> bool:
        return self.kind == "name"


_LONG_BRACKET = "[]="
_OPERATORS = (
    "...", "..=", "//=", "<<=", ">>=",
    "==", "~=", "<=", ">=", "..", "//", "::", "->",
    "+=", "-=", "*=", "/=", "%=", "^=", "..", "&&", "||",
)


def _long_bracket_level(src: str, i: int) -> int | None:
    """Return the level of a long bracket starting at i, else None."""
    if src[i] != "[":
        return None
    j = i + 1
    level = 0
    while j < len(src) and src[j] == "=":
        level += 1
        j += 1
    if j < len(src) and src[j] == "[":
        return level
    return None


def tokenize(src: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(src)
    line = 1
    line_start = 0

    def col(pos: int) -> int:
        return pos - line_start + 1

    while i < n:
        ch = src[i]

        # Newline
        if ch == "\n":
            i += 1
            line += 1
            line_start = i
            continue

        # Whitespace
        if ch in " \t\r\f\v":
            i += 1
            continue

        # Comments
        if src.startswith("--", i):
            lvl = _long_bracket_level(src, i + 2) if i + 2 < n else None
            if lvl is not None:
                close = "]" + "=" * lvl + "]"
                end = src.find(close, i + 2)
                end = n if end == -1 else end + len(close)
            else:
                end = src.find("\n", i)
                end = n if end == -1 else end
            for c in src[i:end]:
                if c == "\n":
                    line += 1
                    line_start = i + src[i:end].index("\n") + 1
            i = end
            continue

        # Long strings [[ ... ]]
        if ch == "[":
            lvl = _long_bracket_level(src, i)
            if lvl is not None:
                close = "]" + "=" * lvl + "]"
                start = i
                start_line, start_col = line, col(i)
                body_start = i + lvl + 2
                end = src.find(close, body_start)
                if end == -1:
                    end = n
                    raw_end = n
                else:
                    raw_end = end + len(close)
                text = src[body_start:end]
                tokens.append(Token("string", src[start:raw_end], start_line, start_col, text=text))
                for idx, c in enumerate(src[body_start:raw_end]):
                    if c == "\n":
                        line += 1
                        line_start = body_start + idx + 1
                i = raw_end
                continue

        # Short strings
        if ch in "\"'":
            quote = ch
            start_line, start_col = line, col(i)
            j = i + 1
            buf = []
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
                    # unterminated string; treat newline as terminator
                    break
                buf.append(c)
                j += 1
            tokens.append(Token("string", src[i:j], start_line, start_col, text="".join(buf)))
            i = j
            continue

        # Numbers
        if ch.isdigit() or (ch == "." and i + 1 < n and src[i + 1].isdigit()):
            start = i
            start_line, start_col = line, col(i)
            if src.startswith(("0x", "0X"), i):
                i += 2
                while i < n and (src[i].isdigit() or src[i].lower() in "abcdef"):
                    i += 1
            else:
                while i < n and (src[i].isdigit() or src[i] in ".eE+-"):
                    # stop at + - unless exponent context is simple
                    if src[i] in "+-" and not (i > start and src[i - 1] in "eE"):
                        break
                    if src[i] == "." and i + 1 < n and src[i + 1] == ".":
                        break
                    i += 1
            tokens.append(Token("number", src[start:i], start_line, start_col))
            continue

        # Names / keywords
        if ch.isalpha() or ch == "_":
            start = i
            start_line, start_col = line, col(i)
            while i < n and (src[i].isalnum() or src[i] == "_"):
                i += 1
            word = src[start:i]
            kind = "keyword" if word in KEYWORDS else "name"
            tokens.append(Token(kind, word, start_line, start_col))
            continue

        # Operators
        matched = None
        for op in _OPERATORS:
            if src.startswith(op, i):
                matched = op
                break
        if matched:
            tokens.append(Token("op", matched, line, col(i)))
            i += len(matched)
            continue

        # Single-char punctuation
        tokens.append(Token("op", ch, line, col(i)))
        i += 1

    tokens.append(Token("eof", "", line, col(n)))
    return tokens


def token_text(tokens: list[Token], lo: int, hi: int) -> str:
    """Reconstruct approximate source text for a token span (best effort)."""
    return " ".join(t.value for t in tokens[lo:hi] if t.kind not in ("eof",))
