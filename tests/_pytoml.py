"""Minimal TOML reader for test tooling on Python 3.10 and older.

Why this exists
---------------
``tests/test_packaging.py`` is the guard that stopped a console script from
shipping with undeclared dependencies (that bug escaped once). It reads
``pyproject.toml`` with ``tomllib``, which only exists from Python 3.11 on.
These projects advertise ``requires-python = ">=3.10"`` and CI runs a 3.10 leg,
so on that leg collection died with ``ModuleNotFoundError: No module named
'tomllib'`` and the whole run went red — while 3.12 laptops stayed green and
hid it for days.

The two cheap options both lose: raising ``requires-python`` to 3.11 breaks
``pip install`` for everyone still on Python 3.10 (Ubuntu 22.04), and skipping
the guard on 3.10 silently disables the one test that catches the one bug that
already escaped. So this module exists instead. It is stdlib-only because
pulling in ``tomli`` would contradict the zero-dependency promise these tools
are built on.

Supported subset (everything in these ``pyproject.toml`` files)
--------------------------------------------------------------
comments, ``[table]`` and ``[dotted.table]`` headers, dotted keys, strings
(basic, literal and triple-quoted variants), integers, floats, booleans,
arrays (may span lines, may contain inline tables) and inline tables.

Anything outside that raises ``TomlError`` rather than guessing: a wrong answer
inside a packaging guard is worse than a loud failure. On Python 3.11+,
``tests/test_pytoml_parity.py`` asserts this parser agrees with ``tomllib``
on the repository's own ``pyproject.toml``.
"""

from __future__ import annotations

_BASIC_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


class TomlError(ValueError):
    """Raised for anything outside the supported subset."""


def loads(text: str) -> dict:
    """Parse TOML text into nested dicts."""
    lines = text.splitlines()
    root: dict = {}
    current: dict = root
    index = 0
    while index < len(lines):
        line, index = _strip_comment(lines[index]), index + 1
        line = line.strip()
        if not line:
            continue
        if line.startswith("["):
            current = _descend(root, _header(line))
            continue
        key, sep, rest = line.partition("=")
        if not sep:
            raise TomlError(f"expected 'key = value', got {line!r}")
        value_text, index = _collect_value(rest, lines, index)
        target = current
        parts = _split_key(key.strip())
        for part in parts[:-1]:
            nxt = target.get(part)
            if nxt is None:
                nxt = target[part] = {}
            elif not isinstance(nxt, dict):
                raise TomlError(f"{key!r} traverses a non-table value")
            target = nxt
        if parts[-1] in target:
            raise TomlError(f"duplicate key {key!r}")
        target[parts[-1]] = _parse_scalar(value_text.strip())
    return root


def load(path: str) -> dict:  # mirrors tomllib.load for convenience
    with open(path, "rb") as fh:
        return loads(fh.read().decode("utf-8"))


# --------------------------------------------------------------------------- #
# line level helpers
# --------------------------------------------------------------------------- #
def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment that is not inside a string."""
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is None:
            if line.startswith('"""', i) or line.startswith("'''", i):
                quote = line[i : i + 3]
                i += 3
                continue
            if ch in "\"'":
                quote = ch
            elif ch == "#":
                return line[:i]
            i += 1
            continue
        if len(quote) == 3:  # multi-line string: only the closing triple ends it
            if line.startswith(quote, i):
                quote = None
                i += 3
                continue
            i += 1
            continue
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch == quote:
            quote = None
        i += 1
    if quote is not None and len(quote) == 1:
        raise TomlError(f"unterminated string: {line[:40]!r}")
    return line


def _header(line: str) -> list[str]:
    """``[tool.setuptools.packages.find]`` -> its dotted parts."""
    if not line.endswith("]") or line.count("[") != line.count("]"):
        raise TomlError(f"unsupported table header: {line!r}")
    inner = line.strip()[1:-1].strip()
    if not inner:
        raise TomlError("empty table header")
    return _split_key(inner)


def _descend(root: dict, header: list[str]) -> dict:
    node = root
    for part in header:
        existing = node.get(part)
        if existing is None:
            existing = node[part] = {}
        elif not isinstance(existing, dict):
            raise TomlError(f"{'.'.join(header)!r} collides with a non-table value")
        node = existing
    return node


def _open_multiline(text: str) -> bool:
    """True when ``text`` ends inside an unterminated triple-quoted string."""
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is None:
            if text.startswith('"""', i) or text.startswith("'''", i):
                quote = text[i : i + 3]
                i += 3
                continue
            if ch in "\"'":
                quote = ch
            i += 1
            continue
        if len(quote) == 3:
            if text.startswith(quote, i):
                quote = None
                i += 3
                continue
            i += 1
            continue
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch == quote:
            quote = None
        i += 1
    return quote is not None and len(quote) == 3


def _split_key(key: str) -> list[str]:
    parts: list[str] = []
    for part in key.split("."):
        part = part.strip()
        if not part:
            raise TomlError(f"empty key segment in {key!r}")
        parts.append(_unquote(part) if part[0] in "\"'" else part)
    return parts


def _collect_value(chunk: str, lines: list[str], index: int) -> tuple[str, int]:
    """Return the complete value text, joining continuation lines if needed."""
    text = _strip_comment(chunk).strip()
    while True:
        state = _balance_state(text)
        if state == "ok":
            return text, index
        if state == "bad" or index >= len(lines):
            raise TomlError(f"unterminated value starting with {text[:40]!r}")
        nxt = lines[index]
        # Inside a multi-line string every character is content, comments
        # included - stripping there would corrupt the value. Join with a real
        # newline so multi-line strings keep their line breaks.
        text = text.rstrip() + "\n" + (
            nxt if _open_multiline(text) else _strip_comment(nxt).strip()
        )
        index += 1


def _balance_state(text: str) -> str:
    """``ok`` (complete), ``more`` (needs the next line) or ``bad``."""
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if len(quote) == 3:
                if text.startswith(quote, i):
                    quote = None
                    i += 3
                    continue
                i += 1
                continue
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if text.startswith('"""', i) or text.startswith("'''", i):
            quote = text[i : i + 3]
            i += 3
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
            if depth < 0:
                return "bad"
        i += 1
    if quote is not None or depth > 0:
        return "more"
    return "ok"


# --------------------------------------------------------------------------- #
# values
# --------------------------------------------------------------------------- #
def _parse_scalar(text: str) -> object:
    if not text:
        raise TomlError("empty value")
    if text[0] in "\"'":
        return _read_string(text)
    if text[0] == "[":
        if not text.endswith("]"):
            raise TomlError(f"unterminated array: {text[:40]!r}")
        return _split_elements(text[1:-1], _parse_scalar)
    if text[0] == "{":
        if not text.endswith("}"):
            raise TomlError(f"unterminated inline table: {text[:40]!r}")
        return _inline_table(text[1:-1])
    if text in ("true", "false"):
        return text == "true"
    if text[0] in "+-.0123456789":
        bare = text.replace("_", "")
        try:
            return int(bare)
        except ValueError:
            pass
        try:
            return float(bare)
        except ValueError as exc:
            raise TomlError(f"not a valid number: {text!r}") from exc
    raise TomlError(f"unsupported value: {text[:40]!r}")


def _split_elements(body: str, parse) -> list[object]:
    """Split a container body on commas that sit outside strings and brackets."""
    out = [parse(token.strip()) for token in _top_level_split(body) if token.strip()]
    return out


def _inline_table(body: str) -> dict:
    table: dict = {}
    for pair in _top_level_split(body):
        pair = pair.strip()
        if not pair:
            continue
        key, sep, rest = pair.partition("=")
        if not sep:
            raise TomlError(f"inline table entry without '=': {pair!r}")
        parts = _split_key(key.strip())
        node = table
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = node[part] = {}
            node = child
        node[parts[-1]] = _parse_scalar(rest.strip())
    return table


def _top_level_split(body: str) -> list[str]:
    tokens: list[str] = []
    buf = ""
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(body):
        ch = body[i]
        if quote:
            if len(quote) == 3:
                if body.startswith(quote, i):
                    quote = None
                    buf += quote
                    i += 3
                    continue
                buf += ch
                i += 1
                continue
            if quote == '"' and ch == "\\":
                buf += body[i : i + 2]
                i += 2
                continue
            buf += ch
            if ch == quote:
                quote = None
            i += 1
            continue
        if body.startswith('"""', i) or body.startswith("'''", i):
            quote = body[i : i + 3]
            buf += quote
            i += 3
            continue
        if ch in "\"'":
            quote = ch
            buf += ch
        elif ch in "[{":
            depth += 1
            buf += ch
        elif ch in "]}":
            depth -= 1
            buf += ch
        elif ch == "," and depth == 0:
            tokens.append(buf)
            buf = ""
        else:
            buf += ch
        i += 1
    if quote is not None:
        raise TomlError(f"unterminated string in {body[:40]!r}")
    tokens.append(buf)
    return tokens


def _read_string(text: str) -> str:
    for delim in ('"""', "'''", '"', "'"):
        if text.startswith(delim):
            if not text.endswith(delim) or len(text) < 2 * len(delim):
                raise TomlError(f"unterminated string: {text[:40]!r}")
            inner = text[len(delim) : -len(delim)]
            if delim == '"""' and inner.startswith("\n"):
                # TOML trims one newline right after the opening delimiter
                inner = inner[1:]
            return inner if delim.startswith("'") else _unescape(inner)
    raise TomlError(f"not a string: {text[:40]!r}")


def _unescape(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            raise TomlError("trailing backslash in string")
        esc = body[i]
        if esc in _BASIC_ESCAPES:
            out.append(_BASIC_ESCAPES[esc])
            i += 1
        elif esc == "u":
            out.append(chr(int(body[i + 1 : i + 5], 16)))
            i += 5
        elif esc == "U":
            out.append(chr(int(body[i + 1 : i + 9], 16)))
            i += 9
        else:
            raise TomlError(f"unsupported escape \\{esc}")
    return "".join(out)


def _unquote(token: str) -> str:
    return _read_string(token) if token[0] in "\"'" else token
