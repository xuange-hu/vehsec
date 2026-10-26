"""Prove ``_pytoml`` is trustworthy before we let it guard packaging.

``tests/test_packaging.py`` silently stopped running on Python 3.10 because it
imported ``tomllib``. The fallback fixes the import, but a hand-written parser
that *silently disagrees* with the real one would be worse than the crash: the
guard would pass while reading the wrong dependencies.

So on any interpreter that has ``tomllib`` (3.11+) this module diffs the two
parsers over the repository's own ``pyproject.toml`` plus a fixture that
exercises every construct in the supported subset. On 3.10 the diff is skipped
and only the structural assertions run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from _pytoml import TomlError, loads

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"

tomllib = pytest.importorskip("tomllib", reason="tomllib needs Python 3.11+")

FIXTURE = '''
# leading comment
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "demo-pkg"
version = "1.2.3"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [{ name = "xuange-hu" }, { name = "nexus" }]
keywords = [
  "one",   # trailing comment inside an array
  "two",
]
description = "escapes: \\"quoted\\" and \\ttab and \\u00e9"
literal = 'raw \\n not an escape'
block = """
multi
line
"""
debug = true
ratio = 0.5
count = 12_000

[project.scripts]
demo = "demo.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
exclude = []
'''


def test_fixture_round_trips_every_supported_construct():
    data = loads(FIXTURE)
    assert data["build-system"]["requires"] == ["setuptools>=68", "wheel"]
    assert data["project"]["version"] == "1.2.3"
    assert data["project"]["license"] == {"text": "MIT"}
    assert data["project"]["authors"] == [{"name": "xuange-hu"}, {"name": "nexus"}]
    assert data["project"]["keywords"] == ["one", "two"]
    assert data["project"]["description"] == 'escapes: "quoted" and \ttab and \u00e9'
    assert data["project"]["literal"] == "raw \\n not an escape"
    assert data["project"]["block"] == "multi\nline\n"  # TOML trims the first newline
    assert data["project"]["debug"] is True
    assert data["project"]["ratio"] == 0.5
    assert data["project"]["count"] == 12000
    assert data["project"]["scripts"]["demo"] == "demo.cli:main"
    assert data["tool"]["setuptools"]["packages"]["find"] == {"where": ["src"], "exclude": []}


def test_matches_tomllib_on_the_fixture():
    assert loads(FIXTURE) == tomllib.loads(FIXTURE)


def test_matches_tomllib_on_this_repos_pyproject():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert loads(text) == tomllib.loads(text)


def test_matches_tomllib_on_a_multiline_array_and_inline_table():
    text = 'a = [\n  "x",\n  "y",\n]\nb = { c = "d", e = [1, 2] }\n'
    assert loads(text) == tomllib.loads(text)


def test_garbage_raises_instead_of_guessing():
    for bad in ['name = "unterminated', "name = [1, 2", "no equals sign here", "= 1"]:
        with pytest.raises(TomlError):
            loads(bad)
