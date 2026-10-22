"""Packaging contract tests.

These catch a class of bug that no behavioural test can see: the package
imports fine in CI because CI installs ``.[all]``, so a *real* user with a
plain ``pip install vehsec`` hits ``ModuleNotFoundError`` on first run.

Concretely, on 2026-10-23 the console script ``vehsec`` pointed at
``vehsec.cli``, which imports ``click`` and ``rich`` — but both were declared
only in the optional ``cli`` extra. Every documented one-liner therefore
crashed on a clean install, and the README's headline command (``uvx --from
"vehsec[mcp]"``) failed for the same reason.

The contract under test:

    For each entry in ``[project.scripts]``, every third-party module that
    its target module imports **at module scope** must be provided by
    ``dependencies`` (always installed) or by that script's declared extras.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src" / "vehsec"

# Distribution name -> importable module names it provides.
DIST_TO_IMPORTS = {
    "python-can": {"can"},
    "can-isotp": {"isotp"},
    "udsoncan": {"udsoncan"},
    "ecdsa": {"ecdsa"},
    "click": {"click"},
    "rich": {"rich"},
    "textual": {"textual"},
    "mcp": {"mcp"},
    "cryptography": {"cryptography"},
}

# A script may rely on extras; anything else must work on a bare install.
SCRIPT_EXTRAS = {
    "vehsec": set(),      # must work with `pip install vehsec`
    "vehsec-mcp": {"mcp"},  # documented as `pip install "vehsec[mcp]"`
}


def _requirement_name(req: str) -> str:
    """``'click>=8.1'`` -> ``'click'``; ``'mcp>=1.2,<2'`` -> ``'mcp'``."""
    return re.split(r"[<>=!~\[; ]", req.strip().strip("'\","), 1)[0].strip("'\"")


def _array_block(text: str, header: str) -> list[str]:
    """Return the string literals inside ``header = [ ... ]``."""
    m = re.search(re.escape(header) + r"\s*=\s*\[(.*?)\]", text, re.S)
    if not m:
        return []
    return re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1)) and [
        a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1))
    ]


def _load_declared() -> tuple[list[str], dict[str, list[str]]]:
    text = PYPROJECT.read_text(encoding="utf-8")
    base = _array_block(text, "dependencies")
    extras: dict[str, list[str]] = {}
    section = re.search(r"\[project\.optional-dependencies\](.*?)(?=\n\[)", text, re.S)
    if section:
        for name, body in re.findall(r"^(\w+)\s*=\s*\[(.*?)\]", section.group(1), re.S | re.M):
            extras[name] = [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", body)]
    return base, extras


def _module_scope_third_party(path: Path) -> set[str]:
    """Third-party modules imported at module scope (not inside a function)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in tree.body:  # module scope only
        targets: list[ast.stmt] = [node]
        if isinstance(node, ast.Try):  # e.g. mcp 1.x vs 2.x import shim
            targets = list(node.body) + list(node.orelse)
        for stmt in targets:
            if isinstance(stmt, ast.Import):
                found.update(a.name.split(".")[0] for a in stmt.names)
            elif isinstance(stmt, ast.ImportFrom) and stmt.module and stmt.level == 0:
                found.add(stmt.module.split(".")[0])
    return {m for m in found if m != "vehsec" and m not in sys.stdlib_module_names}


def _provided(requirements: list[str]) -> set[str]:
    out: set[str] = set()
    for req in requirements:
        out |= DIST_TO_IMPORTS.get(_requirement_name(req), {_requirement_name(req)})
    return out


BASE, EXTRAS = _load_declared()


@pytest.mark.parametrize("script", sorted(SCRIPT_EXTRAS))
def test_console_script_dependencies_are_installable(script: str) -> None:
    """Every console script must import with base deps + its own extras."""
    m = re.search(rf'^{re.escape(script)}\s*=\s*"([^":]+):', PYPROJECT.read_text(encoding="utf-8"), re.M)
    assert m, f"[project.scripts] has no entry for {script!r}"
    module = m.group(1)
    path = SRC / f"{module.split('.')[-1]}.py"
    assert path.exists(), f"{script!r} points at {module!r}, expected {path}"

    available = _provided(BASE)
    for extra in SCRIPT_EXTRAS[script]:
        assert extra in EXTRAS, f"{script!r} relies on undeclared extra {extra!r}"
        available |= _provided(EXTRAS[extra])

    imported = _module_scope_third_party(path)
    missing = {i for i in imported if i not in available}
    assert not missing, (
        f"`{script}` imports {sorted(missing)} at module scope, but they are not in "
        f"dependencies{'' if available == _provided(BASE) else ' or its extras'}. "
        f"A plain `pip install vehsec` then `{script}` would crash on startup."
    )


def test_declared_dists_are_all_mapped() -> None:
    """A new dependency without a dist->import mapping would silently pass."""
    # `dev` is never installed by a user and never backs a console script,
    # so it is out of scope for the import-name mapping.
    known = set(BASE) | {r for extra, reqs in EXTRAS.items() if extra != "dev" for r in reqs}
    known = {_requirement_name(r) for r in known}
    unmapped = {d for d in known if d not in DIST_TO_IMPORTS}
    assert not unmapped, f"add {sorted(unmapped)} to DIST_TO_IMPORTS in {Path(__file__).name}"


def test_scripts_section_matches_contract_table() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    declared = set(re.findall(r"^(\w[\w-]*)\s*=\s*\"vehsec\.", text, re.M))
    assert declared == set(SCRIPT_EXTRAS), (
        f"[project.scripts] changed ({sorted(declared)}); update SCRIPT_EXTRAS"
    )


def test_vehsec_mcp_extra_is_declared() -> None:
    """The README advertises `uvx --from vehsec[mcp]`; the extra must exist."""
    assert "mcp" in EXTRAS, "the `mcp` extra is referenced by every install doc"
