"""Guard the packaging surface: entry points, tool manifest and version.

These are the things that silently rot. A renamed function or a forgotten
version bump does not fail any behavioural test, but it breaks ``pip install``
users and every "just run this one-liner" instruction in the README — which is
exactly how a prospective stargazer gets a broken first impression.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

try:
    import tomllib
except ModuleNotFoundError:  # Python <= 3.10: tomllib landed in 3.11
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _pytoml as tomllib  # type: ignore[no-redef]

# tests/_pytoml.py covers 3.10 as well, so nothing here is skipped any more.
needs_toml = pytest.mark.skipif(tomllib is None, reason="tomllib needs Python 3.11+")


def _pyproject() -> dict:
    assert tomllib is not None
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# version must agree in both places
# --------------------------------------------------------------------------- #
@needs_toml
def test_version_matches_pyproject():
    import vehsec

    assert vehsec.__version__ == _pyproject()["project"]["version"], (
        "src/vehsec/__init__.py and pyproject.toml disagree on the version"
    )


def test_version_is_semver():
    import vehsec

    assert re.fullmatch(r"\d+\.\d+\.\d+", vehsec.__version__), vehsec.__version__


# --------------------------------------------------------------------------- #
# console scripts
# --------------------------------------------------------------------------- #
@needs_toml
def test_console_scripts_declared():
    scripts = _pyproject()["project"]["scripts"]
    assert scripts["vehsec"] == "vehsec.cli:main"
    # dedicated MCP entry: `uvx --from vehsec[mcp] vehsec-mcp` must keep working
    assert scripts["vehsec-mcp"] == "vehsec.mcp_server:run"


@needs_toml
def test_entry_point_targets_are_importable():
    """Resolve each ``module:attr`` target the way setuptools would."""
    import importlib

    for target in _pyproject()["project"]["scripts"].values():
        module, attr = target.split(":")
        obj = importlib.import_module(module)
        for part in attr.split("."):
            obj = getattr(obj, part)
        assert callable(obj), target


def test_mcp_module_exposes_run_and_manifest():
    from vehsec import mcp_server

    assert callable(mcp_server.run)
    assert callable(mcp_server.tool_manifest)


# --------------------------------------------------------------------------- #
# tool manifest
# --------------------------------------------------------------------------- #
def test_tool_manifest_is_complete_and_unique():
    pytest.importorskip("mcp")
    from vehsec.mcp_server import tool_manifest

    rows = tool_manifest()
    assert len(rows) >= 31, f"expected >=31 tools, got {len(rows)}"
    names = [r["name"] for r in rows]
    assert len(names) == len(set(names)), "duplicate tool names"
    for row in rows:
        assert row["name"]
        # an empty docstring becomes an empty tool description, and agents
        # cannot decide when to call a tool they have no description for
        assert row["description"], f"{row['name']} has no description"


@pytest.mark.parametrize(
    "name",
    ["can_send", "uds_security_access", "seedkey_recover", "doip_tls_audit",
     "dbc_decode", "j1939_decode", "isotp_explain"],
)
def test_pillar_tools_are_exposed(name):
    """One representative per pillar — catches a module silently not registering."""
    pytest.importorskip("mcp")
    from vehsec.mcp_server import tool_manifest

    assert name in {r["name"] for r in tool_manifest()}


def test_manifest_matches_decorated_tool_count():
    """Source of truth is the number of @mcp.tool() decorators in the file."""
    pytest.importorskip("mcp")
    from vehsec.mcp_server import tool_manifest

    src = (ROOT / "src" / "vehsec" / "mcp_server.py").read_text(encoding="utf-8")
    assert src.count("@mcp.tool(") == len(tool_manifest())


# --------------------------------------------------------------------------- #
# the shipped agent config must be valid and point at a real script
# --------------------------------------------------------------------------- #
def test_mcp_config_example_is_valid():
    cfg = json.loads((ROOT / "examples" / "mcp-config.json").read_text(encoding="utf-8"))
    server = cfg["mcpServers"]["vehsec"]
    assert server["command"] == "vehsec"
    assert server["args"] == ["mcp"]


def test_package_importable_without_optional_extras():
    """Importing the core must not require click/rich/mcp/cryptography."""
    import vehsec

    for mod in ("can_bus", "dbc", "j1939", "iso_tp", "seedkey", "v2x"):
        assert hasattr(vehsec, mod)
    assert "vehsec" in sys.modules
