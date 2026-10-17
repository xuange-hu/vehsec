import asyncio

import pytest

pytest.importorskip("mcp", reason="mcp is required for MCP server tests")

from vehsec import mcp_server  # noqa: E402

EXPECTED = {
    "can_send",
    "can_fuzz",
    "can_analyze",
    "uds_security_access",
    "uds_read_did",
    "uds_read_dtcs",
    "uds_clear_dtcs",
    "uds_decode_dtc",
    "uds_raw",
    "seedkey_solve",
    "v2x_analyze",
    "icsim_set_speed",
    "icsim_tamper_demo",
    "isotp_segment",
    "isotp_decode",
    "isotp_reassemble",
    "j1939_decode",
    "j1939_encode",
    "j1939_decode_name",
    "j1939_decode_dm1",
    "doip_simulate",
    "doip_probe",
    "dbc_decode",
    "dbc_info",
}


def test_all_tools_registered():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    names = {t.name for t in tools}
    assert EXPECTED <= names, f"missing tools: {EXPECTED - names}"


def test_every_tool_has_a_description():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    for t in tools:
        assert t.description, f"tool {t.name} has no description (agents need it)"
