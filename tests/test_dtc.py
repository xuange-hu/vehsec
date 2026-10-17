"""Tests for diagnostic trouble codes (UDS 0x19 / 0x14) and the raw escape hatch.

DTC handling is the single most requested UDS feature — it is what people expect
from a scan tool — so it gets both pure-codec tests (no bus) and full round
trips over the virtual CAN bus, including the multi-frame case: three DTC
records are 15 bytes, which does not fit in one classic CAN frame.
"""

import pytest

from vehsec import uds


# --- codec ------------------------------------------------------------------ #
def test_decode_powertrain_code():
    dtc = uds.decode_dtc(bytes.fromhex("010000"))
    assert dtc["code"] == "P0100"
    assert dtc["raw"] == "010000"
    assert dtc["description"].startswith("Mass or Volume Air Flow")


@pytest.mark.parametrize("raw,code", [
    ("010000", "P0100"),   # 00 -> P (powertrain)
    ("410000", "C0100"),   # 01 -> C (chassis)
    ("810000", "B0100"),   # 10 -> B (body)
    ("C10000", "U0100"),   # 11 -> U (network)
    ("042000", "P0420"),
])
def test_decode_letter_and_digits(raw, code):
    assert uds.decode_dtc(bytes.fromhex(raw))["code"] == code


def test_encode_round_trips_every_letter():
    for code in ("P0100", "C0100", "B0100", "U0100", "P0420", "C0035", "B0001"):
        assert uds.decode_dtc(uds.encode_dtc(code))["code"] == code


def test_encode_rejects_bad_input():
    for bad in ("P010", "X0100", "P010G", "P4100"):     # last: second char must be 0-3
        with pytest.raises(ValueError):
            uds.encode_dtc(bad)


def test_decode_needs_three_bytes():
    with pytest.raises(ValueError):
        uds.decode_dtc(b"\x01\x00")


def test_failure_type_byte_is_reported_separately():
    assert uds.decode_dtc(bytes.fromhex("01002A"))["failure_type"] == 0x2A


def test_unknown_code_has_no_description():
    assert uds.decode_dtc(bytes.fromhex("019900"))["description"] is None


def test_status_bit_expansion():
    assert uds.decode_dtc_status(0x08) == ["confirmedDTC"]
    assert uds.decode_dtc_status(0x2C) == ["pendingDTC", "confirmedDTC",
                                           "testFailedSinceLastClear"]
    assert uds.decode_dtc_status(0x00) == []


# --- virtual ECU dispatch (no bus) ------------------------------------------ #
def test_report_number_of_dtcs_by_status_mask():
    ecu = uds.VirtualEcu()
    resp = ecu.handle(bytes.fromhex("1901FF"))
    assert resp[:4] == bytes([0x59, 0x01, 0x09, 0x00])
    assert int.from_bytes(resp[4:6], "big") == len(uds.DEFAULT_DTCS)


def test_count_is_filtered_by_status_mask():
    ecu = uds.VirtualEcu()
    confirmed = ecu.handle(bytes.fromhex("190108"))
    assert int.from_bytes(confirmed[4:6], "big") == 3        # all three confirmed
    pending = ecu.handle(bytes.fromhex("190104"))
    assert int.from_bytes(pending[4:6], "big") == 2          # P0100 + P0420


def test_report_dtcs_by_status_mask_lists_records():
    ecu = uds.VirtualEcu()
    resp = ecu.handle(bytes.fromhex("1902FF"))
    assert resp[:3] == bytes([0x59, 0x02, 0x09])
    body = resp[3:]
    assert len(body) % 4 == 0                                # DTC + status each
    codes = [uds.decode_dtc(body[i:i + 3])["code"] for i in range(0, len(body), 4)]
    assert codes == ["P0100", "P0420", "U0100"]


def test_unsupported_dtc_subfunction_is_rejected():
    assert uds.VirtualEcu().handle(bytes.fromhex("1999")) == bytes([0x7F, 0x19, 0x12])


def test_clear_diagnostic_information():
    ecu = uds.VirtualEcu()
    assert ecu.handle(bytes.fromhex("14FFFFFF")) == bytes([0x54])
    assert ecu.dtcs == []
    assert ecu.handle(bytes.fromhex("1901FF"))[4:6] == b"\x00\x00"


def test_clear_honours_the_group_mask():
    """groupOfDTC is a bitmask: a DTC is cleared when (dtc & group) != 0.

    0x00FF00 hits the middle byte, so P0420 (0x042000) goes and the two codes
    with a zero middle byte survive.
    """
    ecu = uds.VirtualEcu()
    ecu.handle(bytes.fromhex("14") + bytes.fromhex("00FF00"))
    assert [uds.decode_dtc(bytes(d[:3]))["code"] for d in ecu.dtcs] == ["P0100", "U0100"]


def test_communication_control_records_state():
    ecu = uds.VirtualEcu()
    assert ecu.handle(bytes.fromhex("280301")) == bytes([0x68, 0x03])
    assert ecu.comm_state == 0x03


# --- end to end over the virtual bus ---------------------------------------- #
pytest.importorskip("isotp", reason="can-isotp is required for UDS round trips")
pytest.importorskip("udsoncan", reason="udsoncan is required for UDS round trips")


def _client(**kwargs):
    kwargs.setdefault("channel", "test-dtc")
    return uds.UdsClient(**kwargs)


def test_dtc_count_end_to_end():
    with _client() as c:
        assert c.dtc_count() == 3
        assert c.dtc_count(0x08) == 3


def test_read_dtcs_end_to_end():
    with _client() as c:
        records = c.read_dtcs()
    assert [r["code"] for r in records] == ["P0100", "P0420", "U0100"]
    assert records[2]["status_text"] == ["confirmedDTC"]
    assert records[2]["description"].startswith("Lost Communication")


def test_read_dtcs_filtered_by_status_mask():
    with _client() as c:
        assert [r["code"] for r in c.read_dtcs(status_mask=0x04)] == ["P0100", "P0420"]


def test_clear_dtcs_end_to_end():
    with _client() as c:
        result = c.clear_dtcs()
        assert result["cleared"] is True
        assert result["remaining"] == 0
        assert c.read_dtcs(supported=True) == []


def test_tester_present_end_to_end():
    with _client() as c:
        assert c.tester_present()["response"] == "7E00"


def test_communication_control_end_to_end():
    with _client() as c:
        assert c.comm_control(0x03, 0x01)["sub_function"] == 3


def test_raw_returns_verbatim_payload():
    with _client() as c:
        assert c.raw(bytes.fromhex("22F190"))[:3] == bytes.fromhex("62F190")


def test_raw_raises_a_named_negative_response():
    with _client() as c:
        with pytest.raises(uds.UdsError) as exc:
            c.raw(bytes.fromhex("22DEAD"))
    assert "requestOutOfRange" in str(exc.value)


def test_raw_can_be_told_to_return_negatives():
    with _client() as c:
        resp = c.raw(bytes.fromhex("22DEAD"), raise_on_negative=False)
    assert resp == bytes([0x7F, 0x22, 0x31])


def test_raw_rejects_an_empty_request():
    with _client() as c:
        with pytest.raises(ValueError):
            c.raw(b"")


# --- MCP tools -------------------------------------------------------------- #
def test_mcp_dtc_tools_are_registered():
    pytest.importorskip("mcp", reason="mcp is required for MCP server tests")
    import asyncio
    import json

    from vehsec import mcp_server

    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    for name in ("uds_read_dtcs", "uds_clear_dtcs", "uds_decode_dtc", "uds_raw"):
        assert name in tools, f"missing MCP tool {name}"

    async def call(name, **args):
        # FastMCP.call_tool returns (content_blocks, metadata); the payload is
        # JSON text in the first block.
        content, _meta = await mcp_server.mcp.call_tool(name, args)
        return json.loads(content[0].text)

    async def scenario():
        decoded = await call("uds_decode_dtc", value="C10000")
        assert decoded["code"] == "U0100"
        # the tool also accepts the human-readable form directly
        assert (await call("uds_decode_dtc", value="U0100"))["code"] == "U0100"
        assert (await call("uds_raw", data_hex="22F190"))["response"].startswith("62F190")
        assert (await call("uds_raw", data_hex="22DEAD"))["nrc"] == "requestOutOfRange"
        assert (await call("uds_clear_dtcs"))["remaining"] == 0

    asyncio.run(scenario())
