"""Tests for the UDS client and the virtual ECU.

The module had no tests and was quietly broken by two upstream renames
(``udsoncan.connection`` -> ``connections``, and can-isotp 2.x replacing
``TransportLayer(bus, address)`` with ``CanStack``). These tests pin both the
pure service dispatch and a full round trip over a virtual CAN bus.
"""

import pytest

from vehsec import iso_tp, uds

VIN = b"WVWZZZ1JZXW000001"


# --- virtual ECU: pure service dispatch ------------------------------------ #
def test_read_did_returns_positive_response_with_vin():
    ecu = uds.VirtualEcu()
    resp = ecu.handle(bytes.fromhex("22F190"))
    assert resp[0] == 0x62                  # positive response to service 0x22
    assert resp[1:3] == bytes.fromhex("F190")
    assert resp[3:] == VIN


def test_read_did_negative_for_unknown_did():
    ecu = uds.VirtualEcu()
    resp = ecu.handle(bytes.fromhex("22F199"))
    assert resp == bytes([0x7F, 0x22, 0x31])    # requestOutOfRange


def test_write_did_then_read_returns_written_value():
    ecu = uds.VirtualEcu()
    ecu.handle(bytes.fromhex("2EF190") + b"HELLO")
    assert ecu.handle(bytes.fromhex("22F190")) == bytes.fromhex("62F190") + b"HELLO"


def test_security_access_seed_then_correct_key():
    ecu = uds.VirtualEcu()
    seed_resp = ecu.handle(bytes.fromhex("2701"))
    assert seed_resp[0] == 0x67 and seed_resp[1] == 0x01
    seed = seed_resp[2:]

    from vehsec import seedkey

    key = seedkey.solve("training_rotate", seed)
    assert ecu.handle(bytes([0x27, 0x02]) + bytes(key))[0] == 0x67
    assert ecu.unlocked is True


def test_security_access_rejects_wrong_key():
    ecu = uds.VirtualEcu()
    ecu.handle(bytes.fromhex("2701"))
    resp = ecu.handle(bytes.fromhex("27") + b"\x02" + bytes(4))
    assert resp == bytes([0x7F, 0x27, 0x35])    # invalidKey
    assert ecu.unlocked is False


def test_unsupported_service_gets_service_not_supported():
    ecu = uds.VirtualEcu()
    assert ecu.handle(bytes.fromhex("AA")) == bytes([0x7F, 0xAA, 0x11])


def test_tester_present_and_session():
    ecu = uds.VirtualEcu()
    assert ecu.handle(bytes.fromhex("3E00")) == bytes([0x7E, 0x00])
    session = ecu.handle(bytes.fromhex("1003"))
    assert session[0] == 0x50 and session[1] == 0x03


def test_ecu_reset_and_routine():
    ecu = uds.VirtualEcu()
    assert ecu.handle(bytes.fromhex("1101")) == bytes([0x51, 0x01])
    assert ecu.handle(bytes.fromhex("31010203")) == bytes([0x71, 0x01, 0x02, 0x03])


def test_vin_response_is_multiframe_over_classic_can():
    """17-byte VIN + echo does not fit in one frame: forces FF + CFs."""
    payload = bytes([0x62, 0xF1, 0x90]) + VIN
    frames = iso_tp.segment(payload)
    assert len(frames) > 1
    assert iso_tp.decode(frames[0])["type"] == "FF"
    assert iso_tp.reassemble(frames) == payload


def test_virtual_ecu_default_dids():
    ecu = uds.VirtualEcu()
    assert ecu.did_data[0xF190] == VIN
    assert ecu.did_data[0xF187] == b"3Q0907115"


# --- helpers ---------------------------------------------------------------- #
def test_stmin_conversion():
    assert abs(uds._stmin_seconds(0x0A) - 0.010) < 1e-9     # 10 ms
    assert abs(uds._stmin_seconds(0xF1) - 0.0001) < 1e-9    # 100 us
    assert uds._stmin_seconds(0x00) == 0.0


def test_default_config_is_mutable_copy():
    cfg = uds.default_config()
    assert "request_timeout" in cfg
    cfg["request_timeout"] = 999
    assert uds.default_config()["request_timeout"] != 999


# --- end-to-end over a virtual CAN bus ------------------------------------- #
pytest.importorskip("isotp", reason="can-isotp is required for UDS round trips")
pytest.importorskip("udsoncan", reason="udsoncan is required for UDS round trips")


def _client(**kwargs):
    kwargs.setdefault("channel", "test-uds")
    return uds.UdsClient(**kwargs)


def test_read_vin_end_to_end():
    with _client() as c:
        result = c.read_did(0xF190)
    assert result["did"] == "0xF190"
    assert result["value"] == VIN.hex()
    assert result["ascii"] == "WVWZZZ1JZXW000001"


def test_write_then_read_end_to_end():
    with _client() as c:
        c.write_did(0xF190, b"TESTING")
        assert c.read_did(0xF190)["ascii"] == "TESTING"


def test_security_access_end_to_end():
    with _client() as c:
        result = c.security_access(level=1, vendor="training_rotate")
    assert result["unlocked"] is True
    assert result["seed"] == "01020304"
    assert len(bytes.fromhex(result["key"])) >= 2


def test_diagnostic_session_end_to_end():
    with _client() as c:
        assert c.session(3)["session"] == 3


def test_ecu_reset_end_to_end():
    with _client() as c:
        assert c.ecu_reset(1)["status"] == "ok"


def test_unknown_did_raises_uds_error():
    with _client() as c:
        with pytest.raises(uds.UdsError):
            c.read_did(0xDEAD)
