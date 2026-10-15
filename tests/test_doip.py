import struct

import pytest

from vehsec import doip as dp


# --------------------------------------------------------------------------- #
# wire codec
# --------------------------------------------------------------------------- #
def test_header_is_eight_bytes_with_inverse_version():
    pkt = dp.build_packet(dp.PayloadType.VEHICLE_ID_REQUEST)
    assert len(pkt) == 8
    assert pkt[0] == dp.PROTOCOL_VERSION
    assert pkt[1] == dp.PROTOCOL_VERSION ^ 0xFF
    assert struct.unpack_from("!H", pkt, 2)[0] == dp.PayloadType.VEHICLE_ID_REQUEST
    assert struct.unpack_from("!I", pkt, 4)[0] == 0


def test_packet_roundtrip():
    payload = b"\xde\xad\xbe\xef"
    pkt = dp.build_packet(dp.PayloadType.DIAGNOSTIC_MESSAGE, payload)
    ptype, body = dp.parse_packet(pkt)
    assert ptype == dp.PayloadType.DIAGNOSTIC_MESSAGE
    assert body == payload


def test_bad_inverse_version_is_rejected():
    pkt = bytearray(dp.build_packet(dp.PayloadType.VEHICLE_ID_REQUEST))
    pkt[1] = 0x00
    with pytest.raises(dp.DoipError):
        dp.parse_packet(bytes(pkt))


def test_short_header_is_rejected():
    with pytest.raises(dp.DoipError):
        dp.parse_packet(b"\x02\xfd\x00")


def test_truncated_payload_is_rejected():
    pkt = dp.build_packet(dp.PayloadType.DIAGNOSTIC_MESSAGE, b"\x01\x02\x03")
    with pytest.raises(dp.DoipError):
        dp.parse_packet(pkt[:-1])


def test_negative_ack_raises():
    pkt = dp.build_packet(dp.PayloadType.NEGATIVE_ACK, bytes([dp.NackCode.UNKNOWN_PAYLOAD_TYPE]))
    with pytest.raises(dp.DoipError, match="negative ack"):
        dp.parse_packet(pkt)


# --------------------------------------------------------------------------- #
# vehicle announcement
# --------------------------------------------------------------------------- #
def test_vehicle_announcement_roundtrip():
    ann = dp.VehicleAnnouncement(
        vin="WVWZZZ1JZXW000001",
        logical_address=0x1000,
        eid=b"\x01\x02\x03\x04\x05\x06",
        gid=b"\xaa\xbb\xcc\xdd\xee\xff",
    )
    back = dp.VehicleAnnouncement.decode(ann.encode())
    assert back.vin == ann.vin
    assert back.logical_address == 0x1000
    assert back.eid == ann.eid
    assert back.gid == ann.gid


def test_announcement_payload_is_33_bytes():
    ann = dp.VehicleAnnouncement(vin="A" * 17, logical_address=1, eid=b"\x00" * 6, gid=b"\x00" * 6)
    assert len(ann.encode()) == 33


def test_short_vin_is_padded():
    ann = dp.VehicleAnnouncement(vin="SHORT", logical_address=1, eid=b"\x00" * 6, gid=b"\x00" * 6)
    assert dp.VehicleAnnouncement.decode(ann.encode()).vin == "SHORT"


def test_announcement_to_dict_is_json_safe():
    import json

    ann = dp.VehicleAnnouncement(vin="X" * 17, logical_address=0x2000, eid=b"\x01" * 6, gid=b"\x02" * 6)
    assert json.loads(json.dumps(ann.to_dict()))["logical_address"] == "0x2000"


def test_vehicle_identification_request_variants():
    assert len(dp.build_vehicle_identification_request()) == 8
    assert len(dp.build_vehicle_identification_request(vin="X" * 17)) == 25
    assert len(dp.build_vehicle_identification_request(eid=b"\x01" * 6)) == 14


# --------------------------------------------------------------------------- #
# routing activation
# --------------------------------------------------------------------------- #
def test_routing_activation_request_layout():
    pkt = dp.build_routing_activation_request(0x0E00)
    _, payload = dp.parse_packet(pkt)
    assert struct.unpack_from("!H", payload, 0)[0] == 0x0E00
    assert payload[2] == 0x00  # default activation type
    assert len(payload) == 11  # 2 addr + 1 type + 4 reserved + 4 vm-specific


def test_routing_activation_response_success():
    payload = struct.pack("!HH", 0x0E00, 0x1000) + bytes([0x10]) + b"\x00" * 8
    result = dp.parse_routing_activation_response(payload)
    assert result["activated"] is True
    assert result["name"] == "SUCCESS"
    assert result["entity_logical_address"] == "0x1000"


def test_routing_activation_response_rejected():
    payload = struct.pack("!HH", 0x0E00, 0x1000) + bytes([0x17]) + b"\x00" * 8
    result = dp.parse_routing_activation_response(payload)
    assert result["activated"] is False
    assert result["name"] == "UNSUPPORTED_ACTIVATION_TYPE"


def test_routing_activation_response_too_short():
    with pytest.raises(dp.DoipError):
        dp.parse_routing_activation_response(b"\x00\x01")


# --------------------------------------------------------------------------- #
# diagnostic message
# --------------------------------------------------------------------------- #
def test_diagnostic_message_roundtrip():
    pkt = dp.build_diagnostic_message(0x0E00, 0x1000, bytes.fromhex("22F190"))
    _, payload = dp.parse_packet(pkt)
    src, dst, uds = dp.parse_diagnostic_message(payload)
    assert (src, dst) == (0x0E00, 0x1000)
    assert uds == bytes.fromhex("22F190")


def test_diagnostic_message_too_short():
    with pytest.raises(dp.DoipError):
        dp.parse_diagnostic_message(b"\x0e")


# --------------------------------------------------------------------------- #
# simulator end-to-end
# --------------------------------------------------------------------------- #
def test_simulator_discovery_over_udp():
    with dp.DoipSimulator(vin="TESTVIN0000000001") as sim:
        found = dp.discover(host=sim.host, port=sim.udp_port, timeout=2.0)
    assert [a.vin for a in found] == ["TESTVIN0000000001"]
    assert found[0].logical_address == sim.logical_address


def test_simulator_routing_activation():
    with dp.DoipSimulator() as sim:
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=3.0) as client:
            result = client.routing_activation()
    assert result["activated"] is True
    assert result["entity_logical_address"] == f"0x{sim.logical_address:04X}"


def test_simulator_uds_read_vin_over_doip():
    with dp.DoipSimulator(vin="WVWZZZ1JZXW000042") as sim:
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=3.0) as client:
            client.routing_activation()
            response = client.request(sim.logical_address, bytes.fromhex("22F190"))
    assert response[:3] == bytes.fromhex("62F190")
    assert response[3:].decode("ascii") == "WVWZZZ1JZXW000042"


def test_simulator_uds_session_control():
    with dp.DoipSimulator() as sim:
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=3.0) as client:
            client.routing_activation()
            response = client.request(sim.logical_address, bytes.fromhex("1003"))
    assert response[0] == 0x50


def test_simulator_negative_response_for_unknown_service():
    with dp.DoipSimulator() as sim:
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=3.0) as client:
            client.routing_activation()
            response = client.request(sim.logical_address, bytes.fromhex("31FF"))
    assert response == bytes([0x7F, 0x31, 0x11])


def test_client_requires_connection():
    client = dp.DoipClient("127.0.0.1", 1)
    with pytest.raises(dp.DoipError):
        client.routing_activation()


def test_multiple_sequential_requests_on_one_socket():
    with dp.DoipSimulator() as sim:
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=3.0) as client:
            client.routing_activation()
            for req, expected in ((b"\x10\x03", 0x50), (b"\x3e\x00", 0x7E)):
                assert client.request(sim.logical_address, req)[0] == expected
