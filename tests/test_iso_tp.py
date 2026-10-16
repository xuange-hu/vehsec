import pytest

from vehsec import iso_tp


# --- single frame ----------------------------------------------------------- #
def test_single_frame_roundtrip():
    payload = bytes.fromhex("22F190")
    frame = iso_tp.encode_single_frame(payload)
    assert frame.hex().upper() == "0322F190"
    d = iso_tp.decode(frame)
    assert d["type"] == "SF" and d["length"] == 3 and d["data"] == payload


def test_single_frame_max_is_seven_bytes():
    assert iso_tp.decode(iso_tp.encode_single_frame(bytes(7)))["length"] == 7
    with pytest.raises(ValueError):
        iso_tp.encode_single_frame(bytes(8))


def test_segment_short_payload_uses_single_frame():
    frames = iso_tp.segment(bytes.fromhex("22F190"))
    assert len(frames) == 1
    assert iso_tp.decode(frames[0])["type"] == "SF"


# --- first frame / multi frame ---------------------------------------------- #
def test_first_frame_carries_twelve_bit_length():
    payload = bytes(range(20))
    ff = iso_tp.encode_first_frame(payload)
    assert ff[0] >> 4 == iso_tp.FF
    assert ff[1] == 20
    assert iso_tp.decode(ff)["total"] == 20
    assert iso_tp.decode(ff)["data"] == payload[:6]


def test_first_frame_rejects_small_and_oversized():
    with pytest.raises(ValueError):
        iso_tp.encode_first_frame(bytes(7))          # fits in SF
    with pytest.raises(ValueError):
        iso_tp.encode_first_frame(bytes(0x1000))     # > 12-bit length


def test_segment_twenty_bytes_is_ff_plus_two_cfs():
    frames = iso_tp.segment(bytes(range(20)))
    kinds = [iso_tp.decode(f)["type"] for f in frames]
    assert kinds == ["FF", "CF", "CF"]
    assert [iso_tp.decode(f)["seq"] for f in frames[1:]] == [1, 2]


def test_reassemble_roundtrip_various_sizes():
    for size in (8, 20, 64, 200, 1000):
        payload = bytes((i * 7) & 0xFF for i in range(size))
        assert iso_tp.reassemble(iso_tp.segment(payload)) == payload


def test_sequence_number_wraps_past_fifteen():
    payload = bytes(range(200))   # needs 28 CFs -> seq reaches 15 then wraps to 0
    frames = iso_tp.segment(payload)
    seqs = [iso_tp.decode(f)["seq"] for f in frames[1:]]
    assert 0 in seqs, "sequence must wrap 15 -> 0"
    assert seqs[:3] == [1, 2, 3]
    assert iso_tp.reassemble(frames) == payload


def test_reassemble_detects_sequence_mismatch():
    frames = iso_tp.segment(bytes(range(40)))
    # swap the first two consecutive frames -> sequence breaks
    frames[1], frames[2] = frames[2], frames[1]
    with pytest.raises(ValueError, match="sequence mismatch"):
        iso_tp.reassemble(frames)


def test_reassemble_detects_incomplete_transfer():
    frames = iso_tp.segment(bytes(range(40)))
    with pytest.raises(ValueError, match="incomplete"):
        iso_tp.reassemble(frames[:-1])


def test_reassemble_rejects_starting_with_cf():
    with pytest.raises(ValueError):
        iso_tp.reassemble([bytes([0x21, 0x00])])


def test_reassemble_empty():
    with pytest.raises(ValueError):
        iso_tp.reassemble([])


# --- flow control ----------------------------------------------------------- #
def test_flow_control_roundtrip():
    fc = iso_tp.encode_flow_control(iso_tp.FLOW_CONTINUE, block_size=8, st_min=10)
    d = iso_tp.decode(fc)
    assert d["type"] == "FC"
    assert d["flow_status"] == iso_tp.FLOW_CONTINUE
    assert d["block_size"] == 8 and d["st_min"] == 10


def test_flow_control_wait_and_overflow():
    for status in (iso_tp.FLOW_WAIT, iso_tp.FLOW_OVERFLOW):
        assert iso_tp.decode(iso_tp.encode_flow_control(status))["flow_status"] == status


# --- misc ------------------------------------------------------------------- #
def test_consecutive_frame_rejects_oversized_chunk():
    with pytest.raises(ValueError):
        iso_tp.encode_consecutive_frame(bytes(8), 1)


def test_decode_unknown_pci_type():
    with pytest.raises(ValueError):
        iso_tp.decode(bytes([0x40, 0x00]))   # PCI type 4 does not exist


def test_decode_empty_frame():
    with pytest.raises(ValueError):
        iso_tp.decode(b"")


def test_describe_returns_frame_hex():
    frames = iso_tp.segment(bytes(range(20)))
    d = iso_tp.describe(frames)
    assert len(d) == 3
    assert all("frame" in x and "type" in x for x in d)
