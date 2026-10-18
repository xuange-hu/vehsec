"""Tests for the ISO-TP ASCII visualisation."""

import pytest

from vehsec import iso_tp as tp


def _multi():
    return tp.segment(bytes(range(20)))


def test_explain_multi_frame_header():
    out = tp.explain(_multi())
    assert "20-byte payload" in out
    assert "3 classic CAN frame(s)" in out


def _rows(out):
    """The per-frame rows only (kind column is one of SF/FF/CF/FC)."""
    return [l for l in out.splitlines() if any(f" {k} " in l for k in ("SF", "FF", "CF", "FC"))]


def test_explain_shows_ff_then_cfs_with_sequence_numbers():
    rows = _rows(tp.explain(_multi()))
    assert len(rows) == 3
    assert " FF " in rows[0] and "total=20" in rows[0]
    assert " CF " in rows[1] and "seq=1" in rows[1]
    assert " CF " in rows[2] and "seq=2" in rows[2]


def test_explain_reports_byte_spans():
    out = tp.explain(_multi())
    assert "carries bytes 0..5" in out
    assert "carries bytes 6..12" in out
    assert "carries bytes 13..19" in out


def test_explain_prints_the_reassembled_payload():
    out = tp.explain(_multi())
    assert "reassembled payload" in out
    squashed = out.replace(" ", "").replace("\n", "")
    assert bytes(range(20)).hex().upper() in squashed
    assert "= 20 bytes" in out


def test_explain_single_frame():
    out = tp.explain(tp.segment(bytes.fromhex("22F190")))
    assert "SF" in out and "len=3" in out
    assert "22 F1 90" in out


def test_explain_flow_control_row():
    frames = [_multi()[0], tp.encode_flow_control(), *_multi()[1:]]
    out = tp.explain(frames)
    assert "FC" in out and "flow=CTS" in out
    # flow control carries no payload, so the total is still 20
    assert "= 20 bytes" in out


def test_explain_flow_control_wait_and_overflow_names():
    out = tp.explain([tp.encode_flow_control(tp.FLOW_WAIT, 3, 10)])
    assert "flow=WAIT" in out and "block=3" in out and "st_min=10" in out
    out = tp.explain([tp.encode_flow_control(tp.FLOW_OVERFLOW)])
    assert "flow=OVFL" in out


def test_explain_marks_incomplete_transfers():
    out = tp.explain(_multi()[:2])  # FF + one CF, 13 of 20 bytes
    assert "INCOMPLETE" in out
    assert "got 13 of 20 bytes" in out


def test_explain_pads_short_frames_to_can_width():
    # 19 bytes -> FF(6) + CF(7) + CF(6): the last frame is one byte short of 8
    out = tp.explain(tp.segment(bytes(range(19))))
    assert tp._PAD in out
    assert out.count(tp._PAD) == 1


def test_explain_payload_equals_explain_of_segment():
    data = bytes(range(30))
    assert tp.explain_payload(data) == tp.explain(tp.segment(data))


def test_explain_rejects_empty_input():
    with pytest.raises(ValueError, match="no frames"):
        tp.explain([])


def test_explain_handles_max_length_payload():
    data = bytes(tp.MAX_TOTAL)
    out = tp.explain_payload(data)
    assert f"{tp.MAX_TOTAL}-byte payload" in out
    assert f"= {tp.MAX_TOTAL} bytes" in out
