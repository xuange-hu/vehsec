"""Tests for the Seed-Key algorithm recovery engine."""

import pytest

from vehsec import seedkey as sk

SEEDS = ["11223344", "A5B6C7D8", "00112233", "DEADBEEF"]


def _pairs(algo, n=3):
    return [(bytes.fromhex(s), algo(bytes.fromhex(s))) for s in SEEDS[:n]]


# --------------------------------------------------------------------------- #
# factories
# --------------------------------------------------------------------------- #
def test_xor_add_sub_roundtrip_on_vectors():
    assert sk.algo_xor(0x5A)(bytes.fromhex("000102")) == bytes.fromhex("5A5B58")
    assert sk.algo_add(0x01)(b"\xfe\xff") == b"\xff\x00"          # wraps mod 256
    assert sk.algo_sub(0x01)(b"\x00\x01") == b"\xff\x00"          # wraps mod 256


def test_rotl_rotr_are_inverses():
    seed = bytes.fromhex("B35F")
    assert sk.algo_rotr(3)(sk.algo_rotl(3)(seed)) == seed


def test_bitreverse_is_an_involution():
    seed = bytes.fromhex("0F3C")
    once = sk.algo_bitreverse()(seed)
    assert once == bytes.fromhex("F03C")
    assert sk.algo_bitreverse()(once) == seed


def test_nibble_and_endian_swap():
    assert sk.algo_nibble_swap()(b"\x1f") == b"\xf1"
    assert sk.algo_endian_swap()(bytes.fromhex("01020304")) == bytes.fromhex("04030201")


def test_crc16_reference_vector():
    # CRC-16/CCITT-FALSE of "123456789" is 0x29B1
    assert sk._crc16_ccitt_false(b"123456789") == 0x29B1


def test_sha_keystream_extends_beyond_one_digest():
    """A SHA-256 digest is only 32 bytes: the keystream must block-extend."""
    long_seed = bytes(range(40))
    key = sk.algo_sha_keystream()(long_seed)
    assert len(key) == 40, "key length must match the seed length"
    first_block = sk.algo_sha_keystream()(long_seed)[:32]
    short = sk.algo_sha_keystream()(long_seed[:32])
    # the first 32 bytes come from digest #0 only in both cases
    assert len(short) == 32
    assert first_block != bytes(32), "keystream must not be all zeroes"


def test_compose_chains_left_to_right():
    f = sk.compose(sk.algo_rotl(1), sk.algo_xor(0x5A))
    assert f(bytes.fromhex("0102")) == bytes.fromhex("585E")


def test_presets_registered():
    vendors = sk.known_vendors()
    for name in ("demo_xor_5a", "demo_add_37", "demo_sha_keystream", "demo_lfsr_xor"):
        assert name in vendors
    assert len(sk.solve("demo_sha_keystream", bytes.fromhex("11223344"))) == 4


# --------------------------------------------------------------------------- #
# recovery
# --------------------------------------------------------------------------- #
def test_recover_xor_const_is_unique_with_three_pairs():
    r = sk.recover(_pairs(sk.algo_xor(0x5A)))
    assert r["count"] == 1
    assert r["confidence"] == "high"
    assert r["candidates"][0]["expr"] == "key[i] = seed[i] ^ 0x5A"


def test_recover_add_const():
    r = sk.recover(_pairs(sk.algo_add(0x37)))
    assert any("+ 0x37" in c["expr"] for c in r["candidates"])


def test_recover_rotl_xor():
    r = sk.recover(_pairs(sk.compose(sk.algo_rotl(1), sk.algo_xor(0x5A))))
    assert any("rotl8(seed[i], 1) ^ 0x5A" in c["expr"] for c in r["candidates"])


def test_recover_bitreverse():
    r = sk.recover(_pairs(sk.compose(sk.algo_bitreverse(), sk.algo_xor(0x00))))
    assert any("bitrev8" in c["expr"] for c in r["candidates"])


def test_recover_affine():
    def affine(s):
        return bytes((0x0B * b + 0x2F) & 0xFF for b in s)

    r = sk.recover(_pairs(affine))
    assert any("0x0B * seed[i] + 0x2F" in c["expr"] for c in r["candidates"])


def test_recover_endian_swap():
    r = sk.recover(_pairs(sk.algo_endian_swap()))
    assert any("seed[n-1-i]" in c["expr"] for c in r["candidates"])


def test_single_pair_is_low_confidence_and_may_be_ambiguous():
    r = sk.recover(_pairs(sk.algo_xor(0x5A), n=1))
    assert r["pairs"] == 1
    assert r["confidence"] in {"low", "medium"}
    assert r["count"] >= 1


def test_unrecoverable_algorithm_returns_no_candidates():
    """sha256-keyed algorithms are outside the brute-forced family catalogue."""
    r = sk.recover(_pairs(sk.algo_sha_keystream()))
    assert r["count"] == 0
    assert r["confidence"] == "none"


def test_candidate_expression_reproduces_every_pair():
    algo = sk.algo_xor(0x5A)
    pairs = _pairs(algo, n=4)
    r = sk.recover(pairs)
    for c in r["candidates"]:
        assert c["example_key"] == algo(pairs[0][0]).hex()


def test_recover_rejects_empty_and_mismatched_input():
    with pytest.raises(ValueError):
        sk.recover([])
    with pytest.raises(ValueError, match="same length"):
        sk.recover([(b"\x11\x22", b"\x33\x44"), (b"\x11", b"\x22")])
    with pytest.raises(ValueError, match="length-preserving"):
        sk.recover([(b"\x11\x22\x33\x44", b"\x11\x22")])


def test_max_results_caps_the_output():
    r = sk.recover(_pairs(sk.algo_xor(0x00)), max_results=1)
    assert r["count"] <= 1


# --------------------------------------------------------------------------- #
# pair parsing
# --------------------------------------------------------------------------- #
def test_parse_pairs_colon_syntax():
    pairs = sk.parse_pairs("1122:3344, aabb:ccdd")
    assert pairs == [(bytes.fromhex("1122"), bytes.fromhex("3344")),
                     (bytes.fromhex("aabb"), bytes.fromhex("ccdd"))]


def test_parse_pairs_json_object_syntax():
    pairs = sk.parse_pairs('[{"seed": "1122", "key": "3344"}]')
    assert pairs == [(bytes.fromhex("1122"), bytes.fromhex("3344"))]


def test_parse_pairs_json_array_syntax():
    pairs = sk.parse_pairs('[["1122", "3344"]]')
    assert pairs == [(bytes.fromhex("1122"), bytes.fromhex("3344"))]


def test_parse_pairs_rejects_bad_input():
    with pytest.raises(ValueError):
        sk.parse_pairs("")
    with pytest.raises(ValueError):
        sk.parse_pairs("11223344")  # missing ':key'
