from vehsec import seedkey


def test_training_rotate_known_vector():
    # seed 0x01,0x02 -> rotl1 then xor 0x5A -> 0x58,0x5E
    assert seedkey.solve("training_rotate", bytes.fromhex("0102")).hex() == "585e"


def test_training_add_known_vector():
    assert seedkey.solve("training_add", bytes.fromhex("0102")).hex() == "1213"


def test_reflect_is_invertible_structure():
    key = seedkey.solve("training_reflect", bytes.fromhex("0102"))
    assert isinstance(key, bytes) and len(key) == 2


def test_unknown_vendor_raises():
    import pytest

    with pytest.raises(KeyError):
        seedkey.solve("definitely_not_a_vendor", b"\x00")


def test_register_custom_algorithm():
    seedkey.register("pytest_custom", lambda s: bytes(b ^ 0xFF for b in s))
    assert seedkey.solve("pytest_custom", b"\x00\x01") == b"\xff\xfe"
    assert "pytest_custom" in seedkey.known_vendors()
