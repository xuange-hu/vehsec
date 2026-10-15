import hashlib
import os

import pytest

pytest.importorskip("ecdsa", reason="ecdsa is required for v2x tests")

from ecdsa import SECP256k1, SigningKey  # noqa: E402
from ecdsa.util import sigencode_string  # noqa: E402

from vehsec import v2x  # noqa: E402


def _sign(sk, msg: bytes, k=None):
    sig = sk.sign(msg, k=k, hashfunc=hashlib.sha256, sigencode=sigencode_string)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    n = SECP256k1.order
    if z.bit_length() > n.bit_length():
        z >>= z.bit_length() - n.bit_length()
    return v2x.Signature(r, s, z)


def test_nonce_reuse_recovers_private_key():
    sk = SigningKey.generate(curve=SECP256k1)
    priv = sk.privkey.secret_multiplier
    k = int.from_bytes(os.urandom(32), "big") % SECP256k1.order
    a = _sign(sk, b"msg-a", k=k)
    b = _sign(sk, b"msg-b", k=k)
    assert a.r == b.r, "same k must produce the same r"
    d = v2x.recover_private_key(a, b)
    assert d == priv


def test_detect_nonce_reuse_finds_pair():
    sk = SigningKey.generate(curve=SECP256k1)
    priv = sk.privkey.secret_multiplier
    k = int.from_bytes(os.urandom(32), "big") % SECP256k1.order
    sigs = [_sign(sk, b"m0", k=k), _sign(sk, b"m1", k=k)]
    sigs += [_sign(sk, f"m{i}".encode()) for i in range(2, 6)]
    findings = v2x.detect_nonce_reuse(sigs)
    assert findings, "nonce reuse should be detected"
    assert all(d == priv for _, _, d in findings)


def test_no_false_positive_on_unique_nonces():
    sk = SigningKey.generate(curve=SECP256k1)
    sigs = [_sign(sk, f"m{i}".encode()) for i in range(8)]
    assert v2x.detect_nonce_reuse(sigs) == []
