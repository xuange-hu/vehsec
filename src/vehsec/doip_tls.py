"""DoIP over TLS — ISO 13400-2 secure diagnostics, and the crypto behind it.

ISO 13400-2:2019 added a **TLS-protected** variant of DoIP: same 8-byte
header, same payload types, but wrapped in TLS. It normally listens on
**TCP 3496** while the plaintext variant keeps TCP 13400. Three things make
this worth auditing rather than just using:

1. **A lot of gateways still answer plaintext 13400.** If the plaintext port
   accepts a routing activation, the TLS port is theatre — an attacker just
   skips it.
2. **The certificates are usually junk.** Self-signed, 1024-bit RSA, SHA-1,
   expired in 2019, CN holding a bare IP address, no subjectAltName. Modern
   TLS clients reject those, so bench tools are shipped with verification
   switched off — and that habit follows them into the field.
3. **Old TLS versions linger.** Bench stacks and aftermarket gateways happily
   negotiate TLS 1.0 / 1.1, which ISO 13400-2 does not permit.

This module is two halves:

* **A zero-dependency X.509 reader** (:func:`parse_certificate`) — a minimal
  DER parser, deliberately written with the standard library only, the same
  way :mod:`vehsec.dbc` parses DBC without a third-party package. It also
  verifies **RSA PKCS#1 v1.5 signatures in pure Python** (:func:`verify_signature`),
  so "self-signed" is proven, not guessed from a subject==issuer string compare.
* **An audit engine** (:func:`audit_certificate`, :func:`probe_tls`,
  :func:`audit_endpoint`) that turns a certificate or a live gateway into a
  severity-graded report.

Only the optional helpers that must *create* key material (:func:`make_self_signed`)
need ``cryptography``; parsing and auditing never do.

Bench/lab equipment and authorized targets only.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import ipaddress
import re
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "DOIP_TLS_PORT",
    "DOIP_PORT",
    "MIN_TLS_VERSION",
    "SEVERITIES",
    "CertError",
    "Certificate",
    "parse_certificate",
    "load_certificate",
    "verify_signature",
    "verify_signed_by",
    "audit_certificate",
    "format_report",
    "TlsProbe",
    "probe_tls",
    "audit_endpoint",
    "make_self_signed",
]

DOIP_PORT = 13400
DOIP_TLS_PORT = 3496
#: ISO 13400-2 requires TLS 1.2 or newer; TLS 1.0/1.1 are deprecated everywhere.
MIN_TLS_VERSION = "TLSv1.2"

SEVERITIES = ("critical", "high", "medium", "low", "info")
_PENALTY = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}


class CertError(ValueError):
    """Raised when a byte string is not a certificate we can parse."""


# --------------------------------------------------------------------------- #
# minimal DER reader
# --------------------------------------------------------------------------- #
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31

# printable / utf8 / t61 / ia5 / bmp / universal string
_TEXT_TAGS = (0x0C, 0x13, 0x14, 0x16, 0x1E, 0x1C)
_UTC_TIME = 0x17
_GENERALIZED_TIME = 0x18


def _tlv(buf: bytes, pos: int) -> Tuple[int, int, int, int]:
    """Read one TLV. Returns ``(tag, value_start, value_end, next_pos)``."""
    if pos >= len(buf):
        raise CertError("truncated DER: expected a tag")
    tag = buf[pos]
    pos += 1
    if tag & 0x1F == 0x1F:  # high-tag-number form (context tags like [0]/[3])
        while pos < len(buf) and buf[pos] & 0x80:
            pos += 1
        pos += 1
    if pos >= len(buf):
        raise CertError("truncated DER: expected a length")
    first = buf[pos]
    pos += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise CertError("indefinite-length encoding is not valid in X.509")
        if pos + count > len(buf):
            raise CertError("truncated DER: short length field")
        length = int.from_bytes(buf[pos : pos + count], "big")
        pos += count
    else:
        length = first
    end = pos + length
    if end > len(buf):
        raise CertError(f"truncated DER: element claims {length} bytes")
    return tag, pos, end, end


def _iter_tlv(buf: bytes, start: int, end: int) -> Iterable[Tuple[int, int, int]]:
    """Iterate the TLVs inside ``buf[start:end]`` as ``(tag, vstart, vend)``."""
    pos = start
    while pos < end:
        tag, vs, ve, nxt = _tlv(buf, pos)
        if nxt > end:
            raise CertError("truncated DER: element overruns its parent")
        yield tag, vs, ve
        pos = nxt


def _first(buf: bytes, start: int, end: int, tag: int) -> Tuple[int, int]:
    """Return the value span of the first child with ``tag``."""
    for ctag, vs, ve in _iter_tlv(buf, start, end):
        if ctag == tag:
            return vs, ve
    raise CertError(f"DER element 0x{tag:02X} not found")


def _seq(buf: bytes, start: int, end: int) -> Tuple[int, int]:
    return _first(buf, start, end, _TAG_SEQUENCE)


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _decode_text(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString is UTF-16BE
        try:
            return raw.decode("utf-16-be")
        except UnicodeDecodeError:
            return raw.hex()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _der(tag: int, value: bytes) -> bytes:
    """Minimal DER encoder — only used for building the padding we compare against."""
    length = len(value)
    if length < 0x80:
        head = bytes([tag, length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(raw)]) + raw
    return head + value


# --------------------------------------------------------------------------- #
# well-known OIDs
# --------------------------------------------------------------------------- #
_ATTR_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
}

_SIGALG = {
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "md5"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "sha1"),
    "1.2.840.113549.1.1.10": ("rsassaPss", "?"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "sha256"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "sha384"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "sha512"),
    "1.2.840.113549.1.1.14": ("sha224WithRSAEncryption", "sha224"),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "sha1"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "sha512"),
    "1.3.101.112": ("Ed25519", "ed25519"),
    "1.3.101.113": ("Ed448", "ed448"),
}

_HASH_OID = {
    "md5": "1.2.840.113549.2.5",
    "sha1": "1.3.14.3.2.26",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}

def _encode_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def _digest_info(hash_name: str, digest: bytes) -> bytes:
    """PKCS#1 v1.5 ``DigestInfo`` — built from the OIDs above, never hand-typed."""
    oid = _encode_oid(_HASH_OID[hash_name])
    alg = _der(_TAG_SEQUENCE, _der(_TAG_OID, oid) + _der(0x05, b""))  # NULL params
    return _der(_TAG_SEQUENCE, alg + _der(_TAG_OCTET_STRING, digest))

# public key algorithms
_PK_RSA = "1.2.840.113549.1.1.1"
_PK_EC = "1.2.840.10045.2.1"
_PK_ED25519 = "1.3.101.112"
_PK_ED448 = "1.3.101.113"

_EC_CURVE_BITS = {
    "1.2.840.10045.3.1.7": (256, "prime256v1"),
    "1.3.132.0.10": (256, "secp256k1"),
    "1.3.132.0.33": (224, "secp224r1"),
    "1.3.132.0.34": (384, "secp384r1"),
    "1.3.132.0.35": (521, "secp521r1"),
    "1.3.36.3.3.2.8.1.1.7": (256, "brainpoolP256r1"),
    "1.3.36.3.3.2.8.1.1.11": (384, "brainpoolP384r1"),
}

# extensions
_EXT_SAN = "2.5.29.17"
_EXT_BASIC_CONSTRAINTS = "2.5.29.19"
_EXT_KEY_USAGE = "2.5.29.15"
_EXT_EXT_KEY_USAGE = "2.5.29.37"

_KEY_USAGE_BITS = (
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
)

_EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}


# --------------------------------------------------------------------------- #
# certificate model
# --------------------------------------------------------------------------- #
@dataclass
class Certificate:
    """The subset of X.509 we need, decoded from DER with no dependencies."""

    subject: str
    issuer: str
    subject_dict: Dict[str, str]
    issuer_dict: Dict[str, str]
    serial: int
    not_before: _dt.datetime
    not_after: _dt.datetime
    signature_algorithm: str
    signature_hash: str
    public_key_algorithm: str
    public_key_bits: int
    public_key_curve: Optional[str]
    is_ca: bool
    key_usage: List[str]
    extended_key_usage: List[str]
    san_dns: List[str]
    san_ip: List[str]
    san_email: List[str]
    has_san: bool
    self_signed: bool
    signature_valid: Optional[bool]
    der: bytes = field(repr=False, default=b"")
    #: raw ``tbsCertificate`` bytes — kept so :func:`verify_signed_by` can check
    #: the signature against an issuer certificate later.
    tbs: bytes = field(repr=False, default=b"")
    signature: bytes = field(repr=False, default=b"")
    #: DER ``RSAPublicKey`` of the subject — what an issuer signature is checked
    #: against by :func:`verify_signed_by`.
    public_key_der: bytes = field(repr=False, default=b"")

    @property
    def common_name(self) -> str:
        return self.subject_dict.get("CN", "")

    @property
    def validity_days(self) -> int:
        return int((self.not_after - self.not_before).total_seconds() // 86400)

    def days_remaining(self, now: Optional[_dt.datetime] = None) -> int:
        now = now or _dt.datetime.now(_dt.timezone.utc)
        return int((self.not_after - now).total_seconds() // 86400)

    def matches_hostname(self, hostname: str) -> bool:
        """Wildcard-aware SAN/CN match, like a TLS client performs (RFC 6125)."""
        return _matches_hostname(hostname, self.san_dns, self.common_name)

    def to_dict(self) -> Dict[str, object]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "common_name": self.common_name,
            "serial": f"{self.serial:X}",
            "valid_from": self.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": self.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "validity_days": self.validity_days,
            "signature_algorithm": self.signature_algorithm,
            "public_key": {
                "algorithm": self.public_key_algorithm,
                "bits": self.public_key_bits,
                "curve": self.public_key_curve,
            },
            "is_ca": self.is_ca,
            "key_usage": self.key_usage,
            "extended_key_usage": self.extended_key_usage,
            "subject_alt_name": {
                "dns": self.san_dns,
                "ip": self.san_ip,
                "email": self.san_email,
                "present": self.has_san,
            },
            "self_signed": self.self_signed,
            "signature_verified": self.signature_valid,
            "sha256_fingerprint": hashlib.sha256(self.der).hexdigest(),
        }


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def _der_from_any(data: bytes) -> bytes:
    """Accept DER, PEM, or a PEM pasted into a text file (banners optional)."""
    if b"-----BEGIN" in data:
        body = []
        for line in data.decode("ascii", "ignore").splitlines():
            line = line.strip()
            if line.startswith("-----") or not line:
                continue
            body.append(line)
        try:
            return base64.b64decode("".join(body))
        except (binascii.Error, ValueError) as exc:
            raise CertError(f"cannot base64-decode the PEM block: {exc}") from exc
    if data[:1] == b"\x30":
        return bytes(data)
    # last resort: maybe it is bare base64 with no banners
    stripped = bytes(data).strip()
    if re.fullmatch(rb"[A-Za-z0-9+/=\s]+", stripped):
        try:
            decoded = base64.b64decode(stripped)
        except (binascii.Error, ValueError):
            raise CertError("input is neither DER nor base64/PEM")
        if decoded[:1] == b"\x30":
            return decoded
    raise CertError("input is not a DER or PEM certificate")


def _parse_name(buf: bytes, start: int, end: int) -> Tuple[str, Dict[str, str]]:
    """Parse an X.501 Name into ``(rfc4514-ish string, {key: value})``."""
    parts: List[str] = []
    mapping: Dict[str, str] = {}
    for _tag, vs, ve in _iter_tlv(buf, start, end):  # RDNSequence -> SETs
        if _tag != _TAG_SET:
            continue
        for _, avs, ave in _iter_tlv(buf, vs, ve):  # SET -> AttributeTypeAndValue
            oid_vs, oid_ve = _first(buf, avs, ave, _TAG_OID)
            oid = _decode_oid(buf[oid_vs:oid_ve])
            for vtag, vvs, vve in _iter_tlv(buf, oid_ve, ave):
                if vtag in _TEXT_TAGS:
                    value = _decode_text(vtag, buf[vvs:vve])
                    break
            else:
                continue
            short = _ATTR_NAMES.get(oid, oid)
            parts.append(f"{short}={value}")
            mapping[short] = value
    return "/" + "/".join(parts), mapping


def _parse_time(tag: int, raw: bytes) -> _dt.datetime:
    text = raw.decode("ascii", "ignore").strip()
    try:
        if tag == _UTC_TIME:
            # YYMMDDHHMMSSZ (or with an offset); two-digit year -> 1950..2049
            if len(text) < 10:
                raise ValueError("short UTCTime")
            year = int(text[0:2])
            year += 1900 if year >= 50 else 2000
            return _dt.datetime(
                year, int(text[2:4]), int(text[4:6]),
                int(text[6:8]), int(text[8:10]),
                int(text[10:12]) if len(text) >= 12 and text[10:12].isdigit() else 0,
                tzinfo=_dt.timezone.utc,
            )
        # GeneralizedTime: YYYYMMDDHHMMSSZ
        seconds = int(text[12:14]) if len(text) >= 14 and text[12:14].isdigit() else 0
        return _dt.datetime(
            int(text[0:4]), int(text[4:6]), int(text[6:8]),
            int(text[8:10]), int(text[10:12]), seconds, tzinfo=_dt.timezone.utc,
        )
    except (ValueError, IndexError) as exc:
        raise CertError(f"unparsable certificate time {text!r}") from exc


def _parse_validity(buf: bytes, start: int, end: int) -> Tuple[_dt.datetime, _dt.datetime]:
    """``[start, end)`` spans the Validity SEQUENCE itself, holding two Times."""
    times: List[_dt.datetime] = []
    for tag, tvs, tve in _iter_tlv(buf, start, end):
        if tag in (_UTC_TIME, _GENERALIZED_TIME):
            times.append(_parse_time(tag, buf[tvs:tve]))
    if len(times) != 2:
        raise CertError("validity must hold exactly two times")
    return times[0], times[1]


def _parse_spki(
    buf: bytes, start: int, end: int
) -> Tuple[str, int, Optional[str], Tuple[int, int]]:
    """Parse SubjectPublicKeyInfo.

    ``[start, end)`` spans the SPKI SEQUENCE. Returns
    ``(algorithm, bits, curve, raw_public_key_span)``; the span covers the DER
    ``RSAPublicKey`` so an RSA signature can be verified later.
    """
    children = list(_iter_tlv(buf, start, end))
    if len(children) < 2 or children[0][0] != _TAG_SEQUENCE:
        raise CertError("subjectPublicKeyInfo is missing its AlgorithmIdentifier")

    avs, ave = children[0][1], children[0][2]
    ovs, ove = _first(buf, avs, ave, _TAG_OID)
    alg = _decode_oid(buf[ovs:ove])

    # the BIT STRING is a sibling of the AlgorithmIdentifier, not a child of it
    key_span = (0, 0)
    for tag, bvs, bve in children[1:]:
        if tag == _TAG_BIT_STRING:
            key_span = (bvs + 1, bve)  # skip the unused-bits octet
            break

    if alg == _PK_RSA:
        inner = buf[key_span[0] : key_span[1]]
        try:
            ivs, ive = _seq(inner, 0, len(inner))
            mvs, mve = _first(inner, ivs, ive, _TAG_INTEGER)
        except CertError as exc:
            raise CertError("RSA public key has no modulus") from exc
        return "RSA", _rsa_bits(int.from_bytes(inner[mvs:mve], "big")), None, key_span

    if alg == _PK_EC:
        curve_oid = ""
        for tag, pvs, pve in _iter_tlv(buf, ove, ave):
            if tag == _TAG_OID:
                curve_oid = _decode_oid(buf[pvs:pve])
                break
        bits, curve = _EC_CURVE_BITS.get(curve_oid, (0, curve_oid or None))
        if bits == 0:
            # unknown curve: fall back to the uncompressed EC point size
            bits = max(0, (key_span[1] - key_span[0] - 1) // 2) * 8
        return "EC", bits, curve, key_span

    if alg == _PK_ED25519:
        return "Ed25519", 256, None, key_span
    if alg == _PK_ED448:
        return "Ed448", 448, None, key_span

    return alg, 0, None, key_span


def _rsa_bits(modulus: int) -> int:
    """Real modulus size in bits, rounded up to the usual 512/1024/2048/4096."""
    if modulus == 0:
        return 0
    bits = modulus.bit_length()
    for step in (256, 512, 1024, 2048, 3072, 4096):
        if bits <= step:
            return step
    return (bits + 255) // 256 * 256


def _parse_extensions(buf: bytes, start: int, end: int) -> Dict[str, Tuple[bool, int, int]]:
    """Return ``{oid: (critical, vstart, vend)}`` for the extensions block."""
    out: Dict[str, Tuple[bool, int, int]] = {}
    vs, ve = _seq(buf, start, end)  # Extensions is SEQUENCE OF Extension
    for _, evs, eve in _iter_tlv(buf, vs, ve):
        ovs, ove = _first(buf, evs, eve, _TAG_OID)
        oid = _decode_oid(buf[ovs:ove])
        critical = False
        cursor = ove
        # optional BOOLEAN DEFAULT FALSE comes before the value
        for tag, bvs, bve in _iter_tlv(buf, ove, eve):
            if tag == 0x01:
                critical = buf[bvs] != 0x00
                cursor = bve
                break
            break
        for tag, vvs, vve in _iter_tlv(buf, cursor, eve):
            if tag == _TAG_OCTET_STRING:
                out[oid] = (critical, vvs, vve)
                break
    return out


def _parse_san(buf: bytes, start: int, end: int) -> Tuple[List[str], List[str], List[str]]:
    dns: List[str] = []
    ips: List[str] = []
    emails: List[str] = []
    vs, ve = _seq(buf, start, end)  # GeneralNames
    for tag, gvs, gve in _iter_tlv(buf, vs, ve):
        raw = buf[gvs:gve]
        if tag == 0x82:  # dNSName
            dns.append(raw.decode("ascii", "replace"))
        elif tag == 0x87:  # iPAddress (4 or 16 bytes)
            try:
                ips.append(str(ipaddress.ip_address(raw)))
            except ValueError:
                ips.append(raw.hex())
        elif tag == 0x81:  # rfc822Name
            emails.append(raw.decode("ascii", "replace"))
    return dns, ips, emails


def _parse_key_usage(buf: bytes, start: int, end: int) -> List[str]:
    vs, ve = _first(buf, start, end, _TAG_BIT_STRING)
    if ve - vs < 2:
        return []
    unused = buf[vs]
    bits: List[str] = []
    for index in range((ve - vs - 1) * 8 - unused):
        byte = buf[vs + 1 + index // 8]
        if byte & (0x80 >> (index % 8)):
            bits.append(_KEY_USAGE_BITS[index])
    return bits


def _parse_eku(buf: bytes, start: int, end: int) -> List[str]:
    vs, ve = _seq(buf, start, end)
    names: List[str] = []
    for _, ovs, ove in _iter_tlv(buf, vs, ve):
        oid = _decode_oid(buf[ovs:ove])
        names.append(_EKU_NAMES.get(oid, oid))
    return names


def parse_certificate(data: bytes) -> Certificate:
    """Parse one X.509 certificate from DER or PEM.

    Raises :class:`CertError` on anything we cannot read. This is the
    dependency-free core of the module: no ``cryptography``, no ``asn1crypto``.
    """
    der = _der_from_any(bytes(data))
    try:
        outer_vs, outer_ve = _tlv(der, 0)[1:3]
        tbs_vs, tbs_ve = _seq(der, outer_vs, outer_ve)
    except (CertError, IndexError) as exc:
        raise CertError(f"not a DER SEQUENCE: {exc}") from exc
    # The signature covers the *whole* tbsCertificate element — header included.
    # tbsCertificate is the first child of the outer SEQUENCE, so it starts at
    # outer_vs and ends at tbs_ve; hashing der[tbs_vs:tbs_ve] would skip the
    # tag and length and make every signature look invalid.
    tbs = der[outer_vs:tbs_ve]

    # --- tbsCertificate children, in the order the ASN.1 module defines them
    version = 1
    serial = 0
    sig_alg_oid = ""
    issuer = ("", {})
    validity: Optional[Tuple[_dt.datetime, _dt.datetime]] = None
    subject = ("", {})
    spki = ("?", 0, None, (0, 0))
    extensions: Dict[str, Tuple[bool, int, int]] = {}

    pending: List[Tuple[int, int, int]] = list(_iter_tlv(der, tbs_vs, tbs_ve))
    index = 0
    # optional [0] EXPLICIT version
    if pending and pending[0][0] == 0xA0:
        _, vs, ve = pending[0]
        for tag, ivs, ive in _iter_tlv(der, vs, ve):
            if tag == _TAG_INTEGER:
                version = int.from_bytes(der[ivs:ive], "big") + 1
        index = 1

    # after the optional version the fixed fields are always present in order
    ordered = [item for item in pending[index:] if item[0] != 0xA1 and item[0] != 0xA2]
    if len(ordered) < 7:
        raise CertError("tbsCertificate is missing required fields")
    if ordered[0][0] == _TAG_INTEGER:
        serial = int.from_bytes(der[ordered[0][1] : ordered[0][2]], "big")
    for child_tag, avs, ave in _iter_tlv(der, ordered[1][1], ordered[1][2]):
        if child_tag == _TAG_OID:
            sig_alg_oid = _decode_oid(der[avs:ave])
            break
    issuer = _parse_name(der, ordered[2][1], ordered[2][2])
    validity = _parse_validity(der, ordered[3][1], ordered[3][2])
    subject = _parse_name(der, ordered[4][1], ordered[4][2])
    spki = _parse_spki(der, ordered[5][1], ordered[5][2])
    for tag, vs, ve in ordered[6:]:
        if tag == 0xA3:  # [3] EXPLICIT Extensions
            extensions = _parse_extensions(der, vs, ve)
            break

    # --- signature: the outer AlgorithmIdentifier mirrors the tbs one, and the
    #     BIT STRING after it is the signature itself.
    sig_value = b""
    for tag, ovs, ove in _iter_tlv(der, tbs_ve, outer_ve):
        if tag == _TAG_BIT_STRING:
            sig_value = der[ovs + 1 : ove]  # drop the unused-bits octet
    sig_name, sig_hash = _SIGALG.get(sig_alg_oid, (sig_alg_oid, "?"))

    # --- extensions
    is_ca = False
    key_usage: List[str] = []
    eku: List[str] = []
    san_dns: List[str] = []
    san_ip: List[str] = []
    san_email: List[str] = []
    has_san = False
    for oid, (_critical, vs, ve) in extensions.items():
        if oid == _EXT_SAN:
            has_san = True
            san_dns, san_ip, san_email = _parse_san(der, vs, ve)
        elif oid == _EXT_BASIC_CONSTRAINTS:
            b_vs, b_ve = _seq(der, vs, ve)
            for tag, cvs, cve in _iter_tlv(der, b_vs, b_ve):
                if tag == 0x01:
                    is_ca = der[cvs] != 0x00
                    break
        elif oid == _EXT_KEY_USAGE:
            key_usage = _parse_key_usage(der, vs, ve)
        elif oid == _EXT_EXT_KEY_USAGE:
            eku = _parse_eku(der, vs, ve)

    self_signed = bool(subject[0]) and subject[0] == issuer[0]
    # Only a self-signed certificate can be checked against its own key. A
    # CA-issued leaf would "fail" that check for perfectly legitimate reasons,
    # so we report None and let verify_signed_by() handle the chain.
    signature_valid = (
        verify_signature(tbs, sig_value, sig_hash, der[spki[3][0] : spki[3][1]])
        if self_signed
        else None
    )

    return Certificate(
        subject=subject[0],
        issuer=issuer[0],
        subject_dict=subject[1],
        issuer_dict=issuer[1],
        serial=serial,
        not_before=validity[0],
        not_after=validity[1],
        signature_algorithm=sig_name,
        signature_hash=sig_hash,
        public_key_algorithm=spki[0],
        public_key_bits=spki[1],
        public_key_curve=spki[2],
        is_ca=is_ca,
        key_usage=key_usage,
        extended_key_usage=eku,
        san_dns=san_dns,
        san_ip=san_ip,
        san_email=san_email,
        has_san=has_san,
        self_signed=self_signed,
        signature_valid=signature_valid,
        der=der,
        tbs=tbs,
        signature=sig_value,
        public_key_der=der[spki[3][0] : spki[3][1]],
    )


def load_certificate(path: str) -> Certificate:
    """Read a certificate file (DER or PEM, possibly a PEM bundle)."""
    with open(path, "rb") as handle:
        data = handle.read()
    if b"-----BEGIN" in data:
        # a bundle may hold several certificates; the leaf is the first one
        first = data.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
        return parse_certificate(first)
    return parse_certificate(data)


# --------------------------------------------------------------------------- #
# signature verification (pure Python, RSA PKCS#1 v1.5 only)
# --------------------------------------------------------------------------- #
def verify_signature(
    tbs: bytes, signature: bytes, hash_name: str, rsa_key_der: bytes
) -> Optional[bool]:
    """Verify an RSA PKCS#1 v1.5 signature over ``tbs``, in pure Python.

    ``rsa_key_der`` is the DER ``RSAPublicKey`` from the certificate. Returns
    ``None`` when the algorithm is out of scope (ECDSA, Ed25519, RSASSA-PSS, or
    a hash we do not carry an OID for) so callers can report "not checked"
    rather than "bad".
    """
    if hash_name not in _HASH_OID or not rsa_key_der:
        return None
    try:
        span = _seq(rsa_key_der, 0, len(rsa_key_der))
    except CertError:
        return None
    fields = [item for item in _iter_tlv(rsa_key_der, *span) if item[0] == _TAG_INTEGER]
    if len(fields) < 2:
        return None
    modulus = int.from_bytes(rsa_key_der[fields[0][1] : fields[0][2]], "big")
    exponent = int.from_bytes(rsa_key_der[fields[1][1] : fields[1][2]], "big")
    if modulus == 0 or exponent == 0:
        return None

    key_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) > key_bytes:
        return False
    em = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_bytes, "big")

    info = _digest_info(hash_name, hashlib.new(hash_name, tbs).digest())
    pad = key_bytes - 3 - len(info)
    if pad < 8:  # PKCS#1 v1.5 needs at least eight 0xFF bytes
        return False
    expected = b"\x00\x01" + b"\xff" * pad + b"\x00" + info
    return em == expected


def verify_signed_by(cert: Certificate, issuer: Certificate) -> Optional[bool]:
    """Check ``cert`` was signed by ``issuer`` (RSA PKCS#1 v1.5 only).

    Pass the CA certificate to turn "somebody signed this" into a real chain
    check. Returns ``None`` when the algorithm is out of scope.
    """
    return verify_signature(
        cert.tbs, cert.signature, cert.signature_hash, issuer.public_key_der
    )


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
def _matches_hostname(hostname: str, san_dns: Sequence[str], common_name: str) -> bool:
    host = hostname.strip().rstrip(".").lower()
    for name in san_dns:
        pattern = name.strip().rstrip(".").lower()
        if pattern == host:
            return True
        # wildcards only cover one label, and never a bare TLD
        if pattern.startswith("*."):
            tail = pattern[2:]
            if tail and host.endswith("." + tail) and host[: -len(tail) - 1].count(".") == 0:
                return True
    return common_name.strip().rstrip(".").lower() == host


def _is_ip_literal(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def audit_certificate(
    cert: Certificate,
    *,
    issuer: Optional[Certificate] = None,
    now: Optional[_dt.datetime] = None,
    hostname: Optional[str] = None,
    private_pki: bool = True,
    min_rsa_bits: int = 2048,
    allow_sha1: bool = False,
    max_validity_days: int = 825,
) -> Dict[str, object]:
    """Grade one certificate and return a JSON-ready report.

    ``private_pki`` matters for automotive: DoIP gateways are supposed to use
    an OEM-internal CA, so a self-signed leaf is *expected* on a bench and only
    worth an ``info`` note. Flip it to ``False`` to grade the certificate the
    way a public TLS client would, where self-signed is a hard failure.

    ``issuer`` optionally supplies the CA certificate, which upgrades the trust
    section from "self-signed?" to a real chain check.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    findings: List[Dict[str, str]] = []
    chain_checked = False
    chain_valid: Optional[bool] = None

    def add(severity: str, code: str, message: str, hint: str = "") -> None:
        findings.append({
            "severity": severity,
            "code": code,
            "message": message,
            "hint": hint,
        })

    # --- validity -------------------------------------------------------- #
    if now > cert.not_after:
        add("critical", "expired",
            f"certificate expired on {cert.not_after:%Y-%m-%d} "
            f"({-cert.days_remaining(now)} days ago)",
            "Re-issue the gateway certificate; most TLS stacks refuse to continue.")
    elif cert.days_remaining(now) <= 30:
        add("medium", "expiring_soon",
            f"certificate expires on {cert.not_after:%Y-%m-%d} "
            f"({cert.days_remaining(now)} days left)",
            "Re-issue before the next flashing session.")
    if now < cert.not_before:
        add("high", "not_yet_valid",
            f"certificate is not valid until {cert.not_before:%Y-%m-%d}",
            "Almost always a clock problem on the bench — check gateway NTP.")
    if cert.validity_days > max_validity_days:
        add("low", "long_validity",
            f"valid for {cert.validity_days} days (>{max_validity_days})",
            "Vehicle certificates outlive the car; a short lifetime limits damage.")

    # --- key ------------------------------------------------------------- #
    if 0 < cert.public_key_bits < min_rsa_bits:
        add("critical", "weak_key",
            f"{cert.public_key_algorithm} key is only {cert.public_key_bits} bits",
            f"Use at least {min_rsa_bits} bits (RSA-2048 / prime256v1).")
    elif cert.public_key_algorithm == "RSA" and cert.public_key_bits < 3072:
        add("info", "key_size_adequate",
            f"RSA {cert.public_key_bits} bits meets the floor but not the 3072-bit target",
            "Fine for a bench; some OEM specs ask for more.")

    # --- signature algorithm --------------------------------------------- #
    if cert.signature_hash in ("md5", "sha1") and not allow_sha1:
        add("high", "weak_signature",
            f"signed with {cert.signature_hash.upper()} ({cert.signature_algorithm})",
            "SHA-1 collisions are practical; re-issue with SHA-256 or better.")
    if cert.signature_valid is False:
        add("critical", "signature_invalid",
            "the signature does not verify against the certificate's own public key",
            "Either the certificate was tampered with or our parser hit a corner case.")
    elif cert.signature_valid is True:
        add("info", "signature_verified",
            "self-signature verified against the embedded public key",
            "The certificate is internally consistent.")

    # --- trust ----------------------------------------------------------- #
    if cert.self_signed:
        if private_pki:
            add("info", "self_signed",
                "self-signed (no CA in the chain) — normal for a bench/OEM-private PKI",
                "There is no third-party anchor, so pin the cert or ship your own CA.")
        else:
            add("high", "self_signed",
                "self-signed certificate with no issuer to validate against",
                "Public TLS clients reject this; install the CA or use a private CA.")
    else:
        chain_checked = issuer is not None
        if issuer is None:
            add("info", "chain_not_checked",
                f"issued by {cert.issuer or '(empty)'} — no CA supplied, chain not verified",
                "Pass the CA certificate to check the signature and the issuer name.")
        else:
            chain_valid = verify_signed_by(cert, issuer)
            if chain_valid is None:
                add("info", "chain_not_checked",
                    "chain check skipped: only RSA PKCS#1 v1.5 signatures are verified here",
                    "ECDSA / Ed25519 / RSASSA-PSS need a crypto backend.")
            elif chain_valid:
                add("info", "chain_verified",
                    f"signature verified against CA {issuer.subject}",
                    "The leaf really was issued by this CA.")
            else:
                add("critical", "chain_invalid",
                    f"signature does NOT verify against CA {issuer.subject}",
                    "Issuer name matches but the signature does not — likely forged.")
            if issuer.subject != cert.issuer:
                add("high", "issuer_name_mismatch",
                    f"issuer field {cert.issuer!r} does not match CA subject {issuer.subject!r}",
                    "The certificate was not issued by the CA you supplied.")
    if cert.is_ca:
        add("medium", "leaf_is_ca",
            "basicConstraints says this is a CA certificate",
            "A gateway leaf should be CA:FALSE; a CA leaf can mint its own certs.")

    # --- names ----------------------------------------------------------- #
    if not cert.has_san:
        add("medium", "no_san",
            "no subjectAltName extension; the CN is the only identity",
            "RFC 6125 clients ignore the CN. Add SAN with the gateway DNS name.")
    if cert.common_name and _is_ip_literal(cert.common_name) and not cert.san_dns:
        add("low", "cn_is_ip",
            f"the CN is the bare IP literal {cert.common_name!r}",
            "Put the address in a SAN iPAddress entry instead.")
    if hostname and not cert.matches_hostname(hostname):
        add("critical", "hostname_mismatch",
            f"certificate does not cover {hostname!r} "
            f"(SAN: {', '.join(cert.san_dns) or 'none'}, CN: {cert.common_name or 'none'})",
            "Clients that verify names will refuse. Re-issue with the right SAN.")
    if cert.key_usage and "digitalSignature" not in cert.key_usage and "keyAgreement" not in cert.key_usage:
        add("medium", "key_usage_unsigned",
            f"keyUsage {cert.key_usage or '[]'} does not permit signing",
            "A TLS leaf needs digitalSignature (or keyAgreement for ECDHE).")
    if not cert.key_usage:
        add("low", "no_key_usage", "no keyUsage extension",
            "Add digitalSignature + keyEncipherment to constrain the key.")
    if cert.extended_key_usage and "serverAuth" not in cert.extended_key_usage:
        add("low", "eku_not_server",
            f"extendedKeyUsage {cert.extended_key_usage} does not include serverAuth",
            "A DoIP gateway is a TLS server; its EKU should say so.")
    if cert.serial.bit_length() < 64:
        add("low", "short_serial",
            f"serial number has only {cert.serial.bit_length()} bits of entropy",
            "CABF requires 64 bits; short serials weaken revocation.")

    # --- score ----------------------------------------------------------- #
    counts = {level: 0 for level in SEVERITIES}
    penalty = 0
    for item in findings:
        counts[item["severity"]] += 1
        penalty += _PENALTY[item["severity"]]
    score = max(0, 100 - penalty)
    if counts["critical"]:
        verdict = "REJECT"
    elif counts["high"]:
        verdict = "WEAK"
    elif score >= 90:
        verdict = "STRONG"
    elif score >= 70:
        verdict = "ACCEPTABLE"
    else:
        verdict = "WEAK"
    grade = (
        "A" if score >= 90 else
        "B" if score >= 75 else
        "C" if score >= 60 else
        "D" if score >= 40 else "F"
    )

    return {
        "certificate": cert.to_dict(),
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "options": {
            "hostname": hostname,
            "private_pki": private_pki,
            "min_rsa_bits": min_rsa_bits,
        },
        "chain": {
            "checked": chain_checked,
            "valid": chain_valid,
            "ca_subject": issuer.subject if issuer else None,
        },
        "counts": counts,
        "findings": findings,
    }


def format_report(report: Dict[str, object], with_verdict: bool = True) -> str:
    """Render an audit report as plain text (no rich required).

    ``with_verdict=False`` drops the summary line, for callers that print a
    coloured verdict themselves and only want the body.
    """
    cert = report["certificate"]
    pub = cert["public_key"]
    san = cert["subject_alt_name"]
    names = list(san["dns"]) + list(san["ip"])
    curve = pub["curve"]

    lines = [
        f"subject      : {cert['subject']}",
        f"issuer       : {cert['issuer']}",
        f"validity     : {cert['valid_from']} -> {cert['valid_until']}"
        f" ({cert['validity_days']} days)",
        f"public key   : {pub['algorithm']} {pub['bits']} bits"
        + (f" ({curve})" if curve else ""),
        f"signature    : {cert['signature_algorithm']}",
        f"identities   : {', '.join(names) or '(none - CN only)'}",
        f"fingerprint  : {cert['sha256_fingerprint'][:32]}...",
        f"self-signed  : {cert['self_signed']}",
    ]
    if cert["signature_verified"] is not None:
        lines.append(f"verified     : {cert['signature_verified']}")
    chain = report.get("chain")
    if chain and chain["checked"]:
        lines.append(f"chain (CA)   : {chain['valid']} via {chain['ca_subject']}")
    if with_verdict:
        lines.append("")
        lines.append(
            f"verdict      : {report['verdict']}"
            f"  (score {report['score']}/100, grade {report['grade']})"
        )

    findings = report["findings"]
    if findings:
        lines.append("")
        lines.append("findings:")
        for item in findings:
            lines.append(f"  [{str(item['severity']).upper():<8}] {item['message']}")
            if item["hint"]:
                lines.append(f"              -> {item['hint']}")
    else:
        lines.append("")
        lines.append("findings     : none")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# live TLS probing
# --------------------------------------------------------------------------- #
@dataclass
class TlsProbe:
    """What a live TLS handshake told us about a DoIP gateway."""

    host: str
    port: int
    tls_available: bool
    negotiated_version: Optional[str] = None
    cipher: Optional[str] = None
    certificate: Optional[Certificate] = None
    accepted_versions: List[str] = field(default_factory=list)
    plaintext_doip: Optional[bool] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "tls_available": self.tls_available,
            "negotiated_version": self.negotiated_version,
            "cipher": self.cipher,
            "accepted_versions": self.accepted_versions,
            "min_accepted_version": self.accepted_versions[0] if self.accepted_versions else None,
            "plaintext_doip": self.plaintext_doip,
            "error": self.error,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


_VERSION_ORDER = (
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
)


def _quiet_ctx(version: Optional[ssl.TLSVersion] = None) -> ssl.SSLContext:
    """A deliberately permissive client context: we want to see the ugly truth.

    ``ssl.TLSVersion.TLSv1`` is deprecated on purpose here — the whole point of
    the census is to find gateways that still accept it, so the warning is
    suppressed rather than avoided.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                ctx.minimum_version = version
            except (ValueError, AttributeError):  # pragma: no cover - bare openssl
                pass
    return ctx


def _census_context() -> ssl.SSLContext:
    return _quiet_ctx(ssl.TLSVersion.TLSv1)


def _handshake(
    host: str, port: int, timeout: float, ctx: ssl.SSLContext
) -> Tuple[Optional[ssl.SSLSocket], Optional[BaseException]]:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return None, exc
    try:
        raw.settimeout(timeout)
        return ctx.wrap_socket(raw, server_hostname=host), None
    except (ssl.SSLError, OSError) as exc:
        raw.close()
        return None, exc


def probe_tls(
    host: str,
    port: int = DOIP_TLS_PORT,
    timeout: float = 3.0,
    probe_downgrade: bool = True,
    probe_plaintext: bool = True,
    plaintext_port: int = DOIP_PORT,
) -> TlsProbe:
    """Handshake with a TLS DoIP gateway and record what it will accept.

    We connect with verification off on purpose: an audit tool must be able to
    finish the handshake to *see* the certificate. The report then says how bad
    it is. ``probe_downgrade`` additionally tries each TLS version alone, which
    is how you find a gateway that still answers TLS 1.0.
    """
    result = TlsProbe(host=host, port=port, tls_available=False)
    sock, error = _handshake(host, port, timeout, _census_context())
    if sock is None:
        result.error = f"{type(error).__name__}: {error}"
        if probe_plaintext:
            result.plaintext_doip = _plaintext_doip_open(host, plaintext_port, timeout)
        return result

    result.tls_available = True
    with sock:
        result.negotiated_version = sock.version()
        cipher = sock.cipher()
        result.cipher = cipher[0] if cipher else None
        der = sock.getpeercert(binary_form=True)
        if der:
            try:
                result.certificate = parse_certificate(der)
            except CertError as exc:
                result.error = f"certificate present but unparsable: {exc}"
    sock = None  # closed by the context manager

    if probe_downgrade:
        for label, version in _VERSION_ORDER:
            ctx = _quiet_ctx(version)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                try:
                    ctx.maximum_version = version
                except (ValueError, AttributeError):  # pragma: no cover
                    continue
            probe_sock, _ = _handshake(host, port, timeout, ctx)
            if probe_sock is not None:
                result.accepted_versions.append(label)
                probe_sock.close()
    if probe_plaintext:
        result.plaintext_doip = _plaintext_doip_open(host, plaintext_port, timeout)
    return result


def _plaintext_doip_open(host: str, port: int, timeout: float) -> Optional[bool]:
    """Is the plaintext DoIP port up? A routing activation is enough to tell."""
    from .doip import (  # local import: doip.py imports this module too
        DoipError, _recv_packet, build_routing_activation_request,
    )

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    try:
        sock.settimeout(timeout)
        sock.sendall(build_routing_activation_request(0x0E00))
        _recv_packet(sock, timeout)
        return True
    except (DoipError, OSError, socket.timeout):
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def audit_endpoint(
    host: str,
    tls_port: int = DOIP_TLS_PORT,
    plaintext_port: int = DOIP_PORT,
    timeout: float = 3.0,
    hostname: Optional[str] = None,
    private_pki: bool = True,
) -> Dict[str, object]:
    """Full gateway audit: certificate posture + TLS versions + plaintext port."""
    probe = probe_tls(
        host,
        tls_port,
        timeout=timeout,
        probe_plaintext=True,
        plaintext_port=plaintext_port,
    )
    report: Dict[str, object] = {"host": host, "tls": probe.to_dict()}
    findings: List[Dict[str, str]] = []

    if not probe.tls_available:
        findings.append({
            "severity": "high" if probe.plaintext_doip else "info",
            "code": "no_tls",
            "message": f"no TLS DoIP service answered on {host}:{tls_port}",
            "hint": "ISO 13400-2 puts TLS DoIP on 3496; check the port or the gateway config.",
        })
        if probe.plaintext_doip:
            findings.append({
                "severity": "high",
                "code": "plaintext_only",
                "message": f"plaintext DoIP on {host}:{plaintext_port} accepted a routing activation",
                "hint": "Every diagnostic request crosses the wire in the clear.",
            })
        report["findings"] = findings
        report["verdict"] = "REJECT" if probe.plaintext_doip else "UNKNOWN"
        report["score"] = 30 if probe.plaintext_doip else 0
        return report

    cert_report = audit_certificate(
        probe.certificate, hostname=hostname or host, private_pki=private_pki
    )
    findings.extend(cert_report["findings"])  # type: ignore[arg-type]

    if probe.plaintext_doip:
        findings.append({
            "severity": "high",
            "code": "plaintext_accepted",
            "message": (
                f"the TLS port is up, but plaintext DoIP on {host}:{plaintext_port} "
                "still accepted a routing activation"
            ),
            "hint": "The TLS listener is optional in practice; anyone can skip it.",
        })

    old = [v for v in probe.accepted_versions if v in ("TLS 1.0", "TLS 1.1")]
    if old:
        findings.append({
            "severity": "high",
            "code": "legacy_tls",
            "message": f"gateway still negotiates {', '.join(old)}",
            "hint": f"ISO 13400-2 wants {MIN_TLS_VERSION}+; disable the old versions.",
        })
    if probe.negotiated_version and probe.negotiated_version in ("TLSv1", "TLSv1.1"):
        findings.append({
            "severity": "high",
            "code": "weak_negotiated",
            "message": f"negotiated {probe.negotiated_version} on the default handshake",
            "hint": f"Raise the minimum to {MIN_TLS_VERSION}.",
        })

    counts = {level: 0 for level in SEVERITIES}
    penalty = 0
    for item in findings:
        counts[item["severity"]] += 1
        penalty += _PENALTY[item["severity"]]
    score = max(0, 100 - penalty)
    verdict = (
        "REJECT" if counts["critical"] else
        "WEAK" if counts["high"] else
        "STRONG" if score >= 90 else
        "ACCEPTABLE" if score >= 70 else "WEAK"
    )
    report["certificate"] = cert_report
    report["findings"] = findings
    report["counts"] = counts
    report["score"] = score
    report["verdict"] = verdict
    return report


# --------------------------------------------------------------------------- #
# optional: key material for the in-process simulator
# --------------------------------------------------------------------------- #
def make_self_signed(
    common_name: str = "vehsec-bench-gateway",
    *,
    san_dns: Sequence[str] = (),
    san_ip: Sequence[str] = (),
    days: int = 365,
    key_size: int = 2048,
    is_ca: bool = False,
) -> Tuple[str, str]:
    """Generate a self-signed certificate + key as PEM strings.

    Only this function needs ``cryptography`` — it has to *create* a key pair,
    which the standard library cannot do. Install the ``tls`` extra.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:  # pragma: no cover - depends on the extra
        raise CertError(
            "make_self_signed needs the 'cryptography' package "
            "(pip install 'vehsec[tls]') to generate key material"
        ) from exc

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _dt.datetime.now(_dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=1))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    san = [x509.DNSName(n) for n in san_dns] + [
        x509.IPAddress(ipaddress.ip_address(n)) for n in san_ip
    ]
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=is_ca,
            crl_sign=is_ca, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem
