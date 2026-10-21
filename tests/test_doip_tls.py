"""Tests for ``vehsec.doip_tls`` — the X.509 reader and the DoIP TLS audit."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

from vehsec import doip_tls as dtl

# The fixtures are PEM constants in a sibling module; load them by path so the
# test works regardless of how pytest sets up sys.path.
_spec = importlib.util.spec_from_file_location(
    "doip_tls_certs", Path(__file__).resolve().parent / "fixtures" / "doip_tls_certs.py"
)
certs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(certs)

GATEWAY_PEM = certs.GATEWAY_PEM.encode("ascii")
CA_PEM = certs.CA_PEM.encode("ascii")
WEAK_PEM = certs.WEAK_PEM.encode("ascii")
EXPIRED_PEM = certs.EXPIRED_PEM.encode("ascii")

# A reference instant inside the gateway certificate's validity window.
NOW = dt.datetime(2026, 10, 20, 12, 0, 0, tzinfo=dt.timezone.utc)


@pytest.fixture(scope="module")
def gateway():
    return dtl.parse_certificate(GATEWAY_PEM)


@pytest.fixture(scope="module")
def ca():
    return dtl.parse_certificate(CA_PEM)


@pytest.fixture(scope="module")
def weak():
    return dtl.parse_certificate(WEAK_PEM)


@pytest.fixture(scope="module")
def expired():
    return dtl.parse_certificate(EXPIRED_PEM)


def _codes(report):
    return [f["code"] for f in report["findings"]]


# --------------------------------------------------------------------------- #
# input handling
# --------------------------------------------------------------------------- #
def test_pem_and_der_produce_the_same_certificate(gateway):
    from_der = dtl.parse_certificate(gateway.der)
    assert from_der.der == gateway.der


def test_bare_base64_without_banners_is_accepted(gateway):
    import base64

    body = b"".join(
        line for line in GATEWAY_PEM.splitlines() if not line.startswith(b"-----")
    )
    assert dtl.parse_certificate(body).der == gateway.der
    assert dtl.parse_certificate(base64.b64decode(body)).der == gateway.der


def test_non_certificate_input_is_rejected():
    for junk in (b"", b"hello", b"-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END"):
        with pytest.raises(dtl.CertError):
            dtl.parse_certificate(junk)


def test_truncated_der_is_rejected(gateway):
    with pytest.raises(dtl.CertError):
        dtl.parse_certificate(gateway.der[:120])


def test_load_certificate_reads_a_pem_file(tmp_path, gateway):
    path = tmp_path / "gw.pem"
    path.write_bytes(GATEWAY_PEM)
    assert dtl.load_certificate(str(path)).der == gateway.der


def test_load_certificate_takes_the_first_cert_of_a_bundle(tmp_path, gateway, ca):
    path = tmp_path / "bundle.pem"
    path.write_bytes(GATEWAY_PEM + CA_PEM)
    assert dtl.load_certificate(str(path)).der == gateway.der


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def test_gateway_identity_is_decoded(gateway):
    assert gateway.subject == "/C=DE/O=Bench-OEM/OU=Gateway/CN=gateway.local"
    assert gateway.common_name == "gateway.local"
    assert gateway.subject_dict["O"] == "Bench-OEM"
    assert gateway.issuer == "/C=DE/O=Bench-CA/CN=vehsec-bench-ca"
    assert gateway.self_signed is False


def test_validity_window(gateway):
    assert gateway.not_before.year == 2026
    assert gateway.not_after.year == 2027
    assert gateway.validity_days == 365


def test_algorithm_and_key(gateway):
    assert gateway.signature_algorithm == "sha256WithRSAEncryption"
    assert gateway.signature_hash == "sha256"
    assert gateway.public_key_algorithm == "RSA"
    assert gateway.public_key_bits == 2048


def test_extensions(gateway):
    assert gateway.san_dns == ["gateway.local", "ecu01.local"]
    assert gateway.san_ip == ["127.0.0.1"]
    assert gateway.has_san is True
    assert gateway.is_ca is False
    assert "digitalSignature" in gateway.key_usage
    assert gateway.extended_key_usage == ["serverAuth"]


def test_weak_certificate_shows_everything_that_is_wrong(weak):
    assert weak.public_key_bits == 1024
    assert weak.signature_hash == "sha1"
    assert weak.self_signed is True
    assert weak.has_san is False
    assert weak.common_name == "192.168.1.10"


def test_expired_certificate_dates(expired):
    assert expired.not_before == dt.datetime(2019, 1, 1, tzinfo=dt.timezone.utc)
    assert expired.not_after == dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)


def test_to_dict_is_json_serialisable(gateway):
    payload = json.dumps(gateway.to_dict())
    assert "sha256_fingerprint" in payload
    assert json.loads(payload)["public_key"]["bits"] == 2048


# --------------------------------------------------------------------------- #
# signature verification (pure Python, checked against OpenSSL output)
# --------------------------------------------------------------------------- #
def test_self_signed_certificates_verify_against_their_own_key(ca, weak, expired):
    assert ca.signature_valid is True
    assert weak.signature_valid is True
    assert expired.signature_valid is True


def test_ca_signed_leaf_is_not_claimed_to_be_self_signed(gateway):
    """Verifying a CA-issued leaf against its own key must say "unknown", not
    "invalid" — otherwise every legitimate certificate is flagged critical."""
    assert gateway.self_signed is False
    assert gateway.signature_valid is None


def test_chain_verification(gateway, ca, weak):
    assert dtl.verify_signed_by(gateway, ca) is True
    assert dtl.verify_signed_by(gateway, weak) is False


def test_signature_check_rejects_a_flipped_bit(gateway, ca):
    tampered = bytearray(gateway.tbs)
    tampered[-1] ^= 0x01
    forged = dtl.parse_certificate(gateway.der)
    object.__setattr__(forged, "tbs", bytes(tampered))
    assert dtl.verify_signed_by(forged, ca) is False


def test_verify_signature_returns_none_outside_rsa_scope(gateway):
    assert dtl.verify_signature(gateway.tbs, gateway.signature, "sha256", b"") is None
    assert dtl.verify_signature(gateway.tbs, gateway.signature, "sha3-256", b"\x30\x00") is None


# --------------------------------------------------------------------------- #
# audit: a good certificate
# --------------------------------------------------------------------------- #
def test_a_well_formed_gateway_certificate_scores_high(gateway, ca):
    report = dtl.audit_certificate(gateway, issuer=ca, now=NOW, hostname="gateway.local")
    assert report["verdict"] == "STRONG"
    assert report["score"] == 100
    assert report["grade"] == "A"
    assert report["chain"]["checked"] is True
    assert report["chain"]["valid"] is True
    assert "expired" not in _codes(report)
    assert "weak_key" not in _codes(report)


def test_issuer_name_mismatch_is_reported(gateway, weak):
    report = dtl.audit_certificate(gateway, issuer=weak, now=NOW)
    assert "issuer_name_mismatch" in _codes(report)
    assert "chain_invalid" in _codes(report)


def test_without_a_ca_the_chain_is_reported_unchecked(gateway):
    report = dtl.audit_certificate(gateway, now=NOW)
    assert report["chain"]["checked"] is False
    assert "chain_not_checked" in _codes(report)


# --------------------------------------------------------------------------- #
# audit: broken certificates
# --------------------------------------------------------------------------- #
def test_weak_certificate_is_rejected(weak):
    report = dtl.audit_certificate(weak, now=NOW, hostname="192.168.1.10")
    codes = _codes(report)
    assert report["verdict"] == "REJECT"
    for expected in ("weak_key", "weak_signature", "self_signed", "no_san", "cn_is_ip"):
        assert expected in codes, expected
    assert report["counts"]["critical"] >= 1


def test_expired_certificate_is_rejected(expired):
    report = dtl.audit_certificate(expired, now=NOW)
    assert "expired" in _codes(report)
    assert report["verdict"] == "REJECT"


def test_the_same_certificate_is_valid_inside_its_window(expired):
    inside = dt.datetime(2019, 6, 1, tzinfo=dt.timezone.utc)
    report = dtl.audit_certificate(expired, now=inside)
    assert "expired" not in _codes(report)
    assert "not_yet_valid" not in _codes(report)


def test_not_yet_valid_is_detected(gateway):
    early = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    report = dtl.audit_certificate(gateway, now=early)
    assert "not_yet_valid" in _codes(report)


def test_expiring_soon_is_medium(gateway):
    soon = gateway.not_after - dt.timedelta(days=9)
    report = dtl.audit_certificate(gateway, now=soon)
    assert "expiring_soon" in _codes(report)
    assert "expired" not in _codes(report)


def test_long_validity_is_flagged(ca):
    report = dtl.audit_certificate(ca, now=NOW)
    assert "long_validity" in _codes(report)


# --------------------------------------------------------------------------- #
# audit: names and policy switches
# --------------------------------------------------------------------------- #
def test_hostname_mismatch_is_critical(gateway):
    report = dtl.audit_certificate(gateway, now=NOW, hostname="attacker.example")
    assert "hostname_mismatch" in _codes(report)
    assert report["counts"]["critical"] == 1


def test_hostname_match_supports_wildcards(gateway):
    assert gateway.matches_hostname("gateway.local")
    assert gateway.matches_hostname("GATEWAY.local.")  # case + trailing dot
    assert not gateway.matches_hostname("other.local")
    # a wildcard SAN only covers one label
    object.__setattr__(gateway, "san_dns", ["*.local"])
    assert gateway.matches_hostname("gateway.local")
    assert not gateway.matches_hostname("a.gateway.local")


def test_private_pki_changes_how_self_signed_is_graded(weak):
    bench = dtl.audit_certificate(weak, now=NOW, private_pki=True)
    public = dtl.audit_certificate(weak, now=NOW, private_pki=False)
    bench_codes = {f["code"]: f["severity"] for f in bench["findings"]}
    public_codes = {f["code"]: f["severity"] for f in public["findings"]}
    assert bench_codes["self_signed"] == "info"
    assert public_codes["self_signed"] == "high"


def test_allow_sha1_suppresses_the_signature_finding(weak):
    report = dtl.audit_certificate(weak, now=NOW, allow_sha1=True)
    assert "weak_signature" not in _codes(report)


def test_min_rsa_bits_is_configurable(weak):
    report = dtl.audit_certificate(weak, now=NOW, min_rsa_bits=1024)
    assert "weak_key" not in _codes(report)


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def test_format_report_mentions_the_verdict_and_findings(weak):
    text = dtl.format_report(dtl.audit_certificate(weak, now=NOW))
    assert "verdict" in text
    assert "REJECT" in text
    assert "1024" in text


# --------------------------------------------------------------------------- #
# live TLS (needs cryptography, only to generate the simulator's key material)
# --------------------------------------------------------------------------- #
def test_doip_over_tls_round_trip():
    """A DoIP gateway served over TLS: handshake, routing activation, UDS."""
    pytest.importorskip("cryptography", reason="needs cryptography to mint a cert")

    from vehsec import doip as dp

    with dp.DoipSimulator(vin="WVWZZZ1JZXW000001", host="127.0.0.1", tls=True) as sim:
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=8.0, tls=True) as client:
            assert client.tls_version is not None
            assert client.tls_version.startswith("TLSv1.2") or client.tls_version == "TLSv1.3"
            assert client.routing_activation()["activated"] is True
            response = client.request(sim.logical_address, bytes.fromhex("22F190"))
            assert response[3:].decode("ascii") == "WVWZZZ1JZXW000001"
            cert = client.peer_certificate()
    assert cert is not None
    assert cert.public_key_bits >= 2048


def test_plaintext_client_cannot_talk_to_a_tls_gateway():
    """A TLS handshake failure must be an error, never a silent plaintext fallback."""
    pytest.importorskip("cryptography", reason="needs cryptography to mint a cert")

    from vehsec import doip as dp

    with dp.DoipSimulator(host="127.0.0.1", tls=True) as sim:
        with pytest.raises(Exception):
            with dp.DoipClient(sim.host, sim.tcp_port, timeout=8.0) as client:
                client.routing_activation()


def test_probe_tls_reports_a_dead_port():
    probe = dtl.probe_tls("127.0.0.1", 1, timeout=0.4, probe_plaintext=False)
    assert probe.tls_available is False
    assert probe.error


def test_audit_endpoint_on_a_dead_host_is_unknown():
    report = dtl.audit_endpoint("127.0.0.1", tls_port=1, plaintext_port=1, timeout=0.4)
    assert report["verdict"] == "UNKNOWN"
    assert report["tls"]["plaintext_doip"] is False


# --------------------------------------------------------------------------- #
# surfaces
# --------------------------------------------------------------------------- #
def test_mcp_exposes_the_doip_tls_tools():
    import asyncio

    from vehsec.mcp_server import mcp

    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert {"doip_tls_audit", "doip_tls_probe", "doip_tls_simulate"} <= names


def test_cli_tls_audit(tmp_path, gateway):
    from click.testing import CliRunner

    from vehsec.cli import cli

    path = tmp_path / "gw.pem"
    path.write_bytes(GATEWAY_PEM)
    result = CliRunner().invoke(
        cli, ["doip", "tls-audit", "--file", str(path), "--hostname", "gateway.local"]
    )
    assert result.exit_code == 0, result.output
    assert "STRONG" in result.output


def test_cli_tls_audit_json(tmp_path, gateway):
    from click.testing import CliRunner

    from vehsec.cli import cli

    path = tmp_path / "gw.pem"
    path.write_bytes(GATEWAY_PEM)
    result = CliRunner().invoke(cli, ["doip", "tls-audit", "--file", str(path), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["certificate"]["common_name"] == "gateway.local"


def test_cli_tls_simulate():
    pytest.importorskip("cryptography", reason="needs cryptography to mint a cert")

    from click.testing import CliRunner

    from vehsec.cli import cli

    result = CliRunner().invoke(cli, ["doip", "tls-simulate"])
    assert result.exit_code == 0, result.output
    assert "TLSv1" in result.output
