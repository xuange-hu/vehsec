"""vehsec MCP server.

Exposes the toolkit as Model Context Protocol tools so AI coding agents
(Claude Code, Cursor, Cline, OpenCode, ...) can drive CAN/UDS/Seed-Key/V2X/ICSim
through natural language. Run with ``vehsec mcp`` (stdio transport).
"""

from __future__ import annotations

import json

try:
    from mcp.server.fastmcp import FastMCP          # mcp v1 (pinned in pyproject)
except ImportError:  # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP

mcp = FastMCP("vehsec")


def _hex(s: str) -> bytes:
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


@mcp.tool()
def can_send(arbitration_id: int, data_hex: str, interface: str = "virtual",
             channel: str = "test") -> str:
    """Send one CAN frame. data_hex like '0202' or '0x0202'."""
    from .can_bus import CanBus

    bus = CanBus(interface, channel)
    bus.send_raw(arbitration_id, _hex(data_hex))
    bus.shutdown()
    return json.dumps({"sent": True, "id": f"0x{arbitration_id:X}", "data": data_hex})


@mcp.tool()
def can_fuzz(ids: str, rounds: int = 100, mutate: bool = True,
             interface: str = "virtual", channel: str = "test") -> str:
    """Fuzz CAN ids (comma list '0x1A4,0x19B'). Returns frames sent."""
    from .can_bus import CanBus

    id_list = [int(x, 16) for x in ids.split(",")]
    bus = CanBus(interface, channel)
    n = len(list(bus.fuzz(id_list, rounds=rounds, mutate=mutate)))
    bus.shutdown()
    return json.dumps({"fuzzed": n})


@mcp.tool()
def can_analyze(file: str) -> str:
    """Discover CAN IDs from a candump log: counts, unique payloads and which
    byte positions change (candidate control signals). Returns JSON stats."""
    from .can_bus import analyze, parse_candump

    return json.dumps(analyze(parse_candump(file)))


@mcp.tool()
def uds_security_access(level: int = 1, vendor: str = "training_rotate",
                        interface: str = "virtual", channel: str = "test") -> str:
    """Run UDS 27 security access: request seed, solve, send key. Returns seed/key."""
    from .uds import UdsClient

    with UdsClient(interface=interface, channel=channel) as c:
        return json.dumps(c.security_access(level=level, vendor=vendor))


@mcp.tool()
def uds_read_did(did: str, interface: str = "virtual", channel: str = "test") -> str:
    """Read a UDS Data Identifier (e.g. '0xF190'). Returns value hex."""
    from .uds import UdsClient

    with UdsClient(interface=interface, channel=channel) as c:
        return json.dumps(c.read_did(int(did, 16)))


@mcp.tool()
def uds_read_dtcs(status_mask: str = "0xFF", supported: bool = False,
                  interface: str = "virtual", channel: str = "test") -> str:
    """Read UDS Diagnostic Trouble Codes (service 0x19): the J2012 code (e.g.
    'U0100'), its raw bytes, the status byte and the decoded status flags.
    status_mask: 0xFF all, 0x08 confirmed, 0x04 pending, 0x01 testFailed.
    supported=true asks for every supported DTC (sub-function 0x0A)."""
    from .uds import UdsClient

    mask = int(status_mask, 16)
    with UdsClient(interface=interface, channel=channel) as c:
        return json.dumps(c.read_dtcs(status_mask=mask, supported=supported))


@mcp.tool()
def uds_clear_dtcs(group: str = "0xFFFFFF", interface: str = "virtual",
                   channel: str = "test") -> str:
    """Clear UDS diagnostic information (service 0x14). group is a 3-byte DTC
    mask; 0xFFFFFF clears everything. Returns how many DTCs remain."""
    from .uds import UdsClient

    with UdsClient(interface=interface, channel=channel) as c:
        return json.dumps(c.clear_dtcs(int(group, 16)))


@mcp.tool()
def uds_decode_dtc(value: str) -> str:
    """Decode a 3-byte UDS DTC (hex, e.g. 'C10000') into its SAE J2012 code and
    a short description. Accepts 'U0100' directly too."""
    from .uds import decode_dtc, encode_dtc

    text = value.strip()
    raw = encode_dtc(text) if (len(text) == 5 and text[0].upper() in "PCBU") \
        else _hex(text)
    return json.dumps(decode_dtc(raw))


@mcp.tool()
def uds_raw(data_hex: str, interface: str = "virtual", channel: str = "test") -> str:
    """Send an arbitrary raw UDS request (e.g. '1902FF' or '22F190') and return
    the response hex. Negative responses are returned, not raised, so the caller
    can read the NRC."""
    from .uds import NRC_NAMES, UdsClient

    with UdsClient(interface=interface, channel=channel) as c:
        response = c.raw(_hex(data_hex), raise_on_negative=False)
    out = {"request": data_hex, "response": response.hex().upper()}
    if response[:1] == b"\x7f":
        nrc = response[2] if len(response) > 2 else 0
        out["negative"] = True
        out["nrc"] = NRC_NAMES.get(nrc, f"0x{nrc:02X}")
    return json.dumps(out)


@mcp.tool()
def seedkey_solve(vendor: str, seed_hex: str) -> str:
    """Solve a UDS seed for a registered vendor. Returns the key hex."""
    from . import seedkey as sk

    key = sk.solve(vendor, _hex(seed_hex))
    return json.dumps({"vendor": vendor, "key": key.hex()})


@mcp.tool()
def seedkey_vendors() -> str:
    """List registered Seed-Key vendors with an example key for seed 11223344."""
    from . import seedkey as sk

    out = {}
    for v in sk.known_vendors():
        try:
            out[v] = sk.solve(v, bytes.fromhex("11223344")).hex()
        except Exception:  # noqa: BLE001 - one bad algorithm must not break listing
            out[v] = None
    return json.dumps({"count": len(out), "vendors": out})


@mcp.tool()
def seedkey_recover(pairs: str, max_results: int = 12) -> str:
    """Recover an unknown UDS seed->key algorithm from observed (seed, key) pairs.

    pairs: 'seed:key' hex pairs separated by commas, e.g.
    '11223344:4B778899,a5b6c7d8:FFE19D82'. A JSON list of {"seed","key"} objects
    also works. Returns matching algorithm expressions with a confidence level;
    3+ pairs usually narrows it to a single answer."""
    from . import seedkey as sk

    return json.dumps(sk.recover(sk.parse_pairs(pairs), max_results=max_results))


@mcp.tool()
def seedkey_predict(pairs: str, seed_hex: str) -> str:
    """Recover a seed->key algorithm from observed pairs and solve a fresh seed.

    Give it 'seed:key' hex pairs captured from one ECU and a NEW seed from the
    next session; it returns an algorithm expression plus the key for that seed.
    This is how you unlock a session without ever reading the OEM DLL."""
    from . import seedkey as sk

    return json.dumps(sk.predict(sk.parse_pairs(pairs), bytes.fromhex(seed_hex)))


@mcp.tool()
def v2x_analyze(file: str) -> str:
    """Analyze V2X ECDSA signatures (JSON list of {r,s,z}) for nonce reuse.
    Returns recovered private keys."""
    from . import v2x as vx

    sigs = vx.load_signatures_json(file)
    findings = vx.detect_nonce_reuse(sigs)
    return json.dumps({"findings": len(findings),
                       "keys": [f"0x{d:X}" for _, _, d in findings]})


@mcp.tool()
def icsim_set_speed(kmh: int, interface: str = "virtual", channel: str = "test") -> str:
    """Set the ICSim virtual cluster speed (km/h)."""
    from .icsim import IcsimController

    c = IcsimController(interface, channel); c.set_speed(kmh); c.shutdown()
    return json.dumps({"speed": kmh})


@mcp.tool()
def icsim_tamper_demo(kmh: int = 250, interface: str = "virtual",
                      channel: str = "test") -> str:
    """Run a one-shot ICSim tamper demo (speed jump + doors locked + turn left)."""
    from .icsim import IcsimController

    c = IcsimController(interface, channel); r = c.demo_tamper(kmh); c.shutdown()
    return json.dumps(r)


@mcp.tool()
def isotp_segment(data_hex: str) -> str:
    """Split a payload into ISO-TP (ISO 15765-2) frames — single frame, or
    first frame + consecutive frames. Returns the frame list as hex."""
    from .iso_tp import segment

    frames = segment(_hex(data_hex))
    return json.dumps({"count": len(frames), "frames": [f.hex().upper() for f in frames]})


@mcp.tool()
def isotp_decode(frame_hex: str) -> str:
    """Decode one ISO-TP frame into its PCI fields (SF / FF / CF / FC)."""
    from .iso_tp import decode

    return json.dumps(decode(_hex(frame_hex)), default=lambda b: b.hex())


@mcp.tool()
def isotp_reassemble(frames_hex: str) -> str:
    """Reassemble a payload from comma-separated ISO-TP frames, validating the
    consecutive-frame sequence numbers. Returns the payload hex and length."""
    from .iso_tp import reassemble

    payload = reassemble([_hex(f) for f in frames_hex.split(",")])
    return json.dumps({"payload": payload.hex().upper(), "length": len(payload)})


@mcp.tool()
def isotp_explain(data_hex: str = "", frames_hex: str = "") -> str:
    """Render an ISO-TP transfer as an ASCII diagram showing how the payload is
    chopped into First Frame + Consecutive Frames, with sequence numbers and the
    reassembled payload. Pass either data_hex (a payload to segment) or
    frames_hex (comma-separated captured frames)."""
    from .iso_tp import explain, explain_payload

    if bool(data_hex) == bool(frames_hex):
        return json.dumps({"error": "pass exactly one of data_hex or frames_hex"})
    if data_hex:
        return explain_payload(_hex(data_hex))
    return explain([_hex(f) for f in frames_hex.split(",")])


@mcp.tool()
def j1939_decode(can_id: str, data_hex: str | None = None) -> str:
    """Decode a J1939 29-bit CAN identifier (trucks/buses). Optionally decode the
    payload when the PGN is known (EEC1 engine speed, DM1 diagnostics, requests).
    can_id like '0x18F00400', data_hex like 'FFFFFFFFFFFFFFFF'."""
    from .j1939 import decode

    payload = _hex(data_hex) if data_hex else None
    return json.dumps(decode(int(can_id, 16), payload))


@mcp.tool()
def j1939_encode(pgn: str, source: int = 0, priority: int = 6,
                 destination: int = 0xFF) -> str:
    """Build a 29-bit J1939 CAN id from a PGN and source address. pgn like '0xF004'."""
    from .j1939 import encode_id

    cid = encode_id(int(pgn, 16), source, priority, destination)
    return json.dumps({"can_id": f"0x{cid:08X}"})


@mcp.tool()
def j1939_decode_name(value: str) -> str:
    """Decode a 64-bit J1939 NAME (address-claim identity) into its fields."""
    from .j1939 import decode_name

    return json.dumps(decode_name(int(value, 16)))


@mcp.tool()
def j1939_decode_dm1(data_hex: str) -> str:
    """Decode a J1939 DM1 message: warning lamps plus the active DTC list
    (SPN / FMI / CM / OC). data_hex includes lamp status bytes."""
    from .j1939 import decode_dm1

    return json.dumps(decode_dm1(_hex(data_hex)))


@mcp.tool()
def doip_simulate(vin: str = "WVWZZZ1JZXW000001") -> str:
    """Run an in-process DoIP (ISO 13400) vehicle, discover it, activate routing
    and read the VIN over UDS. No hardware or vehicle needed. Returns the
    announcement, activation result and UDS response."""
    from . import doip as dp

    with dp.DoipSimulator(vin=vin, host="127.0.0.1") as sim:
        found = dp.discover(host=sim.host, port=sim.udp_port, timeout=1.5)
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=3.0) as c:
            activation = c.routing_activation()
            vin_resp = c.request(sim.logical_address, bytes.fromhex("22F190"))
        return json.dumps({
            "vin": vin,
            "discovered": [a.to_dict() for a in found],
            "routing_activation": activation,
            "uds_22_f190": vin_resp.hex(),
            "vin_ascii": vin_resp[3:].decode("ascii", "replace"),
        })


@mcp.tool()
def doip_probe(host: str, target: str = "0x1000", service: str = "22F190",
               port: int = 13400) -> str:
    """Connect to a real DoIP gateway: routing activation + one UDS request.
    Returns the activation response and the raw UDS response hex."""
    from . import doip as dp

    with dp.DoipClient(host, port, timeout=5.0) as c:
        activation = c.routing_activation()
        resp = c.request(int(target, 16), _hex(service))
    return json.dumps({"routing_activation": activation, "response": resp.hex()})


@mcp.tool()
def doip_tls_audit(file: str, ca: str = "", hostname: str = "",
                   public_pki: bool = False) -> str:
    """Audit a DoIP gateway certificate (PEM or DER file) for weak crypto.

    Reports the key size, signature hash, validity window, subjectAltName and
    self-signed status, each graded critical/high/medium/low with a 0-100 score.
    Pass `ca` (CA certificate path) to verify the chain, and `hostname` to check
    the certificate actually covers the gateway you connected to."""
    from . import doip_tls as dt

    cert = dt.load_certificate(file)
    issuer = dt.load_certificate(ca) if ca else None
    return json.dumps(
        dt.audit_certificate(
            cert, issuer=issuer, hostname=hostname or None, private_pki=not public_pki
        )
    )


@mcp.tool()
def doip_tls_probe(host: str, port: int = 3496, plaintext_port: int = 13400) -> str:
    """Audit a live DoIP gateway: which TLS versions it accepts, the certificate
    it presents, and whether the plaintext port 13400 still allows diagnostics.
    A gateway that answers plaintext 13400 makes its own TLS listener pointless."""
    from . import doip_tls as dt

    return json.dumps(dt.audit_endpoint(host, tls_port=port, plaintext_port=plaintext_port))


@mcp.tool()
def doip_tls_simulate(vin: str = "WVWZZZ1JZXW000001") -> str:
    """Spin up an in-process DoIP gateway *over TLS*, complete the handshake,
    exchange a UDS request, then audit the certificate it presented. No vehicle,
    no hardware, no network."""
    from . import doip as dp
    from . import doip_tls as dt

    with dp.DoipSimulator(vin=vin, host="127.0.0.1", tls=True) as sim:
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=5.0, tls=True) as c:
            version, cipher = c.tls_version, c.tls_cipher
            activation = c.routing_activation()
            vin_resp = c.request(sim.logical_address, bytes.fromhex("22F190"))
            cert = c.peer_certificate()
    return json.dumps({
        "tls_version": version,
        "cipher": cipher,
        "routing_activation": activation,
        "uds_22_f190": vin_resp.hex(),
        "vin_ascii": vin_resp[3:].decode("ascii", "replace"),
        "audit": dt.audit_certificate(cert) if cert else None,
    })


@mcp.tool()
def dbc_decode(file: str, frame_id: str, data_hex: str, raw: bool = False) -> str:
    """Decode a CAN frame with a DBC database into named physical signals.
    frame_id like '0x1A4', data_hex like '1A02'. raw=true returns integers."""
    from .dbc import parse_file

    database = parse_file(file)
    fid = int(frame_id, 16) if frame_id.lower().startswith("0x") else int(frame_id)
    return json.dumps(database.decode(fid, _hex(data_hex), scaled=not raw))


@mcp.tool()
def dbc_info(file: str, search: str = "") -> str:
    """List messages/signals in a DBC file. Optional `search` filters by
    message or signal name substring (e.g. 'speed')."""
    from .dbc import parse_file

    database = parse_file(file)
    messages = database.search(search) if search else list(database)
    return json.dumps([m.to_dict() for m in messages])


async def _tool_manifest() -> list:
    tools = await mcp.list_tools()
    rows = []
    for t in tools:
        desc = (getattr(t, "description", "") or "").strip()
        rows.append({"name": t.name, "description": " ".join(desc.split())})
    return sorted(rows, key=lambda r: r["name"])


def tool_manifest() -> list:
    """Return ``[{"name": ..., "description": ...}, ...]`` for every registered tool.

    Lets ``vehsec mcp --check`` report what an agent would actually get without
    opening the stdio transport, which is also what CI asserts against.
    """
    import asyncio

    return asyncio.run(_tool_manifest())


def run() -> None:
    mcp.run()


if __name__ == "__main__":
    run()
