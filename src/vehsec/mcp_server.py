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
def seedkey_solve(vendor: str, seed_hex: str) -> str:
    """Solve a UDS seed for a registered vendor. Returns the key hex."""
    from . import seedkey as sk

    key = sk.solve(vendor, _hex(seed_hex))
    return json.dumps({"vendor": vendor, "key": key.hex()})


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


def run() -> None:
    mcp.run()


if __name__ == "__main__":
    run()
