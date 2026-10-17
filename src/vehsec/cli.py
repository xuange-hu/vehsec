"""vehsec command-line interface.

A single ``vehsec`` entry point covering CAN, UDS, Seed-Key, V2X, ICSim, DoIP
and DBC decoding, plus ``vehsec tui`` and ``vehsec mcp``.
"""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _hex(s: str) -> bytes:
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


def _ids(s: str) -> list[int]:
    return [int(x, 16) if x.lower().startswith("0x") else int(x) for x in s.split(",")]


# --------------------------------------------------------------------------- #
# top-level group
# --------------------------------------------------------------------------- #
@click.group(help="vehsec — vehicle security toolkit (CAN/UDS/Seed-Key/V2X/ICSim)")
@click.version_option(package_name="vehsec")
def cli():
    pass


# --------------------------------------------------------------------------- #
# CAN
# --------------------------------------------------------------------------- #
@cli.group()
def can():
    """CAN send / replay / fuzz."""


@can.command("send")
@click.option("--id", required=True, help="arbitration id, e.g. 0x7e0")
@click.option("--data", required=True, help="hex payload, e.g. 0202")
@click.option("--iface", default=None)
@click.option("--channel", default=None)
def can_send(id, data, iface, channel):
    from .can_bus import CanBus

    bus = CanBus(iface, channel)
    bus.send_raw(int(id, 16), _hex(data))
    console.print(f"[green]sent[/] id={id} data={data}")
    bus.shutdown()


@can.command("replay")
@click.option("--file", required=True, help="candump log path")
@click.option("--iface", default=None)
@click.option("--channel", default=None)
def can_replay(file, iface, channel):
    from .can_bus import CanBus, parse_candump

    frames = parse_candump(file)
    bus = CanBus(iface, channel)
    n = bus.replay(frames)
    console.print(f"[green]replayed[/] {n} frames from {file}")
    bus.shutdown()


@can.command("fuzz")
@click.option("--ids", required=True, help="comma list of ids, e.g. 0x1A4,0x19B")
@click.option("--rounds", default=100)
@click.option("--mutate/--zeros", default=True)
@click.option("--iface", default=None)
@click.option("--channel", default=None)
def can_fuzz(ids, rounds, mutate, iface, channel):
    from .can_bus import CanBus

    bus = CanBus(iface, channel)
    sent = list(bus.fuzz(_ids(ids), rounds=rounds, mutate=mutate))
    console.print(f"[green]fuzzed[/] {len(sent)} frames")
    bus.shutdown()


@can.command("analyze")
@click.option("--file", required=True, help="candump log path")
def can_analyze(file):
    """Discover CAN IDs from a capture: counts, unique payloads, changing bytes."""
    from .can_bus import analyze, parse_candump

    stats = analyze(parse_candump(file))
    t = Table(title=f"CAN ID discovery — {file}")
    t.add_column("id"); t.add_column("count", justify="right")
    t.add_column("unique", justify="right"); t.add_column("changing bytes")
    t.add_column("first"); t.add_column("last")
    for cid, s in stats.items():
        t.add_row(cid, str(s["count"]), str(s["unique"]),
                  ",".join(str(b) for b in s["changing"]) or "-",
                  s["first"], s["last"])
    console.print(t)
    console.print("[dim]提示：unique 低=周期性状态帧；changing 位置即候选信号字节[/]")


# --------------------------------------------------------------------------- #
# UDS
# --------------------------------------------------------------------------- #
@cli.group()
def uds():
    """UDS diagnostic services."""


@uds.command("session")
@click.option("--level", default=1, help="1 default, 2 programming, 3 extended")
def uds_session(level):
    from .uds import UdsClient

    with UdsClient() as c:
        console.print(c.session(level))


@uds.command("security")
@click.option("--level", default=1)
@click.option("--vendor", default=None, help="registered seed-key vendor")
def uds_security(level, vendor):
    from .uds import UdsClient

    with UdsClient() as c:
        console.print(c.security_access(level=level, vendor=vendor))


@uds.command("read")
@click.option("--did", required=True, help="data identifier, e.g. 0xF190")
def uds_read(did):
    from .uds import UdsClient

    with UdsClient() as c:
        console.print(c.read_did(int(did, 16)))


@uds.command("write")
@click.option("--did", required=True)
@click.option("--data", required=True)
def uds_write(did, data):
    from .uds import UdsClient

    with UdsClient() as c:
        console.print(c.write_did(int(did, 16), _hex(data)))


@uds.command("dtc")
@click.option("--status", "status_mask", default="0xFF",
              help="statusOfDTC mask, e.g. 0x08 for confirmedDTC only")
@click.option("--all", "show_all", is_flag=True, help="0x19 0A — all supported DTCs")
@click.option("--count", is_flag=True, help="only report the number of DTCs")
@click.option("--clear", is_flag=True, help="clear diagnostic information (0x14)")
def uds_dtc(status_mask, show_all, count, clear):
    """Read or clear Diagnostic Trouble Codes (UDS 0x19 / 0x14)."""
    from .uds import UdsClient

    mask = int(status_mask, 16) if str(status_mask).lower().startswith("0x") \
        else int(status_mask)
    with UdsClient() as c:
        if clear:
            console.print(c.clear_dtcs())
            return
        if count:
            console.print({"count": c.dtc_count(mask), "status_mask": f"0x{mask:02X}"})
            return
        records = c.read_dtcs(status_mask=mask, supported=show_all)
    if not records:
        console.print("[green]no DTCs stored[/]")
        return
    t = Table(title=f"Diagnostic Trouble Codes ({len(records)})")
    t.add_column("code")
    t.add_column("raw")
    t.add_column("status")
    t.add_column("flags")
    t.add_column("description")
    for r in records:
        t.add_row(r["code"], r["raw"], f"0x{r['status']:02X}",
                  ",".join(r["status_text"]) or "-", r["description"] or "-")
    console.print(t)


@uds.command("comm")
@click.option("--sub", default="0x00",
              help="0 enableRxAndTx, 1 disableTx, 2 disableRx, 3 disableRxAndTx")
@click.option("--type", "kind", default="0x01", help="communicationType")
def uds_comm(sub, kind):
    """Communication control (UDS 0x28) — mute or restore ECU traffic."""
    from .uds import UdsClient

    with UdsClient() as c:
        console.print(c.comm_control(int(sub, 16), int(kind, 16)))


@uds.command("raw")
@click.option("--data", required=True, help="raw UDS request hex, e.g. 1902FF")
def uds_raw(data):
    """Send an arbitrary UDS request and print the raw response hex."""
    from .uds import UdsClient

    with UdsClient() as c:
        response = c.raw(_hex(data), raise_on_negative=False)
    text = response.hex().upper()
    if response[:1] == b"\x7f":
        console.print(f"[yellow]{text}[/] (negative response)")
    else:
        console.print(f"[green]{text}[/]")


# --------------------------------------------------------------------------- #
# Seed-Key
# --------------------------------------------------------------------------- #
@cli.group()
def seedkey():
    """Seed-Key solver."""


@seedkey.command("solve")
@click.option("--vendor", required=True)
@click.option("--seed", required=True, help="hex seed")
def seedkey_solve(vendor, seed):
    from . import seedkey as sk

    key = sk.solve(vendor, _hex(seed))
    console.print(f"[green]key[/] {key.hex()}")


@seedkey.command("vendors")
def seedkey_vendors():
    from . import seedkey as sk

    t = Table(title="Registered Seed-Key vendors")
    t.add_column("vendor")
    for v in sk.known_vendors():
        t.add_row(v)
    console.print(t)


# --------------------------------------------------------------------------- #
# V2X
# --------------------------------------------------------------------------- #
@cli.group()
def v2x():
    """V2X ECDSA nonce-reuse analysis."""


@v2x.command("analyze")
@click.option("--file", required=True, help="JSON list of {r,s,z}")
def v2x_analyze(file):
    from . import v2x as vx

    sigs = vx.load_signatures_json(file)
    findings = vx.detect_nonce_reuse(sigs)
    if not findings:
        console.print("[yellow]no nonce reuse detected[/]")
        return
    t = Table(title="Nonce-reuse findings (private key recovered)")
    t.add_column("sig_a"); t.add_column("sig_b"); t.add_column("private_key")
    for a, b, d in findings:
        t.add_row(str(a), str(b), f"0x{d:X}")
    console.print(t)


# --------------------------------------------------------------------------- #
# ICSim
# --------------------------------------------------------------------------- #
@cli.group()
def icsim():
    """Drive the ICSim virtual instrument cluster."""


@icsim.command("speed")
@click.option("--kmh", default=60)
def icsim_speed(kmh):
    from .icsim import IcsimController

    c = IcsimController(); c.set_speed(kmh); c.shutdown()
    console.print(f"[green]speed set[/] {kmh}")


@icsim.command("turn")
@click.option("--dir", default="none", help="none|left|right")
def icsim_turn(dir):
    from .icsim import IcsimController

    c = IcsimController(); c.set_turn(dir); c.shutdown()
    console.print(f"[green]turn[/] {dir}")


@icsim.command("demo")
@click.option("--kmh", default=250)
def icsim_demo(kmh):
    from .icsim import IcsimController

    c = IcsimController(); r = c.demo_tamper(kmh); c.shutdown()
    console.print(r)


# --------------------------------------------------------------------------- #
# DoIP (ISO 13400)
# --------------------------------------------------------------------------- #
@cli.group()
def doip():
    """Diagnostics over IP (ISO 13400-2) — discovery and UDS over Ethernet."""


@doip.command("discover")
@click.option("--host", default="<broadcast>", help="target host or <broadcast>")
@click.option("--port", default=13400)
@click.option("--timeout", default=2.0)
def doip_discover(host, port, timeout):
    from . import doip as dp

    found = dp.discover(host=host, port=port, timeout=timeout)
    if not found:
        console.print("[yellow]no DoIP entity answered[/]")
        return
    t = Table(title="DoIP vehicle announcement")
    t.add_column("VIN"); t.add_column("logical addr"); t.add_column("EID"); t.add_column("GID")
    for a in found:
        t.add_row(a.vin, f"0x{a.logical_address:04X}", a.eid.hex(), a.gid.hex())
    console.print(t)


@doip.command("simulate")
@click.option("--vin", default="WVWZZZ1JZXW000001")
@click.option("--host", default="127.0.0.1")
def doip_simulate(vin, host):
    """Run an in-process DoIP entity and probe it end-to-end (no hardware)."""
    from . import doip as dp

    with dp.DoipSimulator(vin=vin, host=host) as sim:
        console.print(f"[dim]simulator tcp={sim.tcp_port} udp={sim.udp_port}[/]")
        found = dp.discover(host=sim.host, port=sim.udp_port, timeout=1.5)
        console.print(f"[green]discovered[/] {[a.vin for a in found]}")
        with dp.DoipClient(sim.host, sim.tcp_port, timeout=3.0) as c:
            console.print(c.routing_activation())
            vin_resp = c.request(sim.logical_address, bytes.fromhex("22F190"))
            console.print(f"[green]UDS 22 F190 ->[/] {vin_resp.hex()}  {vin_resp[3:].decode()}")


@doip.command("probe")
@click.option("--host", required=True)
@click.option("--port", default=13400)
@click.option("--target", default="0x1000", help="ECU logical address")
@click.option("--service", default="22F190", help="UDS request hex, e.g. 22F190")
def doip_probe(host, port, target, service):
    """Routing-activate and send one raw UDS request over DoIP."""
    from . import doip as dp

    with dp.DoipClient(host, port, timeout=5.0) as c:
        console.print(c.routing_activation())
        resp = c.request(int(target, 16), bytes.fromhex(service))
        console.print(f"[green]response[/] {resp.hex()}")


# --------------------------------------------------------------------------- #
# DBC
# --------------------------------------------------------------------------- #
@cli.group()
def dbc():
    """Decode/encode CAN frames with a DBC database."""


@dbc.command("info")
@click.option("--file", required=True, help="path to .dbc")
def dbc_info(file):
    """List messages and signal counts defined in a DBC file."""
    from . import dbc as db

    database = db.parse_file(file)
    t = Table(title=f"{file} — {len(database)} messages")
    t.add_column("id"); t.add_column("name"); t.add_column("dlc", justify="right")
    t.add_column("signals", justify="right")
    for m in database:
        t.add_row(f"0x{m.frame_id:X}", m.name, str(m.length), str(len(m.signals)))
    console.print(t)


@dbc.command("decode")
@click.option("--file", required=True, help="path to .dbc")
@click.option("--id", required=True, help="frame id, e.g. 0x1A4")
@click.option("--data", required=True, help="hex payload, e.g. 1A02")
@click.option("--raw", is_flag=True, help="show raw integers instead of physical values")
@click.option("--json", "as_json", is_flag=True)
def dbc_decode(file, id, data, raw, as_json):
    """Decode one CAN frame into named signals."""
    from . import dbc as db

    database = db.parse_file(file)
    frame_id = int(id, 16) if id.lower().startswith("0x") else int(id)
    payload = _hex(data)
    try:
        values = database.decode(frame_id, payload, scaled=not raw)
    except (db.DecodeError, KeyError, ValueError) as exc:
        raise click.ClickException(str(exc))
    if as_json:
        console.print_json(data=values)
        return
    t = Table(title=f"0x{frame_id:X} {database.message(frame_id).name} — {data}")
    t.add_column("signal"); t.add_column("value", justify="right"); t.add_column("unit")
    unit_map = {s.name: s.unit for s in database.message(frame_id).signals}
    for k, v in values.items():
        t.add_row(k, str(v), unit_map.get(k, ""))
    console.print(t)


@dbc.command("encode")
@click.option("--file", required=True)
@click.option("--id", required=True)
@click.option("--set", "assignments", multiple=True,
              help="Signal=Value, repeatable. e.g. --set Speed=41.5")
def dbc_encode(file, id, assignments):
    """Build a CAN payload from signal names and physical values."""
    from . import dbc as db

    database = db.parse_file(file)
    values = {}
    for item in assignments:
        name, _, value = item.partition("=")
        values[name.strip()] = float(value)
    frame_id = int(id, 16) if id.lower().startswith("0x") else int(id)
    try:
        payload = database.encode(frame_id, values)
    except (db.DecodeError, KeyError, ValueError) as exc:
        raise click.ClickException(str(exc))
    console.print(f"[green]payload[/] {payload.hex()}")


@dbc.command("watch")
@click.option("--file", required=True)
@click.option("--log", required=True, help="candump log to decode")
def dbc_watch(file, log):
    """Decode every frame of a candump log that the DBC knows about."""
    from . import dbc as db
    from .can_bus import parse_candump

    database = db.parse_file(file)
    t = Table(title=f"{log} decoded with {file}")
    t.add_column("id"); t.add_column("name"); t.add_column("signals")
    for f in parse_candump(log):
        msg = database.messages.get(f.arbitration_id)
        if msg is None:
            continue
        try:
            decoded = msg.decode(f.data)
        except Exception as exc:  # short/unknown frames are normal in captures
            t.add_row(f"0x{f.arbitration_id:X}", msg.name, f"[red]{exc}[/]")
            continue
        t.add_row(f"0x{f.arbitration_id:X}", msg.name,
                  ", ".join(f"{k}={v}" for k, v in decoded.items()))
    console.print(t)


# --------------------------------------------------------------------------- #
# J1939
# --------------------------------------------------------------------------- #
@cli.group(help="J1939 (trucks/buses): 29-bit id, NAME, DM1 diagnostics.")
def j1939():
    """J1939 heavy-duty protocol helpers."""


@j1939.command("decode")
@click.option("--id", "can_id", required=True, help="29-bit CAN id, e.g. 0x18F00400")
@click.option("--data", default=None, help="optional hex payload")
def j1939_decode(can_id, data):
    """Decode a J1939 identifier (and payload when the PGN is known)."""
    from .j1939 import decode

    payload = _hex(data) if data else None
    console.print(decode(int(can_id, 16), payload))


@j1939.command("encode")
@click.option("--pgn", required=True, help="PGN, e.g. 0xF004")
@click.option("--source", default=0, type=int)
@click.option("--priority", default=6, type=int)
@click.option("--dest", default=0xFF, help="destination (PDU1 only)")
def j1939_encode(pgn, source, priority, dest):
    """Build a 29-bit J1939 CAN identifier from PGN + source address."""
    from .j1939 import encode_id

    cid = encode_id(int(pgn, 16), source, priority, dest)
    console.print(f"[green]0x{cid:08X}[/]")


@j1939.command("name")
@click.option("--value", required=True, help="64-bit NAME, e.g. 0x0000A00012345678")
def j1939_name(value):
    """Decode a 64-bit J1939 NAME (address-claim identity)."""
    from .j1939 import decode_name

    console.print(decode_name(int(value, 16)))


@j1939.command("dm1")
@click.option("--data", required=True, help="DM1 payload hex (lamp status + DTCs)")
def j1939_dm1(data):
    """Decode a DM1 message into lamps and SPN/FMI/CM/OC list."""
    from .j1939 import decode_dm1

    res = decode_dm1(_hex(data))
    console.print(res)
    if res["dtc_count"] == 0:
        console.print("[dim]no active DTCs[/]")


# --------------------------------------------------------------------------- #
# ISO-TP
# --------------------------------------------------------------------------- #
@cli.group(help="ISO-TP (ISO 15765-2) segmentation: the UDS transport layer.")
def isotp():
    """ISO-TP multi-frame helpers."""


@isotp.command("segment")
@click.option("--data", required=True, help="payload hex, e.g. 22F190")
def isotp_segment(data):
    """Split a payload into ISO-TP frames (SF, or FF + CFs)."""
    from .iso_tp import segment

    for i, f in enumerate(segment(_hex(data))):
        console.print(f"  [{i}] {f.hex().upper()}")


@isotp.command("decode")
@click.option("--frame", required=True, help="one frame hex, e.g. 0322F190")
def isotp_decode(frame):
    """Decode a single ISO-TP frame (SF/FF/CF/FC)."""
    from .iso_tp import decode

    console.print(decode(_hex(frame)))


@isotp.command("reassemble")
@click.option("--frames", required=True, help="comma-separated frame hex list")
def isotp_reassemble(frames):
    """Reassemble a payload from ISO-TP frames (validates CF sequence)."""
    from .iso_tp import reassemble

    payload = reassemble([_hex(f) for f in frames.split(",")])
    console.print(f"[green]{payload.hex().upper()}[/]  ({len(payload)} bytes)")


# --------------------------------------------------------------------------- #
# TUI / MCP entry points
# --------------------------------------------------------------------------- #
@cli.command()
def tui():
    """Launch the interactive TUI."""
    from .tui import VehsecTui

    VehsecTui().run()


@cli.command()
def mcp():
    """Launch the MCP server (stdio) for AI coding agents."""
    from .mcp_server import run

    run()


def main():
    cli()


if __name__ == "__main__":
    main()
