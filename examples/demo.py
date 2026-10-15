#!/usr/bin/env python3
"""vehsec scripted demo — run it, record it, put it in the README.

Runs entirely on the virtual CAN bus (no hardware, no root, Windows-friendly).
    python examples/demo.py
Record with:  asciinema rec vehsec.cast -c "python examples/demo.py"
"""
from __future__ import annotations

import sys
import tempfile

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BANNER = """[bold cyan]vehsec[/] — vehicle security toolkit
[dim]CAN · UDS · Seed-Key · V2X · ICSim — CLI / TUI / MCP[/]"""


def step(n: int, title: str) -> None:
    console.print(Panel(f"[bold]{title}[/]", title=f"Step {n}", border_style="cyan"))


def demo_id_discovery() -> None:
    """Step 1 — find which CAN id carries the control signal."""
    import random

    from vehsec.can_bus import analyze, parse_candump

    rng = random.Random(7)
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        for i in range(60):
            # 0x1A4 carries a changing counter -> likely the control/status signal
            fh.write(f"({i * 0.01:.3f}) vcan0 1A4#{i:02X}{rng.randrange(256):02X}\n")
            # 0x19B is mostly static -> status frame
            fh.write(f"({i * 0.01 + 0.005:.3f}) vcan0 19B#{0:02X}{0:02X}\n")
        path = fh.name

    stats = analyze(parse_candump(path))
    t = Table(title="CAN ID discovery")
    t.add_column("id"); t.add_column("frames", justify="right")
    t.add_column("unique payloads", justify="right"); t.add_column("changing bytes")
    for cid, s in stats.items():
        t.add_row(cid, str(s["count"]), str(s["unique"]),
                  ",".join(str(b) for b in s["changing"]) or "-")
    console.print(t)
    console.print("[green]->[/] [bold]0x1A4[/] changes constantly = the signal to target")


def demo_seedkey() -> None:
    """Step 2 — solve a UDS 27 seed."""
    from vehsec import seedkey

    seed = bytes.fromhex("0102")
    key = seedkey.solve("training_rotate", seed)
    console.print(f"  UDS 27 01 seed : [yellow]{seed.hex()}[/]")
    console.print(f"  UDS 27 02 key  : [green]{key.hex()}[/]")
    console.print("[green]->[/] key accepted, diagnostics unlocked (training algorithm)")


def demo_icsim() -> None:
    """Step 3 — tamper with the virtual instrument cluster."""
    from vehsec.icsim import IcsimController

    c = IcsimController()
    c.set_speed(0)
    result = c.demo_tamper(kmh=250)
    c.shutdown()
    console.print(f"  injected frames -> {result}")
    console.print("[green]->[/] cluster now shows [bold red]250 km/h[/] with doors locked")


def demo_v2x() -> None:
    """Step 4 — recover a V2X private key from a reused ECDSA nonce."""
    try:
        from vehsec import v2x
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]skipped:[/] {e}")
        return
    import hashlib
    import os

    try:
        from ecdsa import SECP256k1, SigningKey
        from ecdsa.util import sigencode_string
    except ImportError:
        console.print("[yellow]skipped:[/] ecdsa not installed")
        return

    sk = SigningKey.generate(curve=SECP256k1)
    priv = sk.privkey.secret_multiplier
    k = int.from_bytes(os.urandom(32), "big") % SECP256k1.order
    sigs = []
    for i, msg in enumerate((b"cam-speed-80", b"cam-speed-90")):
        sig = sk.sign(msg, k=k, hashfunc=hashlib.sha256, sigencode=sigencode_string)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
        sigs.append(v2x.Signature(r, s, z))
    d = v2x.recover_private_key(*sigs)
    console.print(f"  reused nonce   : [yellow]r identical across 2 messages[/]")
    console.print(f"  private key    : [red]0x{d:X}[/]")
    console.print(f"  matches signer : [green]{d == priv}[/]")
    console.print("[green]->[/] with d we can forge any CAM/DENM (MITM on V2X)")


def demo_mcp() -> None:
    """Step 5 — the same tools, exposed to an AI agent over MCP."""
    try:
        from vehsec.mcp_server import mcp
        import asyncio

        tools = asyncio.run(mcp.list_tools())
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]skipped:[/] {e}")
        return
    console.print(f"  {len(tools)} tools exposed over MCP stdio:")
    console.print("  " + ", ".join(t.name for t in tools))
    console.print("[green]->[/] ask Claude Code / Cursor: 'run a UDS security access'")


def main() -> int:
    console.print(Panel(BANNER, border_style="magenta"))
    try:
        step(1, "Recon — which CAN id is the control signal?")
        demo_id_discovery()
        step(2, "UDS 27 — solve the seed")
        demo_seedkey()
        step(3, "ICSim — spoof the instrument cluster")
        demo_icsim()
        step(4, "V2X — recover the signing key from a reused nonce")
        demo_v2x()
        step(5, "MCP — hand the toolkit to an AI agent")
        demo_mcp()
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]demo failed:[/] {e}")
        return 1
    console.print(Panel("[bold green]OK[/] — demo complete. Record it, ship it.",
                        border_style="green"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
