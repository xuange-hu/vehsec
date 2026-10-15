"""Interactive TUI (Textual) for vehsec.

Type commands at the prompt; results stream into the log. Same verbs as the
CLI: ``speed 120``, ``seedkey training_rotate 0102``, ``uds session 3``,
``v2x analyze x.json``, ``can fuzz 0x1A4 50``, ``q`` to quit.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.console import Console as TConsole
from textual.widgets import Footer, Header, Input, RichLog

_HELP = (
    "speed <kmh> | turn <none|left|right> | demo | "
    "seedkey <vendor> <hexseed> | uds session <lvl> | "
    "uds read <did> | v2x analyze <file.json> | "
    "can fuzz <id,id> <rounds> | q"
)


def _hex(s: str) -> bytes:
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


class VehsecTui(App):
    TITLE = "vehsec · vehicle security TUI"
    BINDINGS = [("ctrl+q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="log", markup=True, max_lines=2000)
        yield Input(placeholder=f"cmd: {_HELP}")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(RichLog).write(
            "[bold cyan]vehsec[/] ready. Type a command or [yellow]help[/]."
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if text in ("q", "quit", "exit"):
            self.exit()
            return
        if text in ("help", "?"):
            self.query_one(RichLog).write(_HELP)
            return
        self._run(text)

    def _run(self, text: str) -> None:
        log = self.query_one(RichLog)
        try:
            parts = text.split()
            cmd, args = parts[0], parts[1:]
            if cmd == "speed":
                from .icsim import IcsimController

                c = IcsimController(); c.set_speed(int(args[0])); c.shutdown()
                log.write(f"[green]speed[/] -> {args[0]}")
            elif cmd == "turn":
                from .icsim import IcsimController

                c = IcsimController(); c.set_turn(args[0]); c.shutdown()
                log.write(f"[green]turn[/] -> {args[0]}")
            elif cmd == "demo":
                from .icsim import IcsimController

                c = IcsimController(); r = c.demo_tamper(); c.shutdown()
                log.write(str(r))
            elif cmd == "seedkey":
                from . import seedkey as sk

                key = sk.solve(args[0], _hex(args[1]))
                log.write(f"[green]key[/] {key.hex()}")
            elif cmd == "uds" and args[0] == "session":
                from .uds import UdsClient

                with UdsClient() as u:
                    log.write(str(u.session(int(args[1]))))
            elif cmd == "uds" and args[0] == "read":
                from .uds import UdsClient

                with UdsClient() as u:
                    log.write(str(u.read_did(int(args[1], 16))))
            elif cmd == "v2x" and args[0] == "analyze":
                from . import v2x as vx

                sigs = vx.load_signatures_json(args[1])
                findings = vx.detect_nonce_reuse(sigs)
                log.write(f"[cyan]{len(findings)}[/] nonce-reuse finding(s)")
                for a, b, d in findings:
                    log.write(f"  sigs {a},{b} -> priv 0x{d:X}")
            elif cmd == "can" and args[0] == "fuzz":
                from .can_bus import CanBus

                ids = [int(x, 16) for x in args[1].split(",")]
                bus = CanBus(); n = len(list(bus.fuzz(ids, rounds=int(args[2])))); bus.shutdown()
                log.write(f"[green]fuzzed[/] {n} frames")
            else:
                log.write(f"[red]unknown[/]: {text}  (type help)")
        except Exception as e:  # noqa: BLE001
            log.write(f"[red]error[/]: {e}")
