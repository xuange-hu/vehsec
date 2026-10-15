"""UDS (Unified Diagnostic Services) client.

Built on ``udsoncan`` + ``isotp`` + ``python-can``. Designed to talk to a real
ECU or to UDSim / a virtual ECU over a CAN transport (ISO-TP).
"""

from __future__ import annotations

from typing import Optional

from . import seedkey

try:
    import isotp
except ImportError:  # pragma: no cover
    isotp = None

try:
    import udsoncan
    from udsoncan.connection import Connection
except ImportError:  # pragma: no cover
    udsoncan = None
    Connection = None


def _require():
    if isotp is None or udsoncan is None:
        raise RuntimeError(
            "UDS requires isotp and udsoncan (pip install isotp udsoncan)"
        )


class UdsClient:
    """High-level UDS client over ISO-TP."""

    def __init__(
        self,
        txid: int = 0x7E0,
        rxid: int = 0x7E8,
        interface: Optional[str] = None,
        channel: Optional[str] = None,
        request_timeout: float = 2.0,
    ):
        from .can_bus import default_bus

        _require()
        self.txid, self.rxid = txid, rxid
        bus = default_bus(interface, channel)
        addr = isotp.Address(rxid=rxid, txid=txid)
        self.tp = isotp.TransportLayer(bus, addr)
        cfg = udsoncan.configs.default.copy()
        cfg["request_timeout"] = request_timeout
        self.conn = Connection(self.tp, config=cfg)

    def __enter__(self):
        self.conn.open()
        return self

    def __exit__(self, *exc):
        self.conn.close()
        self.tp.shutdown()

    # --- diagnostic services -------------------------------------------------
    def session(self, level: int):
        """Switch diagnostic session (1=default, 2=programming, 3=extended)."""
        with udsoncan.Client(self.conn, request_timeout=self.conn.config["request_timeout"]) as c:
            c.change_session(level)
        return {"session": level, "status": "ok"}

    def security_access(self, level: int = 1, vendor: Optional[str] = None,
                        algorithm=None, seed_len: int = 4):
        """Request a seed, solve it, send the key, return the result."""
        with udsoncan.Client(self.conn, request_timeout=self.conn.config["request_timeout"]) as c:
            seed = c.request_seed(level)
            seed_bytes = bytes(seed)
            if algorithm is not None:
                key = algorithm(seed_bytes)
            elif vendor is not None:
                key = seedkey.solve(vendor, seed_bytes)
            else:
                raise ValueError("provide 'vendor' or 'algorithm' to solve the seed")
            c.send_key(level, key)
        return {"level": level, "seed": seed_bytes.hex(), "key": bytes(key).hex(), "unlocked": True}

    def read_did(self, did: int):
        """Read a Data Identifier (22 service)."""
        with udsoncan.Client(self.conn, request_timeout=self.conn.config["request_timeout"]) as c:
            resp = c.read_data_by_identifier(did)
        return {"did": f"0x{did:04X}", "value": bytes(resp).hex()}

    def write_did(self, did: int, data: bytes):
        """Write a Data Identifier (2E service)."""
        with udsoncan.Client(self.conn, request_timeout=self.conn.config["request_timeout"]) as c:
            c.write_data_by_identifier(did, data)
        return {"did": f"0x{did:04X}", "written": len(data)}

    def ecu_reset(self, kind: int = 1):
        """ECU reset (11 service)."""
        with udsoncan.Client(self.conn, request_timeout=self.conn.config["request_timeout"]) as c:
            c.ecu_reset(kind)
        return {"reset": kind, "status": "ok"}

    def routine(self, rid: int, data: bytes = b""):
        """Routine control (31 service)."""
        with udsoncan.Client(self.conn, request_timeout=self.conn.config["request_timeout"]) as c:
            c.routine_control(rid, data)
        return {"routine": f"0x{rid:04X}", "status": "ok"}
