"""UDS (Unified Diagnostic Services) client over ISO-TP.

Built on ``udsoncan`` + ``can-isotp`` + ``python-can``. Talks to a real ECU, to
UDSim, or — by default and with no hardware at all — to the :class:`VirtualEcu`
included here, so every ``vehsec uds ...`` command works on a laptop.

Compatibility notes (both of these silently broke the client at some point):

* ``udsoncan`` moved ``Connection`` from ``udsoncan.connection`` to
  ``udsoncan.connections`` in 1.22. Import both shapes.
* ``can-isotp`` 2.x changed ``TransportLayer(bus, address)`` to
  ``TransportLayer(rxfn, txfn, address)``. The bus-carrying constructor is now
  ``CanStack(bus, address)``. Support both, because ``can-isotp>=1.0`` resolves
  to 2.x on a fresh install.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Dict, Optional

from . import iso_tp, seedkey

try:
    import isotp
except ImportError:  # pragma: no cover
    isotp = None

try:
    import udsoncan
    from udsoncan.client import Client  # noqa: F401  (re-exported for callers)
except ImportError:  # pragma: no cover
    udsoncan = None
    Client = None

# Default virtual-network addressing: tester asks on 0x7E0, ECU answers 0x7E8.
DEFAULT_TXID = 0x7E0
DEFAULT_RXID = 0x7E8

#: A 17-character VIN, returned by DID 0xF190 on the virtual ECU.
DEFAULT_VIN = b"WVWZZZ1JZXW000001"

_NEGATIVE_SERVICE_NOT_SUPPORTED = 0x11
_NEGATIVE_REQUEST_OUT_OF_RANGE = 0x31
_NEGATIVE_INVALID_KEY = 0x35


class UdsError(RuntimeError):
    """Raised when UDS cannot run (missing deps, bad response, timeout)."""


def _require() -> None:
    if isotp is None or Client is None:
        raise UdsError(
            "UDS requires can-isotp and udsoncan — pip install 'vehsec[all]' "
            "(note the ISO-TP distribution is named can-isotp, and imports as isotp)"
        )


# --------------------------------------------------------------------------- #
# dependency-shape shims
# --------------------------------------------------------------------------- #
def isotp_address(txid: int, rxid: int):
    """Build an isotp Address across can-isotp 1.x/2.x."""
    return isotp.Address(txid=txid, rxid=rxid)


def isotp_layer(bus, address):
    """Build an ISO-TP layer bound to a python-can bus.

    can-isotp 2.x exposes ``CanStack(bus, address)``; 1.x only had
    ``TransportLayer(bus, address)``.
    """
    if hasattr(isotp, "CanStack"):              # can-isotp >= 2.0
        # address must be keyword: CanStack forwards *args to TransportLayer,
        # whose first positional is rxfn, not address.
        return isotp.CanStack(bus, address=address)
    return isotp.TransportLayer(bus, address)   # can-isotp 1.x


def make_connection(layer, name: str = "vehsec"):
    """Wrap an ISO-TP layer in the udsoncan connection class for this version."""
    try:                                        # udsoncan >= 1.22
        from udsoncan.connections import PythonIsoTpConnection
        return PythonIsoTpConnection(layer, name=name)
    except ImportError:
        pass
    try:                                        # udsoncan < 1.22
        from udsoncan.connection import Connection
        return Connection(layer)
    except ImportError as exc:                  # pragma: no cover
        raise UdsError(f"cannot locate a udsoncan connection class: {exc}") from exc


def default_config() -> dict:
    """A mutable copy of udsoncan's default client config.

    The object was renamed ``configs.default`` -> ``configs.default_client_config``
    in udsoncan 1.22, so look for both.
    """
    configs = udsoncan.configs
    base = getattr(configs, "default_client_config", None) or getattr(configs, "default")
    return dict(base).copy()


def _raw_did_codec():
    """A pass-through DID codec.

    udsoncan refuses to touch a DID that has no entry in
    ``config['data_identifiers']``. Rather than making callers declare every
    DID up front (you usually don't know them before scanning), register a raw
    codec under the ``'default'`` key that ``check_did_config`` accepts.
    """
    from udsoncan.common.dids import DidCodec

    class _RawDid(DidCodec):
        def encode(self, *did_value):
            if not did_value:
                return b""
            if isinstance(did_value[0], (bytes, bytearray)):
                return bytes(did_value[0])
            return bytes(did_value)

        def decode(self, did_value):
            return bytes(did_value)

        def __len__(self):
            # The DID payload length is unknown ahead of time; telling udsoncan
            # to take the rest of the response is exactly what we want.
            raise DidCodec.ReadAllRemainingData

    return _RawDid()


def _ascii_or_none(data: bytes):
    """DIDs often hold text (a VIN is ASCII). Return it when printable."""
    try:
        text = bytes(data).decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def _stmin_seconds(st_min: int) -> float:
    """STmin -> seconds. 0x00-0x7F is milliseconds; 0xF1-0xF9 is 100-900 us."""
    if 0xF1 <= st_min <= 0xF9:
        return (st_min - 0xF0) / 10_000.0
    return min(st_min, 0x7F) / 1000.0


# --------------------------------------------------------------------------- #
# virtual ECU
# --------------------------------------------------------------------------- #
class VirtualEcu(threading.Thread):
    """An in-process UDS ECU that speaks ISO-TP on a virtual CAN bus.

    The client's requests show up on the bus; this thread answers them, so
    ``vehsec uds read --did 0xF190`` works with nothing plugged in. It is also
    a compact, readable model of what a real ECU does at the UDS layer — which
    is what makes the project usable for learning.

    Supported services: 0x10 session, 0x11 reset, 0x22 read DID, 0x2E write
    DID, 0x27 security access, 0x31 routine control, 0x3E tester present.
    Unsupported services get a proper negative response (0x7F svc 0x11).
    """

    daemon = True

    def __init__(
        self,
        channel: str = "test",
        interface: str = "virtual",
        request_id: int = DEFAULT_TXID,
        response_id: int = DEFAULT_RXID,
        did_data: Optional[Dict[int, bytes]] = None,
        seed: bytes = b"\x01\x02\x03\x04",
        key_fn: Optional[Callable[[bytes], bytes]] = None,
        vendor: str = "training_rotate",
        timeout: float = 0.05,
    ):
        super().__init__(name="vehsec-virtual-ecu", daemon=True)
        self.request_id = request_id
        self.response_id = response_id
        self.channel = channel
        self.interface = interface
        self.seed = bytes(seed)
        self.key_fn = key_fn
        self.vendor = vendor
        self.timeout = timeout
        self.did_data: Dict[int, bytes] = dict(did_data or {})
        self.did_data.setdefault(0xF190, DEFAULT_VIN)   # VIN
        self.did_data.setdefault(0xF187, b"3Q0907115")  # spare part number
        self.did_data.setdefault(0xF18C, b"SN-0001")    # ECU serial
        self.unlocked = False
        self.seen: list[bytes] = []
        self._stop = threading.Event()
        self._bus = None

    # --- bus plumbing ------------------------------------------------------- #
    def open(self) -> None:
        import can

        self._bus = can.Bus(channel=self.channel, interface=self.interface)

    def close(self) -> None:
        self._stop.set()
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:               # pragma: no cover - best-effort teardown
                pass
            self._bus = None

    def _write(self, data: bytes) -> None:
        import can

        self._bus.send(can.Message(arbitration_id=self.response_id,
                                   data=bytes(data), is_extended_id=False))

    def _read(self, timeout: float):
        if self._bus is None:
            return None
        msg = self._bus.recv(timeout=timeout)
        if msg is None or msg.arbitration_id != self.request_id:
            return None
        return bytes(msg.data)

    # --- transport ---------------------------------------------------------- #
    def _transmit(self, payload: bytes) -> None:
        """Send a UDS response, segmenting through ISO-TP and honouring the
        receiver's flow control (block size / STmin) on multi-frame replies."""
        frames = iso_tp.segment(payload)
        self._write(frames[0])
        if len(frames) == 1:
            return

        block_size, st_min = 0, 0
        for i, frame in enumerate(frames[1:], start=1):
            if i == 1 or (block_size and (i - 1) % block_size == 0):
                fc = self._wait_flow_control()
                if fc is None:
                    break
                block_size = fc.get("block_size", 0)
                st_min = fc.get("st_min", 0)
            delay = _stmin_seconds(st_min)
            if delay:
                time.sleep(delay)
            self._write(frame)

    def _wait_flow_control(self, timeout: float = 1.0):
        """Wait for a flow control frame (here the *tester* is the receiver)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self._read(0.05)
            if not raw:
                continue
            try:
                parsed = iso_tp.decode(raw)
            except ValueError:
                continue
            if parsed["type"] != "FC":
                continue
            if parsed.get("flow_status") == iso_tp.FLOW_WAIT:
                continue                        # FC.Wait: keep waiting
            return parsed
        return None

    def _collect_request(self):
        """Read one ISO-TP request: single frame directly, else FF + CFs."""
        first = self._read(self.timeout)
        if not first:
            return None
        try:
            head = iso_tp.decode(first)
        except ValueError:
            return None
        if head["type"] == "SF":
            return head["data"]
        if head["type"] != "FF":
            return None

        # Multi-frame request: grant flow control, then gather the CFs.
        self._write(iso_tp.encode_flow_control(iso_tp.FLOW_CONTINUE, 0, 0))
        frames = [first]
        total = head["total"]
        got = len(head["data"])
        deadline = time.monotonic() + 1.0
        while got < total and time.monotonic() < deadline:
            raw = self._read(0.05)
            if not raw:
                continue
            try:
                parsed = iso_tp.decode(raw)
            except ValueError:
                continue
            if parsed["type"] == "CF":
                frames.append(raw)
                got += len(parsed["data"])
        try:
            return iso_tp.reassemble(frames)
        except ValueError:
            return None

    # --- UDS layer ---------------------------------------------------------- #
    def handle(self, req: bytes) -> bytes:
        """Pure UDS service dispatch — no bus involved, so it is unit-testable."""
        self.seen.append(bytes(req))
        if not req:
            return bytes([0x7F, 0x00, _NEGATIVE_SERVICE_NOT_SUPPORTED])
        svc, data = req[0], req[1:]
        sub = data[0] if data else 0x00

        if svc == 0x10:                             # diagnostic session control
            return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])
        if svc == 0x11:                             # ECU reset
            return bytes([0x51, sub])
        if svc == 0x22 and len(data) >= 2:          # read data by identifier
            did = int.from_bytes(data[:2], "big")
            value = self.did_data.get(did)
            if value is None:
                return bytes([0x7F, 0x22, _NEGATIVE_REQUEST_OUT_OF_RANGE])
            return bytes([0x62]) + data[:2] + value
        if svc == 0x2E and len(data) >= 2:          # write data by identifier
            did = int.from_bytes(data[:2], "big")
            self.did_data[did] = bytes(data[2:])
            return bytes([0x6E]) + data[:2]
        if svc == 0x27 and data:                    # security access
            if sub % 2 == 1:                        # odd sub-function: send seed
                return bytes([0x67, sub]) + self.seed
            expected = (self.key_fn(self.seed) if self.key_fn
                        else seedkey.solve(self.vendor, self.seed))
            if bytes(data[1:1 + len(expected)]) == bytes(expected):
                self.unlocked = True
                return bytes([0x67, sub])
            return bytes([0x7F, 0x27, _NEGATIVE_INVALID_KEY])
        if svc == 0x31 and len(data) >= 3:          # routine control
            return bytes([0x71, sub, data[1], data[2]])
        if svc == 0x3E:                             # tester present
            return bytes([0x7E, 0x00])
        return bytes([0x7F, svc, _NEGATIVE_SERVICE_NOT_SUPPORTED])

    # --- thread body -------------------------------------------------------- #
    def run(self) -> None:
        while not self._stop.is_set():
            req = self._collect_request()
            if req:
                try:
                    self._transmit(self.handle(req))
                except Exception:               # pragma: no cover - bus already gone
                    break

    def __enter__(self):
        self.open()
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------- #
# client
# --------------------------------------------------------------------------- #
class UdsClient:
    """High-level UDS client over ISO-TP.

    By default it attaches a :class:`VirtualEcu` to the same virtual channel so
    every command works out of the box. Pass ``auto_ecu=False`` to talk to a
    real ECU or to UDSim without our simulator answering for it.
    """

    def __init__(
        self,
        txid: int = DEFAULT_TXID,
        rxid: int = DEFAULT_RXID,
        interface: Optional[str] = None,
        channel: Optional[str] = None,
        request_timeout: float = 2.0,
        auto_ecu: bool = True,
        ecu: Optional[VirtualEcu] = None,
    ):
        from .can_bus import default_bus

        _require()
        self.txid, self.rxid = txid, rxid
        self.interface = interface or os.environ.get("VEHSEC_CAN_IFACE", "virtual")
        self.channel = channel or os.environ.get("VEHSEC_CAN_CHANNEL", "test")

        bus = default_bus(self.interface, self.channel)
        addr = isotp_address(txid=txid, rxid=rxid)
        self.tp = isotp_layer(bus, addr)
        self.conn = make_connection(self.tp)
        self.bus = bus

        self.config = default_config()
        self.config["request_timeout"] = request_timeout

        self.ecu = ecu
        if self.ecu is None and auto_ecu and self.interface == "virtual":
            self.ecu = VirtualEcu(channel=self.channel, interface=self.interface,
                                  request_id=txid, response_id=rxid)
        if self.ecu is not None and not self.ecu.is_alive():
            self.ecu.open()
            self.ecu.start()

    # --- internals ---------------------------------------------------------- #
    def _client(self):
        return Client(self.conn, config=self.config,
                      request_timeout=self.config["request_timeout"])

    @staticmethod
    def _payload(resp) -> bytes:
        """Unwrap a udsoncan ``Response`` (1.26+) down to its payload bytes."""
        if hasattr(resp, "positive") and hasattr(resp, "data"):
            if not resp.positive:
                name = getattr(resp, "code_name", "unknown")
                raise UdsError(f"ECU refused the request: {name}")
            return bytes(resp.data)
        return bytes(resp)

    @staticmethod
    def _did_value(resp):
        """Normalise read_data_by_identifier's return across udsoncan versions.

        Older releases returned raw bytes (or a ``{did: value}`` dict); 1.26+
        returns a ``Response`` object that must be unwrapped, and whose payload
        still carries the two-byte DID echo in front of the value.
        """
        if hasattr(resp, "positive") and hasattr(resp, "data"):
            payload = UdsClient._payload(resp)
        elif isinstance(resp, dict):
            items = list(resp.items())
            if not items:
                raise UdsError("ECU returned no data for the DID")
            payload = bytes(items[0][1])
        else:
            payload = bytes(resp)
        return payload

    def _did_config(self):
        """Ensure bare (undeclared) DIDs can be read and written."""
        dids = self.config.setdefault("data_identifiers", {})
        if not isinstance(dids, dict):          # pragma: no cover - defensive
            dids = self.config["data_identifiers"] = {}
        dids.setdefault("default", _raw_did_codec())
        return self.config

    # --- diagnostic services ------------------------------------------------ #
    def session(self, level: int):
        """Switch diagnostic session (1=default, 2=programming, 3=extended)."""
        with self._client() as c:
            c.change_session(level)
        return {"session": level, "status": "ok"}

    def security_access(self, level: int = 1, vendor: Optional[str] = None,
                        algorithm=None, seed_len: int = 4):
        """Request a seed, solve it, send the key, return the result.

        The solving is injected through udsoncan's ``security_algo`` hook so the
        seed we see is the one udsoncan parsed out of the response — stripping
        the service framing by hand breaks whenever it changes.
        """
        if algorithm is None and vendor is None:
            raise ValueError("provide 'vendor' or 'algorithm' to solve the seed")

        captured: Dict[str, bytes] = {}

        def _algo(seed, level=None, params=None):
            seed_bytes = bytes(seed)
            if algorithm is not None:
                key = algorithm(seed_bytes)
            else:
                key = seedkey.solve(vendor, seed_bytes)
            key_bytes = bytes(key)
            captured["seed"] = seed_bytes
            captured["key"] = key_bytes
            return key_bytes

        cfg = dict(self.config)
        cfg["security_algo"] = _algo
        with Client(self.conn, config=cfg,
                    request_timeout=cfg["request_timeout"]) as c:
            c.unlock_security_access(level)
        return {"level": level, "seed": captured.get("seed", b"").hex(),
                "key": captured.get("key", b"").hex(), "unlocked": True}

    def read_did(self, did: int):
        """Read a Data Identifier (service 0x22)."""
        cfg = self._did_config()
        # Handle the refusal ourselves so callers get a UdsError with the NRC
        # name instead of an opaque third-party exception type.
        cfg["exception_on_negative_response"] = False
        with Client(self.conn, config=cfg,
                    request_timeout=cfg["request_timeout"]) as c:
            resp = c.read_data_by_identifier(did)
        payload = self._did_value(resp)
        value = payload
        # The response echoes the DID before the value; drop it so the caller
        # gets just the data (kept only when it really is the echo).
        if len(payload) >= 2 and int.from_bytes(payload[:2], "big") == did:
            value = payload[2:]
        return {"did": f"0x{did:04X}", "value": value.hex(), "ascii": _ascii_or_none(value)}
    def write_did(self, did: int, data: bytes):
        """Write a Data Identifier (service 0x2E)."""
        with Client(self.conn, config=self._did_config(),
                    request_timeout=self.config["request_timeout"]) as c:
            c.write_data_by_identifier(did, data)
        return {"did": f"0x{did:04X}", "written": len(data)}

    def ecu_reset(self, kind: int = 1):
        """ECU reset (service 0x11)."""
        with self._client() as c:
            c.ecu_reset(kind)
        return {"reset": kind, "status": "ok"}

    def routine(self, rid: int, data: bytes = b""):
        """Routine control (service 0x31)."""
        with self._client() as c:
            c.routine_control(rid, data)
        return {"routine": f"0x{rid:04X}", "status": "ok"}

    # --- lifecycle ---------------------------------------------------------- #
    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:                   # pragma: no cover
            pass
        try:
            if hasattr(self.tp, "stop"):
                self.tp.stop()
            elif hasattr(self.tp, "shutdown"):
                self.tp.shutdown()
        except Exception:                   # pragma: no cover
            pass
        try:
            self.bus.shutdown()
        except Exception:                   # pragma: no cover
            pass
        if self.ecu is not None:
            self.ecu.close()

    def __enter__(self):
        self.conn.open()
        return self

    def __exit__(self, *exc):
        self.close()
