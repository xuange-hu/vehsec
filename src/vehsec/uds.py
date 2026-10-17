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
_NEGATIVE_SUBFUNCTION_NOT_SUPPORTED = 0x12
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
# diagnostic trouble codes (SAE J2012 / ISO 14229-1)
# --------------------------------------------------------------------------- #
#: Bit 7-6 of the DTC high byte select the system the fault belongs to.
DTC_LETTERS = {0b00: "P", 0b01: "C", 0b10: "B", 0b11: "U"}
DTC_LETTER_CODES = {v: k for k, v in DTC_LETTERS.items()}

#: statusOfDTC (ISO 14229-1 annex D). Bit 0 is the LSB of the status byte.
DTC_STATUS_BITS = [
    (0x01, "testFailed"),
    (0x02, "testFailedThisOperationCycle"),
    (0x04, "pendingDTC"),
    (0x08, "confirmedDTC"),
    (0x10, "testNotCompletedSinceLastClear"),
    (0x20, "testFailedSinceLastClear"),
    (0x40, "testNotCompletedThisOperationCycle"),
    (0x80, "warningIndicatorRequested"),
]

#: A short lookup for the codes the virtual ECU reports and a handful of the
#: ones you meet in the wild. Unknown codes still decode to their identifier.
DTC_DESCRIPTIONS = {
    "P0100": "Mass or Volume Air Flow Circuit Malfunction",
    "P0101": "Mass Air Flow Circuit Range/Performance",
    "P0300": "Random/Multiple Cylinder Misfire Detected",
    "P0420": "Catalyst System Efficiency Below Threshold (Bank 1)",
    "P0562": "System Voltage Low",
    "U0001": "High Speed CAN Communication Bus",
    "U0100": "Lost Communication With ECM/PCM 'A'",
    "U0101": "Lost Communication With TCM",
    "U0121": "Lost Communication With Anti-Lock Brake System Control Module",
    "U0140": "Lost Communication With Body Control Module",
    "C0035": "Left Front Wheel Speed Sensor Circuit",
    "B0001": "Driver Frontal Airbag Stage 1 Deployment Control",
}

#: Negative response codes worth naming in error messages.
NRC_NAMES = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x78: "requestCorrectlyReceived-ResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

#: DTCs the virtual ECU ships with: (high, mid, low, status).
DEFAULT_DTCS = [
    (0x01, 0x00, 0x00, 0x2C),   # P0100 — confirmed, failed since last clear
    (0x04, 0x20, 0x00, 0x0C),   # P0420 — pending + confirmed
    (0xC1, 0x00, 0x00, 0x08),   # U0100 — confirmed only
]


def decode_dtc(data) -> Dict[str, object]:
    """Decode a 3-byte UDS DTC into its SAE J2012 identifier.

    ``bytes.fromhex('0100')`` -> ``P0100``: bits 7-6 of the high byte pick the
    system letter, bits 5-4 and 3-0 are characters 2 and 3, and the middle byte
    holds characters 4 and 5. The third byte is the failure type (FTB) and is
    reported separately rather than folded into the code.
    """
    raw = bytes(data)[:3]
    if len(raw) < 3:
        raise ValueError(f"a DTC needs 3 bytes, got {len(raw)}")
    high, mid, low = raw
    letter = DTC_LETTERS[(high >> 6) & 0b11]
    code = f"{letter}{(high >> 4) & 0b11:X}{high & 0x0F:X}{(mid >> 4) & 0x0F:X}{mid & 0x0F:X}"
    return {"code": code, "raw": raw.hex().upper(), "failure_type": low,
            "description": DTC_DESCRIPTIONS.get(code)}


def encode_dtc(code: str) -> bytes:
    """Inverse of :func:`decode_dtc`: ``'P0100'`` -> ``b'\\x01\\x00\\x00'``."""
    text = str(code).strip().upper()
    if len(text) != 5 or text[0] not in DTC_LETTER_CODES:
        raise ValueError(f"'{code}' is not a DTC like P0100 / U0100")
    letter, digits = text[0], text[1:]
    try:
        second, third = int(digits[0], 16), int(digits[1], 16)
        fourth, fifth = int(digits[2], 16), int(digits[3], 16)
    except ValueError as exc:
        raise ValueError(f"'{code}' has non-hex digits") from exc
    if second > 3:
        raise ValueError(f"'{code}': the second character must be 0-3, got {second}")
    high = (DTC_LETTER_CODES[letter] << 6) | (second << 4) | third
    mid = (fourth << 4) | fifth
    return bytes([high, mid, 0x00])


def decode_dtc_status(status: int) -> list:
    """Expand a statusOfDTC byte into its flag names."""
    status &= 0xFF
    return [name for bit, name in DTC_STATUS_BITS if status & bit]


# --------------------------------------------------------------------------- #
# virtual ECU
# --------------------------------------------------------------------------- #
class VirtualEcu(threading.Thread):
    """An in-process UDS ECU that speaks ISO-TP on a virtual CAN bus.

    The client's requests show up on the bus; this thread answers them, so
    ``vehsec uds read --did 0xF190`` works with nothing plugged in. It is also
    a compact, readable model of what a real ECU does at the UDS layer — which
    is what makes the project usable for learning.

    Supported services: 0x10 session, 0x11 reset, 0x14 clear diagnostic
    information, 0x19 read DTC information, 0x22 read DID, 0x28 communication
    control, 0x2E write DID, 0x27 security access, 0x31 routine control,
    0x3E tester present. Unsupported services get a proper negative response
    (0x7F svc 0x11).
    """

    daemon = True

    def __init__(
        self,
        channel: str = "test",
        interface: str = "virtual",
        request_id: int = DEFAULT_TXID,
        response_id: int = DEFAULT_RXID,
        did_data: Optional[Dict[int, bytes]] = None,
        dtcs: Optional[list] = None,
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
        # (high, mid, low, status) — see DEFAULT_DTCS. Mutable so 0x14 can clear.
        self.dtcs: list = [tuple(d) for d in (dtcs if dtcs is not None else DEFAULT_DTCS)]
        self.comm_state: Optional[int] = None
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
        if svc == 0x14:                             # clear diagnostic information
            return self._clear_dtcs(data)
        if svc == 0x19 and data:                    # read DTC information
            return self._read_dtc_information(sub, data[1:])
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
        if svc == 0x28 and data:                    # communication control
            self.comm_state = sub
            return bytes([0x68, sub])
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

    # --- DTC sub-services --------------------------------------------------- #
    def _matching_dtcs(self, mask: int):
        return [d for d in self.dtcs if (d[3] & mask)]

    def _read_dtc_information(self, sub: int, data: bytes) -> bytes:
        """Service 0x19. Supported sub-functions: 0x01 count, 0x02 by status
        mask, 0x0A all supported DTCs."""
        mask = data[0] if data else 0xFF
        if sub == 0x01:                             # reportNumberOfDTCByStatusMask
            count = len(self._matching_dtcs(mask))
            return bytes([0x59, 0x01, 0x09, 0x00]) + count.to_bytes(2, "big")
        if sub in (0x02, 0x0A):                     # by status mask / supported
            records = self._matching_dtcs(mask) if sub == 0x02 else self.dtcs
            out = bytearray([0x59, sub, 0x09])
            for high, mid, low, status in records:
                out += bytes([high, mid, low, status])
            return bytes(out)
        return bytes([0x7F, 0x19, _NEGATIVE_SUBFUNCTION_NOT_SUPPORTED])

    def _clear_dtcs(self, data: bytes) -> bytes:
        """Service 0x14. ``0xFFFFFF`` clears every DTC; any other group clears
        the codes whose identifier overlaps the mask."""
        group = int.from_bytes(data[:3].ljust(3, b"\x00"), "big") if data else 0xFFFFFF
        if group == 0:                              # 0 is not a useful mask
            group = 0xFFFFFF
        self.dtcs = [d for d in self.dtcs
                     if not (int.from_bytes(bytes(d[:3]), "big") & group)]
        return bytes([0x54])

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

    # --- raw escape hatch --------------------------------------------------- #
    def raw(self, request: bytes, timeout: Optional[float] = None,
            raise_on_negative: bool = True) -> bytes:
        """Send an arbitrary UDS payload and return the raw response.

        Everything else in this class goes through ``udsoncan`` helpers, which
        only exist for the services that library models. Services we add
        ourselves (0x19/0x14/0x28) and anything vendor-specific go through here,
        so the payload is sent verbatim and the answer is returned verbatim.
        """
        _require()
        payload = bytes(request)
        if not payload:
            raise ValueError("an empty UDS request says nothing")
        wait = timeout if timeout is not None else self.config["request_timeout"]
        with Client(self.conn, config=self.config, request_timeout=wait) as c:
            c.conn.send(payload)
            response = c.conn.wait_frame(timeout=wait)
        if response is None:
            raise UdsError(f"no response to {payload.hex().upper()} "
                           f"within {wait}s")
        data = bytes(response)
        if raise_on_negative and data and data[0] == 0x7F:
            nrc = data[2] if len(data) > 2 else 0
            service = data[1] if len(data) > 1 else 0
            name = NRC_NAMES.get(nrc, f"0x{nrc:02X}")
            raise UdsError(f"service 0x{service:02X} refused: {name}")
        return data

    def tester_present(self, sub: int = 0x00):
        """Tester present (service 0x3E) — keeps the session from timing out."""
        resp = self.raw(bytes([0x3E, sub & 0xFF]))
        if not resp or resp[0] != 0x7E:
            raise UdsError(f"unexpected tester present response: {resp.hex()}")
        return {"tester_present": True, "response": resp.hex().upper()}

    # --- diagnostic trouble codes ------------------------------------------- #
    def dtc_count(self, status_mask: int = 0xFF) -> int:
        """Number of stored DTCs whose status overlaps ``status_mask`` (0x19 01)."""
        resp = self.raw(bytes([0x19, 0x01, status_mask & 0xFF]))
        if len(resp) < 6 or resp[0] != 0x59 or resp[1] != 0x01:
            raise UdsError(f"unexpected DTC count response: {resp.hex().upper()}")
        return int.from_bytes(resp[4:6], "big")

    def read_dtcs(self, status_mask: int = 0xFF, supported: bool = False) -> list:
        """Read the DTC list (0x19 02 by status mask, or 0x19 0A for all).

        Returns one dict per record: the J2012 code, its raw bytes, the failure
        type byte, the status byte and the expanded status flags.
        """
        sub = 0x0A if supported else 0x02
        resp = self.raw(bytes([0x19, sub, status_mask & 0xFF]))
        if len(resp) < 3 or resp[0] != 0x59 or resp[1] != sub:
            raise UdsError(f"unexpected DTC list response: {resp.hex().upper()}")
        body = resp[3:]
        records = []
        for offset in range(0, len(body) - 3, 4):
            entry = body[offset:offset + 4]
            record = decode_dtc(entry[:3])
            record["status"] = entry[3]
            record["status_text"] = decode_dtc_status(entry[3])
            records.append(record)
        return records

    def clear_dtcs(self, group: int = 0xFFFFFF):
        """Clear diagnostic information (service 0x14). Returns what is left."""
        group &= 0xFFFFFF
        resp = self.raw(bytes([0x14]) + group.to_bytes(3, "big"))
        if not resp or resp[0] != 0x54:
            raise UdsError(f"unexpected clear-DTC response: {resp.hex().upper()}")
        return {"cleared": True, "group": f"0x{group:06X}",
                "remaining": len(self.read_dtcs(supported=True))}

    def comm_control(self, sub: int = 0x00, kind: int = 0x01):
        """Communication control (service 0x28): mute/unmute the ECU's traffic.

        sub: 0x00 enableRxAndTx, 0x01 enableRxAndDisableTx,
             0x02 disableRxAndEnableTx, 0x03 disableRxAndTx.
        """
        resp = self.raw(bytes([0x28, sub & 0xFF, kind & 0xFF]))
        if not resp or resp[0] != 0x68:
            raise UdsError(f"unexpected communication control response: "
                           f"{resp.hex().upper()}")
        return {"sub_function": sub, "communication_type": kind,
                "response": resp.hex().upper()}

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
