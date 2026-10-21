"""DoIP — Diagnostics over IP (ISO 13400-2).

DoIP is the transport modern ECUs use for flashing and diagnostics over
Ethernet (100BASE-TX / 1000BASE-T) instead of CAN. It is the gateway to
everything interesting on a 2015+ vehicle: UDS over TCP port 13400, with a
routing-activation handshake in front of it.

This module gives you three layers:

1. **Wire codec** — header/packet encode & decode, vehicle announcement,
   routing activation, diagnostic message framing. Pure bytes in/out.
2. **``DoipClient``** — a TCP client that performs routing activation and
   exchanges UDS payloads with a gateway.
3. **``DoipSimulator``** — an in-process DoIP entity (UDP + TCP) so the whole
   flow can be exercised on a laptop with no vehicle, no hardware and no
   network access. This is what the tests use.

Safety note: routing activation is trivially spoofable on many gateways.
Everything here targets your own bench/lab equipment or an authorized target.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

__all__ = [
    "PROTOCOL_VERSION",
    "DOIP_PORT",
    "PayloadType",
    "NackCode",
    "RoutingActivationCode",
    "DoipError",
    "VehicleAnnouncement",
    "build_packet",
    "parse_packet",
    "build_vehicle_identification_request",
    "build_routing_activation_request",
    "parse_routing_activation_response",
    "build_diagnostic_message",
    "parse_diagnostic_message",
    "DoipClient",
    "DoipSimulator",
    "discover",
]

PROTOCOL_VERSION = 0x02
DOIP_PORT = 13400

# 8-byte generic DoIP header: version, inverse version, payload type, length.
_HEADER = struct.Struct("!BBHI")


class PayloadType(IntEnum):
    """ISO 13400-2 payload types."""

    NEGATIVE_ACK = 0x0000
    VEHICLE_ID_REQUEST = 0x0001
    VEHICLE_ID_REQUEST_EID = 0x0002
    VEHICLE_ID_REQUEST_VIN = 0x0003
    VEHICLE_ANNOUNCEMENT = 0x0004
    ROUTING_ACTIVATION_REQUEST = 0x0005
    ROUTING_ACTIVATION_RESPONSE = 0x0006
    ALIVE_CHECK_REQUEST = 0x0007
    ALIVE_CHECK_RESPONSE = 0x0008
    ENTITY_STATUS_REQUEST = 0x4001
    ENTITY_STATUS_RESPONSE = 0x4002
    POWER_MODE_REQUEST = 0x4003
    POWER_MODE_RESPONSE = 0x4004
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_ACK = 0x8002
    DIAGNOSTIC_NACK = 0x8003


class NackCode(IntEnum):
    """Generic DoIP header negative acknowledgement codes."""

    INCORRECT_PATTERN = 0x00
    UNKNOWN_PAYLOAD_TYPE = 0x01
    MESSAGE_TOO_LARGE = 0x02
    OUT_OF_MEMORY = 0x03
    INVALID_PAYLOAD_LENGTH = 0x04


class RoutingActivationCode(IntEnum):
    """Routing activation response codes (0x10 is the one you want)."""

    SUCCESS = 0x10
    UNKNOWN_SOURCE_ADDRESS = 0x11
    NO_SOCKETS_AVAILABLE = 0x12
    SOCKET_REGISTERED_DIFFERENT = 0x13
    SOCKET_ALREADY_ACTIVE = 0x14
    AUTHENTICATION_MISSING = 0x15
    CONFIRMATION_REJECTED = 0x16
    UNSUPPORTED_ACTIVATION_TYPE = 0x17
    UNSUPPORTED_SECURITY = 0x18
    TLS_REQUIRED = 0x19
    ROUTING_ACTIVATION_DENIED = 0x1A


class DoipError(RuntimeError):
    """Raised on malformed DoIP traffic or a rejected activation."""


# --------------------------------------------------------------------------- #
# wire codec
# --------------------------------------------------------------------------- #
def build_header(payload_type: int, payload_length: int) -> bytes:
    return _HEADER.pack(
        PROTOCOL_VERSION, PROTOCOL_VERSION ^ 0xFF, int(payload_type), int(payload_length)
    )


def build_packet(payload_type: int, payload: bytes = b"") -> bytes:
    """Wrap a payload into a complete DoIP packet."""
    return build_header(payload_type, len(payload)) + payload


def parse_header(data: bytes) -> Tuple[int, int]:
    """Return ``(payload_type, payload_length)`` from the first 8 bytes."""
    if len(data) < _HEADER.size:
        raise DoipError(f"DoIP header needs {_HEADER.size} bytes, got {len(data)}")
    version, inverse, payload_type, length = _HEADER.unpack_from(data)
    if inverse != (version ^ 0xFF):
        raise DoipError(f"inverse protocol version mismatch (0x{inverse:02X})")
    return payload_type, length


def parse_packet(data: bytes) -> Tuple[int, bytes]:
    """Split one complete packet into ``(payload_type, payload)``.

    A payload type of ``0x0000`` is a negative ack and is raised as
    :class:`DoipError` so callers cannot silently ignore a rejected request.
    """
    payload_type, length = parse_header(data)
    payload = data[_HEADER.size : _HEADER.size + length]
    if len(payload) != length:
        raise DoipError(f"truncated DoIP payload: want {length}, got {len(payload)}")
    if payload_type == PayloadType.NEGATIVE_ACK:
        code = payload[0] if payload else 0x00
        try:
            name = NackCode(code).name
        except ValueError:
            name = "UNKNOWN"
        raise DoipError(f"DoIP negative ack 0x{code:02X} ({name})")
    return payload_type, payload


def _read_exactly(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = bytearray()
    while len(chunks) < n:
        try:
            chunk = sock.recv(n - len(chunks))
        except socket.timeout:
            raise DoipError(f"timeout reading DoIP stream ({len(chunks)}/{n} bytes)")
        if not chunk:
            raise DoipError("peer closed the DoIP connection")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_packet(sock: socket.socket, timeout: float = 5.0) -> Tuple[int, bytes]:
    header = _read_exactly(sock, _HEADER.size, timeout)
    _, length = parse_header(header)
    if length == 0:
        return parse_packet(header)
    return parse_packet(header + _read_exactly(sock, length, timeout))


# --------------------------------------------------------------------------- #
# vehicle identification
# --------------------------------------------------------------------------- #
@dataclass
class VehicleAnnouncement:
    """A DoIP vehicle announcement / identification response (payload 0x0004)."""

    vin: str
    logical_address: int
    eid: bytes  # 6-byte MAC-like entity id
    gid: bytes  # 6-byte group id
    further_action: int = 0x00
    vin_gid_sync: int = 0x00

    def encode(self) -> bytes:
        vin = self.vin.encode("ascii", "replace")[:17].ljust(17, b"\x00")
        eid = bytes(self.eid)[:6].ljust(6, b"\x00")
        gid = bytes(self.gid)[:6].ljust(6, b"\x00")
        return (
            vin
            + struct.pack("!H", self.logical_address)
            + eid
            + gid
            + bytes([self.further_action & 0xFF, self.vin_gid_sync & 0xFF])
        )

    @classmethod
    def decode(cls, payload: bytes) -> "VehicleAnnouncement":
        # ISO 13400-2:2012 -> 33 bytes; later revisions append a reserved byte.
        if len(payload) < 32:
            raise DoipError(f"vehicle announcement too short ({len(payload)} bytes)")
        vin = payload[:17].decode("ascii", "replace").rstrip("\x00")
        logical_address = struct.unpack_from("!H", payload, 17)[0]
        eid = payload[19:25]
        gid = payload[25:31]
        return cls(
            vin=vin,
            logical_address=logical_address,
            eid=eid,
            gid=gid,
            further_action=payload[31] if len(payload) > 31 else 0x00,
            vin_gid_sync=payload[32] if len(payload) > 32 else 0x00,
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "vin": self.vin,
            "logical_address": f"0x{self.logical_address:04X}",
            "eid": self.eid.hex(),
            "gid": self.gid.hex(),
            "further_action": self.further_action,
            "vin_gid_sync": self.vin_gid_sync,
        }


def build_vehicle_identification_request(
    vin: Optional[str] = None, eid: Optional[bytes] = None
) -> bytes:
    """Vehicle identification request; plain, by-VIN or by-EID."""
    if vin is not None:
        return build_packet(
            PayloadType.VEHICLE_ID_REQUEST_VIN,
            vin.encode("ascii")[:17].ljust(17, b"\x00"),
        )
    if eid is not None:
        return build_packet(PayloadType.VEHICLE_ID_REQUEST_EID, bytes(eid)[:6].ljust(6, b"\x00"))
    return build_packet(PayloadType.VEHICLE_ID_REQUEST)


# --------------------------------------------------------------------------- #
# routing activation
# --------------------------------------------------------------------------- #
def build_routing_activation_request(
    source_address: int, activation_type: int = 0x00, vm_specific: bytes = b""
) -> bytes:
    """Routing activation request. ``activation_type`` 0x00 = default diagnostics."""
    payload = struct.pack("!H", source_address) + bytes([activation_type & 0xFF])
    # ISO 13400-2:2012 -> 4 reserved bytes; :2019 -> 4 reserved + 4 VM specific.
    payload += b"\x00" * 4 + bytes(vm_specific)[:4].ljust(4, b"\x00")
    return build_packet(PayloadType.ROUTING_ACTIVATION_REQUEST, payload)


def parse_routing_activation_response(payload: bytes) -> Dict[str, object]:
    if len(payload) < 5:
        raise DoipError(f"routing activation response too short ({len(payload)} bytes)")
    client_addr, entity_addr = struct.unpack_from("!HH", payload, 0)
    code = payload[4]
    try:
        name = RoutingActivationCode(code).name
    except ValueError:
        name = "UNKNOWN"
    return {
        "client_logical_address": f"0x{client_addr:04X}",
        "entity_logical_address": f"0x{entity_addr:04X}",
        "response_code": f"0x{code:02X}",
        "name": name,
        "activated": code == RoutingActivationCode.SUCCESS,
    }


# --------------------------------------------------------------------------- #
# diagnostic message
# --------------------------------------------------------------------------- #
def build_diagnostic_message(
    source_address: int, target_address: int, uds_payload: bytes
) -> bytes:
    """Wrap a raw UDS request into a DoIP diagnostic message (0x8001)."""
    return build_packet(
        PayloadType.DIAGNOSTIC_MESSAGE,
        struct.pack("!HH", source_address, target_address) + bytes(uds_payload),
    )


def parse_diagnostic_message(payload: bytes) -> Tuple[int, int, bytes]:
    """Return ``(source_address, target_address, uds_payload)``."""
    if len(payload) < 4:
        raise DoipError("diagnostic message shorter than the 4-byte address block")
    src, dst = struct.unpack_from("!HH", payload, 0)
    return src, dst, payload[4:]


# --------------------------------------------------------------------------- #
# client
# --------------------------------------------------------------------------- #
class DoipClient:
    """A DoIP client: connect, activate routing, exchange UDS payloads."""

    def __init__(
        self,
        host: str,
        port: int = DOIP_PORT,
        source_address: int = 0x0E00,
        timeout: float = 5.0,
        tls: bool = False,
        ca_file: Optional[str] = None,
        server_hostname: Optional[str] = None,
        min_tls_version: Optional[str] = "TLSv1.2",
    ) -> None:
        self.host = host
        self.port = port
        self.source_address = source_address
        self.timeout = timeout
        self.tls = tls
        self.ca_file = ca_file
        self.server_hostname = server_hostname
        self.min_tls_version = min_tls_version
        self.sock: Optional[socket.socket] = None
        self.entity_address: Optional[int] = None
        self._vin: Optional[str] = None

    # -- TLS ---------------------------------------------------------------- #
    def _client_context(self) -> ssl.SSLContext:
        """Build the client context.

        Without ``ca_file`` we deliberately disable verification: a bench
        gateway hands out a self-signed certificate, and an audit tool has to
        complete the handshake to *see* that certificate. Pass ``ca_file`` (and
        inspect :meth:`peer_certificate`) when you want a real check.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.ca_file:
            ctx.load_verify_locations(self.ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if self.min_tls_version:
            wanted = getattr(ssl.TLSVersion, self.min_tls_version.replace(".", "_"), None)
            if wanted is not None:
                try:
                    ctx.minimum_version = wanted
                except ValueError:  # pragma: no cover - openssl built without it
                    pass
        return ctx

    @property
    def tls_version(self) -> Optional[str]:
        """The TLS version actually negotiated, or ``None`` on a plaintext link."""
        if isinstance(self.sock, ssl.SSLSocket):
            return self.sock.version()
        return None

    @property
    def tls_cipher(self) -> Optional[str]:
        if isinstance(self.sock, ssl.SSLSocket):
            cipher = self.sock.cipher()
            return cipher[0] if cipher else None
        return None

    def peer_certificate(self):
        """The peer certificate as a :class:`vehsec.doip_tls.Certificate`."""
        if not isinstance(self.sock, ssl.SSLSocket):
            return None
        der = self.sock.getpeercert(binary_form=True)
        if not der:
            return None
        from .doip_tls import parse_certificate  # local: doip_tls imports doip too

        return parse_certificate(der)

    # -- lifecycle ---------------------------------------------------------- #
    def connect(self) -> "DoipClient":
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.tls:
            self.sock = self._client_context().wrap_socket(
                raw, server_hostname=self.server_hostname or self.host
            )
        else:
            self.sock = raw
        return self

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "DoipClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    # -- handshake ---------------------------------------------------------- #
    def routing_activation(self, activation_type: int = 0x00) -> Dict[str, object]:
        if self.sock is None:
            raise DoipError("not connected; call connect() first")
        self.sock.sendall(build_routing_activation_request(self.source_address, activation_type))
        ptype, payload = _recv_packet(self.sock, self.timeout)
        if ptype != PayloadType.ROUTING_ACTIVATION_RESPONSE:
            raise DoipError(f"expected routing activation response, got 0x{ptype:04X}")
        result = parse_routing_activation_response(payload)
        if not result["activated"]:
            raise DoipError(f"routing activation rejected: {result['name']}")
        self.entity_address = int(str(result["entity_logical_address"]), 16)
        return result

    # -- diagnostics -------------------------------------------------------- #
    def send_diagnostic(self, target_address: int, uds_payload: bytes) -> None:
        if self.sock is None:
            raise DoipError("not connected; call connect() first")
        self.sock.sendall(
            build_diagnostic_message(self.source_address, target_address, uds_payload)
        )

    def recv_diagnostic(self, timeout: Optional[float] = None) -> Tuple[int, int, bytes]:
        """Read the next diagnostic message (0x8001), skipping acks/pings."""
        if self.sock is None:
            raise DoipError("not connected; call connect() first")
        deadline = time.monotonic() + (timeout or self.timeout)
        while True:
            remaining = max(0.1, deadline - time.monotonic())
            ptype, payload = _recv_packet(self.sock, remaining)
            if ptype == PayloadType.DIAGNOSTIC_MESSAGE:
                return parse_diagnostic_message(payload)
            if ptype == PayloadType.ALIVE_CHECK_REQUEST:
                self.sock.sendall(
                    build_packet(
                        PayloadType.ALIVE_CHECK_RESPONSE,
                        struct.pack("!H", self.source_address),
                    )
                )
            # 0x8002/0x8003 acks are intentionally skipped.

    def request(
        self, target_address: int, uds_payload: bytes, timeout: Optional[float] = None
    ) -> bytes:
        """Send a UDS request and return the UDS response payload."""
        self.send_diagnostic(target_address, uds_payload)
        _, _, response = self.recv_diagnostic(timeout)
        return response


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def discover(
    host: str = "<broadcast>", port: int = DOIP_PORT, timeout: float = 2.0
) -> List[VehicleAnnouncement]:
    """Broadcast a vehicle identification request and collect announcements.

    Pass ``host="127.0.0.1"`` to talk to a local :class:`DoipSimulator`.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if host == "<broadcast>":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            destinations = ["<broadcast>"]
        else:
            destinations = [host]
        sock.bind(("", 0))
        sock.settimeout(timeout)
        for dest in destinations:
            sock.sendto(build_vehicle_identification_request(), (dest, port))
        found: List[VehicleAnnouncement] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                break
            try:
                ptype, payload = parse_packet(data)
            except DoipError:
                continue
            if ptype == PayloadType.VEHICLE_ANNOUNCEMENT:
                found.append(VehicleAnnouncement.decode(payload))
        return found
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# simulator
# --------------------------------------------------------------------------- #
@dataclass
class DoipSimulator:
    """An in-process DoIP entity for offline practice and tests.

    Speaks vehicle identification over UDP and routing activation + UDS over
    TCP. ``start()`` binds both sockets to ephemeral ports so it never
    collides with a real (or privileged) port 13400.
    """

    vin: str = "WVWZZZ1JZXW000001"
    logical_address: int = 0x1000
    eid: bytes = b"\x01\x02\x03\x04\x05\x06"
    gid: bytes = b"\x11\x22\x33\x44\x55\x66"
    host: str = "127.0.0.1"
    timeout: float = 5.0
    tcp_port: int = 0
    udp_port: int = 0
    #: serve the TCP side over TLS (ISO 13400-2 secure diagnostics, usually 3496)
    tls: bool = False
    #: PEM strings; generated on the fly when ``tls`` is set and none supplied
    cert_pem: Optional[str] = field(default=None, repr=False)
    key_pem: Optional[str] = field(default=None, repr=False)
    _tcp: Optional[socket.socket] = field(default=None, repr=False)
    _udp: Optional[socket.socket] = field(default=None, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _threads: List[threading.Thread] = field(default_factory=list, repr=False)
    _tmpdir: Optional[str] = field(default=None, repr=False)
    _tls_ctx: object = field(default=None, repr=False)

    # -- TLS ---------------------------------------------------------------- #
    def _server_context(self) -> ssl.SSLContext:
        from .doip_tls import make_self_signed  # local: doip_tls imports doip too

        if not self.cert_pem or not self.key_pem:
            self.cert_pem, self.key_pem = make_self_signed(
                common_name=self.vin[:17] or "vehsec-gateway",
                san_dns=["gateway.local"],
                san_ip=[self.host] if self.host != "127.0.0.1" else ["127.0.0.1"],
            )
        self._tmpdir = tempfile.mkdtemp(prefix="vehsec-doip-tls-")
        cert_path = os.path.join(self._tmpdir, "gateway.pem")
        key_path = os.path.join(self._tmpdir, "gateway.key")
        with open(cert_path, "w", encoding="ascii") as handle:
            handle.write(self.cert_pem)
        with open(key_path, "w", encoding="ascii") as handle:
            handle.write(self.key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> "DoipSimulator":
        self._stop.clear()
        self._tls_ctx = self._server_context() if self.tls else None

        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((self.host, 0))
        self._udp.settimeout(0.2)
        self.udp_port = self._udp.getsockname()[1]

        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((self.host, 0))
        self._tcp.listen(4)
        self._tcp.settimeout(0.2)
        self.tcp_port = self._tcp.getsockname()[1]

        self._threads = [
            threading.Thread(target=self._udp_loop, daemon=True),
            threading.Thread(target=self._tcp_loop, daemon=True),
        ]
        for t in self._threads:
            t.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._tcp, self._udp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._tcp = self._udp = None
        self._tls_ctx = None
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    def __enter__(self) -> "DoipSimulator":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def announcement(self) -> VehicleAnnouncement:
        return VehicleAnnouncement(
            vin=self.vin,
            logical_address=self.logical_address,
            eid=self.eid,
            gid=self.gid,
        )

    # -- server loops ------------------------------------------------------- #
    def _udp_loop(self) -> None:
        sock = self._udp
        while sock is not None and not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                sock = self._udp
                continue
            try:
                ptype, _ = parse_packet(data)
            except DoipError:
                continue
            if ptype in (
                PayloadType.VEHICLE_ID_REQUEST,
                PayloadType.VEHICLE_ID_REQUEST_EID,
                PayloadType.VEHICLE_ID_REQUEST_VIN,
            ):
                try:
                    sock.sendto(
                        build_packet(PayloadType.VEHICLE_ANNOUNCEMENT, self.announcement.encode()),
                        addr,
                    )
                except OSError:
                    break

    def _tcp_loop(self) -> None:
        listener = self._tcp
        while listener is not None and not self._stop.is_set():
            try:
                conn, _ = listener.accept()
            except (socket.timeout, OSError):
                listener = self._tcp
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, raw_conn: socket.socket) -> None:
        conn: socket.socket = raw_conn
        try:
            if self._tls_ctx is not None:
                # A gateway that cannot complete the handshake must not take the
                # rest of the loop down with it.
                try:
                    conn = self._tls_ctx.wrap_socket(raw_conn, server_side=True)
                except (ssl.SSLError, OSError):
                    return
            conn.settimeout(self.timeout)
            source = None
            while not self._stop.is_set():
                try:
                    ptype, payload = _recv_packet(conn, self.timeout)
                except (DoipError, OSError):
                    return
                if ptype == PayloadType.ROUTING_ACTIVATION_REQUEST:
                    source = struct.unpack_from("!H", payload, 0)[0]
                    activation_type = payload[2] if len(payload) > 2 else 0x00
                    code = (
                        RoutingActivationCode.SUCCESS
                        if activation_type in (0x00, 0x01)
                        else RoutingActivationCode.UNSUPPORTED_ACTIVATION_TYPE
                    )
                    resp = (
                        struct.pack("!HH", source, self.logical_address)
                        + bytes([int(code)])
                        + b"\x00" * 4
                        + b"\x00" * 4
                    )
                    conn.sendall(build_packet(PayloadType.ROUTING_ACTIVATION_RESPONSE, resp))
                elif ptype == PayloadType.DIAGNOSTIC_MESSAGE:
                    src, dst, uds = parse_diagnostic_message(payload)
                    # Positive ack first, as a real gateway does.
                    conn.sendall(
                        build_packet(
                            PayloadType.DIAGNOSTIC_ACK,
                            struct.pack("!HH", src, dst) + b"\x00" + uds[:1],
                        )
                    )
                    conn.sendall(
                        build_packet(
                            PayloadType.DIAGNOSTIC_MESSAGE,
                            struct.pack("!HH", dst, src) + self._uds_response(uds),
                        )
                    )
                elif ptype == PayloadType.ALIVE_CHECK_REQUEST:
                    conn.sendall(
                        build_packet(
                            PayloadType.ALIVE_CHECK_RESPONSE, struct.pack("!H", source or 0)
                        )
                    )
                else:
                    conn.sendall(
                        build_packet(PayloadType.NEGATIVE_ACK, bytes([NackCode.UNKNOWN_PAYLOAD_TYPE]))
                    )
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # -- fake ECU ----------------------------------------------------------- #
    def _uds_response(self, req: bytes) -> bytes:
        """Minimal UDS responses so the DoIP round trip is meaningful."""
        if not req:
            return bytes([0x7F, 0x00, 0x13])
        service = req[0]
        if service == 0x10:  # diagnostic session control
            return bytes([0x50, req[1] if len(req) > 1 else 0x01, 0x00, 0x32, 0x01, 0xF4])
        if service == 0x22 and len(req) >= 3:  # read data by identifier
            did = (req[1] << 8) | req[2]
            if did == 0xF190:  # VIN
                return bytes([0x62, req[1], req[2]]) + self.vin.encode("ascii")
            return bytes([0x62, req[1], req[2]]) + b"\x00\x01\x02\x03"
        if service == 0x27 and len(req) >= 2:  # security access
            return bytes([0x67, req[1]]) + b"\xde\xad\xbe\xef"
        if service == 0x3E:  # tester present
            return bytes([0x7E, 0x00])
        if service == 0x11:  # ECU reset
            return bytes([0x51, req[1] if len(req) > 1 else 0x01])
        return bytes([0x7F, service, 0x11])  # service not supported
