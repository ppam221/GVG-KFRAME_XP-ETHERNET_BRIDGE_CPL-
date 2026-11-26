"""
NTv2 - Universal CPL bridge: WebSocket -> K-Frame (UDP handshake connection)
14.7.1 - 20.1.1
Reverse Coding....Nava
This revision replaces the "bare UDP datagram to a fixed port" transport with the real V14 UDP
session, ported from handshake-connection-class.cts / connection-manager.cts:

  1. Handshake 1  : main socket -> frame UDP 5000   (packets 1-6)
  2. Port announce: frame (UDP 5001) -> listener socket announces a dynamic comms port
  3. Handshake 2  : main socket -> dynamic port     (packets 12-17)
  4. Suite select : suite1a..suite4a command frames are sent on the dynamic port
  5. Heartbeat    : every 1 s, 5 missed -> connection dropped and re-established (supervisor)
  6. Commands      (crosspoint / auto / cut / macro) go to the dynamic port as DATA packets,
                   inbound data packets are ACKed.

  * HandshakeConnection  = one session to one suite (state machine, heartbeat, ACKs, commands)
  * ConnectionManager    = owns the sessions, creates / replaces / closes them and re-connects
                           automatically with back-off when a session drops
  * Changing the suite (UI SET_CONFIG) closes the old session and opens a new one that selects the
    new suite on the frame; the tally TCP stream (port 2012) is restarted for that suite as well.
  * Commands are refused with a clear error until the session is CONNECTED (never silently dropped).

Local UDP ports (main/listener) default to 6130/6131 for suite 1, 6132/6133 for suite 2, ...
Override with --ports 1=6130:6131,2=6132:6133 (suite=MAIN:LISTENER).

V100 additions
  * ME4 : M/E indices 0..4 are accepted (ME1-3 = 0-2, PGM = 3, ME4 = 4 - the same 5 addresses the ME-bus
          subscriptions already cover). The tally stream now also tracks the "ME4" VPE.
  * AUX bus routing        {"action": "aux", "aux": 1, "source": 12}
  * Transition / keyer rate {"action": "rate", "kind": "transition", "me": 0, "seconds": 1.0}
                            {"action": "rate", "kind": "keyer", "me": 0, "keyer": 1, "seconds": 0.5}
                            ("frames": n may be sent instead of "seconds"; seconds = n / fps)
  * Keyer on/off            {"action": "key", "me": 0, "keyer": 2, "state": true}   (keyers 1-8; ME 0-4)
                            decoded from captures: SET_EVENT EID 0x0044, DID 0x08000000 | ((keyer-1) << 4) | me,
                            data 01000000 = ON / 00000000 = OFF. Status replies carry the last commanded
                            state as "keys"; a key_set event is broadcast to every connected UI.
  * Frame rate for "frames" rates: --fps (default 30), changed at runtime with
                            {"action": "set_fps", "fps": 50}  or  {"action": "set_config", "config": {"fps": 60}}
                            or per command with {"action": "rate", ..., "frames": 25, "fps": 50} (one-shot).
                            The current value is reported as "fps" in bridge_config / config replies.
  AUX take and the rates are decoded from panel captures (constants above the protocol section):
    aux take : SET_EVENT EID 0x007E, DID 0x19000100 | (aux-1), data = source (u16) + 0x0001
    rates    : SET_PARAM PID 0x1150, flags 0x0600, data = float32 seconds,
               transition DID 0x03000000 | me, keyer DID 0x08000000 | ((keyer-1) << 4) | me
"""
import argparse
import asyncio
import json
import logging
import random
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

INITIAL_SERVER_PORT = 5000
PORT_ANNOUNCE_SERVER_PORT = 5001
TALLY_PORT = 2012
MODULE_VERSION = "20.1.1"
CONN_ID = "main"

# M/E indices accepted from the UI: 0-2 = ME1-ME3, 3 = PGM, 4 = ME4 (see ME-bus subscriptions / tally VPE names)
MAX_ME = 4
ME_LABELS = {0: "ME1", 1: "ME2", 2: "ME3", 3: "PGM", 4: "ME4"}


def me_label(me):
    return ME_LABELS.get(me, f"ME{me + 1}")


# AUX take (from panel captures): SET_EVENT EID 0x007E, DID 0x19000100 | (aux-1), data = source u16 + 0x0001
AUX_TAKE_EID = 0x007E
AUX_DID_BASE = 0x19000100
AUX_TAKE_FLAG = 0x0001
AUX_MAX = 48                   # captures verified for aux 1, 2, 5, 12, 24, 48

# Rate commands (from panel captures): SET_PARAM PID 0x1150, type flags 0x0600, data = float32 seconds (big endian)
#   transition rate : DID 0x03000000 | me
#   keyer rate      : DID 0x08000000 | ((keyer - 1) << 4) | me
RATE_PID = 0x1150
RATE_FLAGS = 0x0600
TRANS_RATE_DID_BASE = 0x03000000
KEYER_RATE_DID_BASE = 0x08000000
KEYER_MAX = 8                  # 8 keyers per M/E (confirmed by user)

# Keyer ON/OFF (from panel captures, M/E 1-4 keyers 1-4): SET_EVENT EID 0x0044 (same EID as CUT),
#   DID 0x08000000 | ((keyer - 1) << 4) | me, data = 4 bytes: 01 00 00 00 = ON, 00 00 00 00 = OFF
KEY_EID = 0x0044
KEY_DID_BASE = 0x08000000
RATE_MAX_SECONDS = 99.0        # 99 s maximum (confirmed by user)

# --------------------------------------------------------------------------- protocol constants
SUITE_COMMANDS = {
    1: [bytes.fromhex("0004017c000200060000000c0000001417960200010000070000000a"),
        bytes.fromhex("000407a700020005000000090000001004b600000100000700")],
    2: [bytes.fromhex("0004017a000200060000000c0000001417960200010000070000000c"),
        bytes.fromhex("000407a700020005000000090000001004b600000100000700")],
    3: [bytes.fromhex("0004017e000200060000000c0000001417960200010000070000000e"),
        bytes.fromhex("000407ab00020005000000090000001004b600000100000700")],
    4: [bytes.fromhex("000401f7000200060000000c00000014179602000100000700000010"),
        bytes.fromhex("000407ab00020005000000090000001004b600000100000700")],
}

PKT_1 = bytes([0x00, 0x06, 0x00, 0x00])           # also packet 12
PKT_ACK0 = bytes([0x00, 0x02, 0x00, 0x00])        # expected 2, 4, 13, 15 / heartbeat response / packet 8
PKT_HELLO = bytes([0x00, 0x01, 0x00, 0x00])       # packet 3, 14 / client heartbeat / expected 7
PKT_ACK1 = bytes([0x00, 0x02, 0x00, 0x01])        # expected 6, 17 / packet 10


def parse_module_version(value):
    """'20.1.1' or 'V20.1.1' -> '20.1.1' (the bridge adds the leading V itself). Letters, digits, . _ - only."""
    v = str(value or "").strip()
    if v[:1] in ("V", "v"):
        v = v[1:]
    if not v or len(v) > 24 or not v.isascii() or not all(ch.isalnum() or ch in "._-" for ch in v):
        raise ValueError(f"bad version '{value}' (use e.g. 20.1.1; letters, digits, . _ - only, max 24 chars)")
    return v


def _version_arg(value):
    try:
        return parse_module_version(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def sanitize_panel_name(name, default="NTv2", max_len=24):
    """Base panel name shown in the frame's panel connections: printable ASCII only, trimmed, max_len chars."""
    clean = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(name or "")).strip()
    return (clean[:max_len].strip()) or default


def build_set_param(pid, type_flags, did, data, msg_id):
    outer = 8 + len(data)
    return struct.pack(">HHHHIIHHI", 0x0004, msg_id, 0x0002, 0x0006, outer, outer + 8, pid, type_flags, did) + data


def build_set_event(eid, did, data=b"", msg_id=0):
    outer = 8 + len(data)
    return struct.pack(">HHHHIIHHI", 0x0004, msg_id, 0x0002, 0x0005, outer, outer + 7, eid, 0x0000, did) + data


def build_ack(msg):
    return struct.pack(">H", 0x0002) + msg[2:4]


def build_subscription_packet(seq, sub_id, pid, did):
    """Subscribe to parameter `pid` of object `did` (the frame then pushes its value on change)."""
    pkt = bytearray(52)
    struct.pack_into(">HHHHII", pkt, 0, 0x0004, seq, 0x0002, 0x0008, 0x24, 0x2E)
    struct.pack_into(">HHHHIHH", pkt, 32, sub_id, 0x0001, 0x0003, 0x0003, 0, pid, 0x0000)
    struct.pack_into(">I", pkt, 48, did)
    return bytes(pkt)


def build_me_subscription_packet(seq, sub_id, address):
    return build_subscription_packet(seq, sub_id, 0x104A, 0x04000000 | address)


# --------------------------------------------------------------------------- HandshakeConnection
class HandshakeConnection:
    """One V14 UDP session to one suite of the frame (non-blocking: threads do the work)."""

    def __init__(self, connection_id, host, suite, main_port=6130, listener_port=6131, on_status=None, *,
                 initial_port=INITIAL_SERVER_PORT, announce_port=PORT_ANNOUNCE_SERVER_PORT,
                 heartbeat_interval=1.0, handshake_timeout=10.0, max_missed=5, connected_delay=2.0,
                 post_connect_delay=3.4, client_name=None, aux_sub=True, aux_sub_pid=0x104A,
                 aux_count=48, log_rx=False, module_version=MODULE_VERSION):
        if suite not in SUITE_COMMANDS:
            raise ValueError(f"suite must be 1-4 (got {suite})")
        self.connection_id = connection_id
        self.host = socket.gethostbyname(host)
        self.suite = suite
        self.main_port = main_port
        self.listener_port = listener_port
        self.on_status = on_status
        self.initial_port = initial_port
        self.announce_port = announce_port
        self.heartbeat_interval = heartbeat_interval
        self.handshake_timeout = handshake_timeout
        self.max_missed = max_missed
        self.connected_delay = connected_delay
        self.post_connect_delay = post_connect_delay
        self.client_name = client_name or f"NTv2 - Suite {suite}"
        self.aux_sub = aux_sub            # subscribe to aux buses 1-48 to read their real sources (verified on a frame)
        self.aux_sub_pid = aux_sub_pid
        self.aux_count = aux_count
        self.module_version = parse_module_version(module_version)   # announced to the frame as 'V<version>'
        self.log_rx = log_rx              # log every inbound data packet (hex) to learn / verify formats
        self._aux_sub_ids = {}            # subscription id -> aux number
        self.aux_bus = {}                 # aux number -> source reported by the frame

        self._lock = threading.RLock()
        self.main_sock = None
        self.listener_sock = None
        self._threads = []

        self.stage = 1                    # 1 idle, 2..8 handshake, 9 established
        self.closing = False
        self.fully_connected = False
        self.announced_port = 0
        self.dynamic_port = 0

        self._next_p1 = 0.0
        self._handshake_deadline = None
        self._next_hb = 0.0
        self._missed = 0
        self._last_hb_resp = 0.0
        self._scheduled = []              # [(due_monotonic, fn)]

        self._last_aux_id = None
        self._next_macro_id = 0
        self._recent_macro_ids = deque(maxlen=50)
        self._macro_queue = deque()
        self._macro_busy = False
        self._last_macro_id = None

        self._sub_seq = 0x0300
        self._next_sub_id = 0x0400
        self._me_sub_ids = set()
        self.me_bus = {}                  # address byte -> source (A = 0x0m, B = 0x1m)

        name = self.client_name.encode("ascii", "replace") + b"\x00"
        outer = 4 + len(name)
        self._pkt5 = struct.pack(">HHHHIIHH", 4, 1, 2, 0x1F, outer, 0x2C, 1, 0) + name
        self._pkt16 = struct.pack(">HHHHII", 4, 1, 2, 0x1F, outer, 0x2C) + struct.pack(">H", 3) + b"\x00\x00" + name

    # ---- helpers
    def emit(self, typ, message=""):
        if self.on_status:
            try:
                self.on_status(self, typ, message)
            except Exception:
                logging.exception("status callback failed")

    def call_later(self, delay, fn):
        with self._lock:
            self._scheduled.append((time.monotonic() + delay, fn))

    @staticmethod
    def _open_socket(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if hasattr(socket, "SIO_UDP_CONNRESET"):      # Windows: ignore ICMP port-unreachable
                try:
                    s.ioctl(socket.SIO_UDP_CONNRESET, False)
                except (OSError, ValueError):
                    pass
            s.bind(("0.0.0.0", port))
            s.settimeout(0.5)
        except OSError:
            s.close()
            raise
        return s

    def _send(self, data, port, ip=None, sock=None):
        s = sock or self.main_sock
        if self.closing or s is None:
            return False, "socket closed"
        try:
            s.sendto(data, (ip or self.host, port))
            return True, "sent"
        except OSError as e:
            return False, f"UDP write failed: {e}"

    def _send_dyn(self, data, label=None):
        if not self.dynamic_port:
            return False, "no dynamic port yet"
        ok, msg = self._send(data, self.dynamic_port)
        if label:
            if ok:
                logging.info(f"[CPL TX UDP] {label} -> {self.host}:{self.dynamic_port} {data.hex()}")
            else:
                logging.warning(f"[CPL TX UDP] {label} FAILED: {msg}")
        return ok, msg

    # ---- lifecycle
    def start(self):
        """Bind both sockets and begin the handshake. Raises OSError if a port cannot be bound."""
        with self._lock:
            if self.closing:
                raise RuntimeError("connection already closed")
            main = self._open_socket(self.main_port)
            try:
                lst = self._open_socket(self.listener_port)
            except OSError:
                main.close()
                raise
            self.main_sock, self.listener_sock = main, lst
            self.main_port = main.getsockname()[1]
            self.listener_port = lst.getsockname()[1]
            self.emit("CONNECTING", f"Suite {self.suite}: starting handshake with {self.host} "
                                    f"(local {self.main_port}/{self.listener_port})")
            for target in (lambda: self._recv_loop(main, self._on_main),
                           lambda: self._recv_loop(lst, self._on_listener),
                           self._timer_loop):
                t = threading.Thread(target=target, daemon=True)
                self._threads.append(t)
                t.start()
            # stage must be 2 before packet 1 leaves, or a fast reply would be ignored
            self.stage = 2
            now = time.monotonic()
            self._next_p1 = now + 1.0
            self._handshake_deadline = now + self.handshake_timeout
            ok, err = self._send(PKT_1, self.initial_port)
            if not ok:
                self.emit("ERROR", f"Error sending packet 1: {err}")
        if not ok:
            self.cleanup()
            raise OSError(err)

    def cleanup(self):
        with self._lock:
            already = self.closing
            self.closing = True
            self.fully_connected = False
            socks = [self.main_sock, self.listener_sock]
            self.main_sock = self.listener_sock = None
            self._scheduled.clear()
            self._macro_queue.clear()
        for s in socks:
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        cur = threading.current_thread()
        for t in self._threads:
            if t is not cur:
                t.join(timeout=2.0)       # the ports are free again when this returns
        if not already:
            self.emit("DISCONNECTED", "Connection closed")

    # ---- worker threads
    def _recv_loop(self, sock, handler):
        while not self.closing:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue
            except OSError as e:
                if not self.closing:
                    self.emit("ERROR", f"socket error: {e}")
                    self.cleanup()
                return
            with self._lock:
                if self.closing:
                    return
                try:
                    handler(data, addr[0], addr[1])
                except Exception:
                    logging.exception("packet handler failed")

    def _timer_loop(self):
        while not self.closing:
            time.sleep(0.02)
            reason = None
            with self._lock:
                if self.closing:
                    return
                now = time.monotonic()
                if self.stage == 2 and now >= self._next_p1:
                    self._send(PKT_1, self.initial_port)
                    self._next_p1 = now + 1.0
                if self._handshake_deadline is not None and now >= self._handshake_deadline:
                    self._handshake_deadline = None
                    reason = ("HANDSHAKE_TIMEOUT_ERROR", "Couldn't connect (timeout)")
                if reason is None and self.stage == 9 and now >= self._next_hb:
                    self._missed += 1
                    if self._missed >= self.max_missed:
                        reason = ("HEARTBEAT_TIMEOUT", f"Connection lost after {self.max_missed} missed heartbeats.")
                    else:
                        self._send(PKT_HELLO, self.dynamic_port)
                        self._next_hb = now + self.heartbeat_interval
                if reason is None and self._scheduled:
                    due = [t for t in self._scheduled if t[0] <= now]
                    if due:
                        self._scheduled = [t for t in self._scheduled if t[0] > now]
                        for _, fn in sorted(due, key=lambda t: t[0]):
                            try:
                                fn()
                            except Exception:
                                logging.exception("scheduled task failed")
            if reason:
                self.emit(*reason)
                self.cleanup()
                return

    # ---- inbound: main socket (handshake + dynamic-port traffic)
    def _on_main(self, msg, src_ip, src_port):
        st = self.stage
        if st == 2 and src_port == self.initial_port and msg == PKT_ACK0:
            self.stage = 3
            self._send(PKT_HELLO, self.initial_port)
        elif st == 3 and src_port == self.initial_port and msg == PKT_ACK0:
            self.stage = 4
            self._send(self._pkt5, self.initial_port)
        elif st == 4 and src_port == self.initial_port and msg == PKT_ACK1:
            self.stage = 5
            if self.announced_port > 0:
                self.stage = 6
                self._send(PKT_1, self.announced_port)
        elif st == 6 and src_port == self.announced_port and msg == PKT_ACK0:
            self.dynamic_port = src_port
            self.stage = 7
            self._send(PKT_HELLO, self.dynamic_port)
        elif st == 7 and src_port == self.dynamic_port and msg == PKT_ACK0:
            self.stage = 8
            self._send(self._pkt16, self.dynamic_port)
        elif st == 8 and src_port == self.dynamic_port and msg == PKT_ACK1:
            self._handshake_deadline = None
            self.stage = 9
            self.emit("HANDSHAKE_COMPLETE", "Handshake complete, sending suite command...")
            self._send_suite_command()
            now = time.monotonic()
            self._last_hb_resp = 0.0
            self._missed = 0
            self._next_hb = now + self.heartbeat_interval
            self.call_later(self.post_connect_delay, self._start_me_subscriptions)
        elif st == 9 and src_port == self.dynamic_port:
            if len(msg) >= 4 and struct.unpack(">H", msg[:2])[0] in (0x0001, 0x0004, 0x0006):
                self._send(build_ack(msg), src_port, src_ip)
            if (self._last_macro_id is not None and len(msg) == 4 and msg[0] == 0x00 and msg[1] == 0x02
                    and msg[2] == 0x03 and msg[3] == self._last_macro_id):
                self.emit("MACRO_ACK", str(self._last_macro_id))
                self._last_macro_id = None
            elif msg == PKT_ACK0:
                if self._last_hb_resp == 0.0:
                    self._last_hb_resp = time.monotonic()
                    self.call_later(self.connected_delay, self._mark_connected)
                else:
                    self._last_hb_resp = time.monotonic()
                    self.emit("HEARTBEAT_ACK", "Heartbeat acknowledged.")
                self._missed = 0
            elif len(msg) > 4:
                self._handle_subscription_data(msg)

    # ---- inbound: listener socket (port announce + subscription data channel)
    def _on_listener(self, msg, src_ip, src_port):
        lst = self.listener_sock
        if src_port == self.announce_port:
            if msg == PKT_HELLO:
                self._send(PKT_ACK0, src_port, src_ip, sock=lst)
            elif len(msg) >= 20:
                new_port = struct.unpack(">H", msg[18:20])[0]
                if 0 < new_port < 65536:
                    self.announced_port = new_port
                    ok, _ = self._send(PKT_ACK1, src_port, src_ip, sock=lst)
                    if ok and self.stage == 5:
                        self.stage = 6
                        self._send(PKT_1, self.announced_port)
        elif src_ip == self.host:
            if len(msg) == 4 and msg == PKT_HELLO:
                self._send(PKT_ACK0, src_port, src_ip, sock=lst)
                self.emit("AUX_DATA_CHANNEL", f"Subscription data channel established on port {src_port}")
            elif len(msg) >= 4:
                if struct.unpack(">H", msg[:2])[0] in (0x0001, 0x0004, 0x0006):
                    self._send(build_ack(msg), src_port, src_ip, sock=lst)
                if len(msg) > 4:
                    self._handle_subscription_data(msg)

    # ---- session bring-up helpers
    def _send_suite_command(self):
        msgs = SUITE_COMMANDS[self.suite]
        ok, _ = self._send_dyn(msgs[0], f"SUITE {self.suite} SELECT")
        if ok and len(msgs) > 1:
            self.call_later(0.1, lambda: None if self.closing else self._send_dyn(msgs[1], f"SUITE {self.suite} SELECT (2)"))

    def _mark_connected(self):
        if self.stage == 9 and not self.closing:
            self.fully_connected = True
            self.emit("CONNECTED", "Heartbeat established.")
            self._announce_identity()

    def _announce_identity(self):
        now = time.localtime()
        build = f"{time.strftime('%b', now)} {now.tm_mday:2d} {now.tm_year}"
        stamp = time.strftime("%H:%M:%S", now)
        for pid, flags, did, data in (
                (0x2008, 0x0300, 0x01000001, b"\x00\x08"),
                (0x134F, 0x0800, 0x2F003001, f"V{self.module_version}\x00".encode()),
                (0x1350, 0x0800, 0x2F003001, f"{stamp}\x00".encode()),
                (0x1351, 0x0800, 0x2F003001, f"{build}\x00".encode())):
            self._send_dyn(build_set_param(pid, flags, did, data, self._unique_aux_id()))

    def _start_me_subscriptions(self):
        """Subscribe to the A and B buses of ME1-ME3, PGM and ME4 (10 packets, paced 50 ms apart)."""
        if self.closing or self.stage != 9:
            return
        addrs = [(bus << 4) | me for bus in (0, 1) for me in range(5)]
        for i, addr in enumerate(addrs):
            self.call_later(0.05 * i, lambda a=addr: self._send_me_subscription(a))
        if self.aux_sub:
            for aux in range(1, self.aux_count + 1):
                self.call_later(0.05 * (len(addrs) + aux - 1), lambda a=aux: self._send_aux_subscription(a))

    def _send_aux_subscription(self, aux):
        if self.closing or self.stage != 9:
            return
        sub_id, seq = self._next_sub_id, self._sub_seq
        self._next_sub_id += 1
        self._sub_seq += 1
        self._aux_sub_ids[sub_id] = aux
        self._send_dyn(build_subscription_packet(seq, sub_id, self.aux_sub_pid, AUX_DID_BASE | (aux - 1)))

    def _send_me_subscription(self, address):
        if self.closing or self.stage != 9:
            return
        sub_id, seq = self._next_sub_id, self._sub_seq
        self._next_sub_id += 1
        self._sub_seq += 1
        self._me_sub_ids.add(sub_id)
        self._send_dyn(build_me_subscription_packet(seq, sub_id, address))

    def _handle_subscription_data(self, msg):
        if self.log_rx:
            logging.info(f"[CPL RX UDP] {len(msg)}B {msg[:240].hex()}")
        try:
            off = 4
            while off + 12 <= len(msg):
                resp_type = struct.unpack(">H", msg[off + 2:off + 4])[0]
                pay_len = struct.unpack(">I", msg[off + 4:off + 8])[0]
                if off + 12 + pay_len > len(msg):
                    break
                if resp_type == 0x0010 and pay_len >= 22:
                    pb = off + 12
                    first = struct.unpack(">H", msg[pb:pb + 2])[0]
                    sig = struct.unpack(">H", msg[pb + 8:pb + 10])[0]
                    if first in self._aux_sub_ids:
                        aux = self._aux_sub_ids[first]
                        src = struct.unpack(">H", msg[pb + 20:pb + 22])[0]
                        if self.log_rx:
                            logging.info(f"[AUX SUB RX] aux {aux}: pid 0x{sig:04X} src {src} payload {msg[pb:pb + pay_len].hex()}")
                        if 0 < src <= 809 and self.aux_bus.get(aux) != src:
                            prev = self.aux_bus.get(aux)
                            self.aux_bus[aux] = src
                            self.emit("AUX_BUS", {"aux": aux, "source": src, "previous": prev})
                    if first in self._me_sub_ids and sig == 0x104A and msg[pb + 12] == 0x04:
                        addr = msg[pb + 15]
                        src = struct.unpack(">H", msg[pb + 20:pb + 22])[0]
                        if src > 0 and self.me_bus.get(addr) != src:
                            prev = self.me_bus.get(addr)
                            self.me_bus[addr] = src
                            self.emit("ME_BUS", {"address": addr, "source": src, "previous": prev})
                off += 12 + pay_len
        except Exception as e:
            self.emit("SUB_PARSE_ERROR", str(e))

    # ---- commands
    def _unique_aux_id(self):
        while True:
            c = random.randint(0, 0xFFFF)
            if c != self._last_aux_id:
                self._last_aux_id = c
                return c

    def ready(self):
        return (not self.closing) and self.stage == 9 and self.fully_connected

    def not_ready_message(self):
        if self.closing:
            return "Not connected (session closed, reconnecting...)"
        if self.stage == 9:
            return "Not connected (session established, waiting for first heartbeat...)"
        return f"Not connected (handshake stage {self.stage}/9 with {self.host})"

    def send_crosspoint(self, pid, did, source, label="XPT"):
        if not self.ready():
            return False, self.not_ready_message()
        if pid not in (0x104A, 0x103A):
            return False, "Invalid crosspoint PID."
        if not 1 <= source <= 809:
            return False, "Invalid source number (1-809)."
        frame = build_set_param(pid, 0x0100, did, struct.pack(">H", source), self._unique_aux_id())
        return self._send_dyn(frame, label)

    def send_set_param(self, pid, type_flags, did, data, label="SET"):
        """Generic SET_PARAM (used for aux routing and rates)."""
        if not self.ready():
            return False, self.not_ready_message()
        if not 0 <= pid <= 0xFFFF:
            return False, "Invalid parameter ID."
        return self._send_dyn(build_set_param(pid, type_flags, did, data, self._unique_aux_id()), label)

    def send_event(self, eid, did, data=b"", label="EVENT"):
        """Generic SET_EVENT (used for aux take)."""
        if not self.ready():
            return False, self.not_ready_message()
        if not 0 <= eid <= 0xFFFF:
            return False, "Invalid event ID."
        return self._send_dyn(build_set_event(eid, did, data, self._unique_aux_id()), label)

    def send_transition_event(self, eid, did, label="TRANS"):
        if not self.ready():
            return False, self.not_ready_message()
        if eid not in (0x0043, 0x0044):
            return False, "Invalid transition EID."
        return self._send_dyn(build_set_event(eid, did, b"", self._unique_aux_id()), label)

    def _next_unique_macro_id(self):
        for _ in range(256):
            cand = self._next_macro_id
            self._next_macro_id = (self._next_macro_id + 1) % 256
            if cand not in self._recent_macro_ids:
                break
        self._recent_macro_ids.append(cand)
        return cand

    def send_macro(self, number, label=None):
        if not self.ready():
            return False, self.not_ready_message()
        if not 1 <= number <= 999:
            return False, "Invalid macro number (1-999)."
        with self._lock:
            mid = self._next_unique_macro_id()
            payload = build_set_event(0x0002, 0x77000000, struct.pack(">HH", number - 1, 0), 0x0300 | mid)
            self._macro_queue.append((label or f"MACRO {number}", payload, mid))
            self._process_macro_queue()
        return True, "sent"

    def _process_macro_queue(self):
        if self._macro_busy or not self._macro_queue or self.closing or self.stage != 9:
            return
        label, payload, mid = self._macro_queue.popleft()
        self._macro_busy = True
        self._last_macro_id = mid
        ok, _ = self._send_dyn(payload, label)
        if not ok:
            self._last_macro_id = None
        self._scheduled.append((time.monotonic() + 0.05, self._macro_done))

    def _macro_done(self):
        self._macro_busy = False
        self._process_macro_queue()

    def info(self):
        return {"id": self.connection_id, "suite": self.suite, "host": self.host, "stage": self.stage,
                "connected": self.ready(), "ports": {"main": self.main_port, "listener": self.listener_port,
                                                     "dynamic": self.dynamic_port}}


# --------------------------------------------------------------------------- ConnectionManager
class ConnectionManager:
    """Owns the sessions. ensure_connection() also keeps the session alive (re-connect with back-off)."""

    def __init__(self, on_status=None):
        self.connections = {}
        self._desired = {}
        self._lock = threading.RLock()
        self.on_status = on_status
        self._stop = threading.Event()
        self._thread = None

    def _forward(self, conn, typ, message):
        if self.on_status and self.connections.get(conn.connection_id) is conn:
            self.on_status(conn, typ, message)

    def create_connection(self, cid, host, suite, ports=None, **kw):
        with self._lock:
            self.disconnect_connection(cid)
            main_port, listener_port = ports or (6130, 6131)
            conn = HandshakeConnection(cid, host, suite, main_port, listener_port, on_status=self._forward, **kw)
            self.connections[cid] = conn          # registered first so its own status events are forwarded
            try:
                conn.start()
            except OSError:
                self.connections.pop(cid, None)
                raise
            return conn

    def ensure_connection(self, cid, host, suite, ports=None, **kw):
        """Create the session now (raises OSError if a port cannot be bound) and keep it alive."""
        conn = self.create_connection(cid, host, suite, ports, **kw)
        with self._lock:
            self._desired[cid] = {"host": host, "suite": suite, "ports": ports, "kw": kw,
                                  "backoff": 2.0, "next_try": 0.0, "dead_seen": False}
            if self._thread is None or not self._thread.is_alive():
                self._stop.clear()
                self._thread = threading.Thread(target=self._supervise, daemon=True)
                self._thread.start()
        return conn

    def disconnect_connection(self, cid):
        with self._lock:
            conn = self.connections.get(cid)
            if conn:
                conn.cleanup()               # emits DISCONNECTED while still registered, so the UI hears it
                if self.connections.get(cid) is conn:
                    del self.connections[cid]

    def remove_connection(self, cid):
        with self._lock:
            self._desired.pop(cid, None)
        self.disconnect_connection(cid)

    def shutdown(self):
        self._stop.set()
        for cid in list(self.connections):
            self.remove_connection(cid)

    def get_connection(self, cid):
        return self.connections.get(cid)

    def get_connection_info(self, cid):
        c = self.connections.get(cid)
        return c.info() if c else None

    def _supervise(self):
        while not self._stop.wait(0.5):
            now = time.monotonic()
            with self._lock:
                for cid, d in list(self._desired.items()):
                    conn = self.connections.get(cid)
                    if conn is not None and not conn.closing:
                        if conn.fully_connected:
                            d["backoff"] = 2.0
                        d["dead_seen"] = False
                        continue
                    if not d["dead_seen"]:
                        d["dead_seen"] = True
                        d["next_try"] = now + d["backoff"]
                        d["backoff"] = min(d["backoff"] * 1.5, 10.0)
                        continue
                    if now < d["next_try"]:
                        continue
                    try:
                        logging.info(f"[CONNECTION] Re-connecting {cid} (suite {d['suite']}) to {d['host']}...")
                        self.create_connection(cid, d["host"], d["suite"], d["ports"], **d["kw"])
                        d["dead_seen"] = False
                    except OSError as e:
                        logging.warning(f"[CONNECTION] Re-connect failed: {e}")
                        d["next_try"] = now + d["backoff"]
                        d["backoff"] = min(d["backoff"] * 1.5, 10.0)


# --------------------------------------------------------------------------- bridge
def _etp(inner):
    return f"<ETP>{inner}</ETP>"


_TALLY_REQUESTS = ["Configuration-Request", "EngineeringSourceMap-Request", "LogicalSourceMap-Request",
                   "VPEInputMap-Request", "VPEOutputMap-Request", "OutputTallyMap-Request"]


class GVGCPLBridgeUDP:
    def __init__(self, host, suite=1, live=False, ports=None, name="NTv2", fps=30.0):
        self.host = host
        self.fps = float(fps)        # frames per second used to convert {"frames": n} rates
        self.module_version = MODULE_VERSION   # --version: the module version announced to the frame
        self.aux_state = {}          # aux number -> last commanded source
        self.rate_trans = {}         # me -> last commanded transition rate (seconds)
        self.rate_key = {}           # (me, keyer) -> last commanded keyer rate (seconds)
        self.key_state = {}          # (me, keyer) -> last commanded keyer on/off (bool)
        self.suite = suite
        self.live = live
        self.name = sanitize_panel_name(name)       # panel name = "<name> - Suite N"
        self.tally_port = TALLY_PORT
        self.event_callback = None

        self._lock = threading.RLock()
        self._tally_gen = 0          # bumping this tells the running tally thread to exit
        self._tally_sock = None
        self.tally_state = {}        # me_idx -> {"pgm": int, "pvw": int}
        self.me_bus = {}             # address byte -> source (from the UDP ME-bus subscriptions)

        # local UDP ports per suite: (main, listener)
        self.udp_ports = {s: (6130 + 2 * (s - 1), 6131 + 2 * (s - 1)) for s in (1, 2, 3, 4)}
        for s, p in (ports or {}).items():
            self.udp_ports[s] = p
        self.conn_kwargs = {}        # extra HandshakeConnection options (timings) - used by the tests
        self.manager = ConnectionManager(on_status=self._on_conn_status)

    # ------------------------------------------------------------------ config / status
    @property
    def main_port(self):
        return self.udp_ports[self.suite][0]

    @property
    def listener_port(self):
        return self.udp_ports[self.suite][1]

    def _conn(self):
        return self.manager.get_connection(CONN_ID)

    def set_fps(self, fps):
        """Change the frame rate used to convert {"frames": n} rates to seconds. True if it changed."""
        fps = parse_fps(fps)
        with self._lock:
            if fps == self.fps:
                return False
            logging.info(f"[CONFIG] frame rate {self.fps:g} -> {fps:g} fps")
            self.fps = fps
            return True

    def config_dict(self):
        conn = self._conn()
        return {"ip": self.host, "suite": self.suite, "name": self.name, "version": self.module_version,
                "panel_name": f"{self.name} - Suite {self.suite}",
                "tx_port": self.main_port, "rx_port": self.listener_port,      # UI field names (kept)
                "main_port": self.main_port, "listener_port": self.listener_port,
                "frame_port": INITIAL_SERVER_PORT, "tally_port": self.tally_port, "live": self.live,
                "fps": self.fps, "protocol": "udp-handshake", "stage": conn.stage if conn else 0,
                "connected": bool(conn and conn.ready())}

    def get_status(self, me):
        st = self.tally_state.get(me)
        conn = self._conn()
        return {"me": me, "suite": self.suite, "live": self.live, "known": st is not None,
                "pgm": st["pgm"] if st else None, "pvw": st["pvw"] if st else None,
                "bus_a": self.me_bus.get(me), "bus_b": self.me_bus.get(0x10 | me),
                "transition_rate": self.rate_trans.get(me),
                "keyer_rates": {k: v for (m, k), v in self.rate_key.items() if m == me},
                "aux": dict(self.aux_state),
                "keys": {k: v for (m, k), v in self.key_state.items() if m == me},   # last commanded, not read back
                "connected": bool(conn and conn.ready()), "stage": conn.stage if conn else 0}

    def _on_conn_status(self, conn, typ, message):
        if typ == "HEARTBEAT_ACK":
            return
        if typ == "AUX_BUS":
            self.aux_state[message["aux"]] = message["source"]
            if self.event_callback:
                self.event_callback({"event": "aux_routed", "aux": message["aux"], "source": message["source"],
                                     "suite": conn.suite, "from_frame": True})
            return
        if typ == "ME_BUS":
            self.me_bus[message["address"]] = message["source"]
            if self.event_callback:
                addr = message["address"]
                self.event_callback({"event": "me_bus", "me": addr & 0x0F, "bus": "b" if addr & 0x10 else "a",
                                     "source": message["source"], "suite": conn.suite})
            return
        level = logging.WARNING if typ in ("ERROR", "HANDSHAKE_TIMEOUT_ERROR", "HEARTBEAT_TIMEOUT") else logging.INFO
        logging.log(level, f"[CONNECTION] {typ}: {message}")
        if self.event_callback:
            self.event_callback({"event": "connection_status", "type": typ, "message": str(message),
                                 "suite": conn.suite, "stage": conn.stage, "connected": conn.ready(),
                                 "ip": conn.host})

    def _start_frame_connection(self):
        kw = dict(self.conn_kwargs)
        kw.setdefault("module_version", self.module_version)
        kw.setdefault("client_name", f"{self.name} - Suite {self.suite}")
        self.manager.ensure_connection(CONN_ID, self.host, self.suite, self.udp_ports[self.suite], **kw)

    def configure(self, ip=None, suite=None):
        """Change frame IP and/or suite at runtime. Returns True if something changed.
        Raises ValueError / OSError (state is rolled back) if the new settings cannot be applied."""
        new_suite = self.suite if suite is None else int(suite)
        if new_suite not in self.udp_ports:
            raise ValueError(f"suite must be 1-4 (got {suite})")
        new_host = self.host
        if ip is not None and str(ip).strip():
            new_host = socket.gethostbyname(str(ip).strip())   # also accepts plain IPs

        with self._lock:
            if new_suite == self.suite and new_host == self.host:
                return False

            old_host, old_suite = self.host, self.suite
            logging.info(f"[CONFIG] {old_host} suite {old_suite} -> {new_host} suite {new_suite}")

            self._tally_gen += 1               # old tally thread will exit
            self._close_tally_socket()
            self.tally_state = {}
            self.me_bus = {}
            self.aux_state, self.rate_trans, self.rate_key, self.key_state = {}, {}, {}, {}
            self.manager.remove_connection(CONN_ID)

            self.host, self.suite = new_host, new_suite
            if self.live:
                try:
                    self._start_frame_connection()
                except OSError:
                    # roll back so the bridge keeps working with the previous settings
                    self.host, self.suite = old_host, old_suite
                    try:
                        self._start_frame_connection()
                    except OSError as e2:
                        logging.error(f"[CONFIG] rollback failed: {e2}")
                    self.start_tally_listener()
                    raise
                self.start_tally_listener()
            return True

    def connect(self):
        if not self.live:
            return True
        try:
            with self._lock:
                self._start_frame_connection()
            return True
        except OSError as e:
            logging.error(f"[CPL UDP BIND ERROR] {e}")
            return False

    def shutdown(self):
        self.live = False
        self._tally_gen += 1
        self._close_tally_socket()
        self.manager.shutdown()

    # ------------------------------------------------------------------ commands (UI -> frame)
    def _dispatch(self, label, method, *args):
        if not self.live:
            logging.warning(f"[DRY-RUN UDP] {label}  (NOT sent - start the bridge with --live)")
            return True, "dry-run (NOT sent to frame)"
        conn = self._conn()
        if conn is None:
            return False, "No frame session (re-connecting...)"
        return getattr(conn, method)(*args, label=label)

    def send_crosspoint(self, me, side, src):
        addr = (0x10 if side == "b" else 0x00) | me
        return self._dispatch(f"XPT {me_label(me)} {side.upper()} SRC {src}", "send_crosspoint",
                              0x104A, 0x04000000 | addr, src)

    def send_transition(self, kind, me):
        eid = 0x0044 if kind == "cut" else 0x0043
        return self._dispatch(f"{kind.upper()} {me_label(me)}", "send_transition_event", eid, 0x03000000 | me)

    def send_aux(self, aux, src):
        """Route source `src` to aux bus number `aux` (1-based)."""
        if not 1 <= aux <= AUX_MAX:
            return False, f"Invalid aux number (1-{AUX_MAX})."
        ok, msg = self._dispatch(f"AUX {aux} TAKE SRC {src}", "send_event", AUX_TAKE_EID,
                                 AUX_DID_BASE | (aux - 1), struct.pack(">HH", src, AUX_TAKE_FLAG))
        if ok and self.live:
            self.aux_state[aux] = src
            if self.event_callback:
                self.event_callback({"event": "aux_routed", "aux": aux, "source": src, "suite": self.suite})
        return ok, msg

    def send_key(self, me, keyer, state):
        """Turn keyer `keyer` (1-8) of M/E `me` on or off."""
        if not 1 <= keyer <= KEYER_MAX:
            return False, f"Invalid keyer number (1-{KEYER_MAX})."
        state = bool(state)
        did = KEY_DID_BASE | ((keyer - 1) << 4) | me
        ok, msg = self._dispatch(f"KEY{keyer} {'ON' if state else 'OFF'} {me_label(me)}", "send_event",
                                 KEY_EID, did, bytes([1 if state else 0, 0, 0, 0]))
        if ok and self.live:
            self.key_state[(me, keyer)] = state
            if self.event_callback:
                self.event_callback({"event": "key_set", "me": me, "keyer": keyer, "state": state,
                                     "suite": self.suite})
        return ok, msg

    def send_rate(self, kind, me, seconds, keyer=1):
        """Set the transition rate (kind='transition') or a keyer's rate (kind='keyer'), in seconds."""
        if not 0.0 <= seconds <= RATE_MAX_SECONDS:
            return False, f"Invalid rate (0-{RATE_MAX_SECONDS:g} seconds)."
        if kind == "keyer":
            if not 1 <= keyer <= KEYER_MAX:
                return False, f"Invalid keyer number (1-{KEYER_MAX})."
            did = KEYER_RATE_DID_BASE | ((keyer - 1) << 4) | me
            label = f"KEY{keyer} RATE {me_label(me)} = {seconds:g}s"
        else:
            did = TRANS_RATE_DID_BASE | me
            label = f"TRANS RATE {me_label(me)} = {seconds:g}s"
        ok, msg = self._dispatch(label, "send_set_param", RATE_PID, RATE_FLAGS, did, struct.pack(">f", seconds))
        if ok and self.live:
            if kind == "keyer":
                self.rate_key[(me, keyer)] = seconds
            else:
                self.rate_trans[me] = seconds
            if self.event_callback:
                self.event_callback({"event": "rate_set", "kind": kind, "me": me,
                                     "keyer": keyer if kind == "keyer" else None,
                                     "seconds": seconds, "suite": self.suite})
        return ok, msg

    def send_macro(self, number):
        """Run macro `number` (1-999)."""
        return self._dispatch(f"MACRO {number}", "send_macro", number)

    # ------------------------------------------------------------------ tally (TCP 2012)
    def start_tally_listener(self):
        if not self.live:
            return
        with self._lock:
            gen = self._tally_gen
        threading.Thread(target=self._tally_stream_loop, args=(gen,), daemon=True).start()

    def _close_tally_socket(self):
        s, self._tally_sock = self._tally_sock, None
        if s:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _tally_stream_loop(self, gen):
        vpe_map = {"ME1": 0, "ME2": 1, "ME3": 2, "PGM": 3, "ME4": 4}

        def current():
            return self.live and gen == self._tally_gen

        while current():
            sock = None
            try:
                with self._lock:
                    host, suite, port = self.host, self.suite, self.tally_port
                logging.info(f"[TALLY STREAM] Connecting to {host}:{port} (TCP), suite {suite}...")
                sock = socket.create_connection((host, port), timeout=5.0)
                with self._lock:
                    if gen != self._tally_gen:        # config changed while connecting
                        sock.close()
                        return
                    self._tally_sock = sock
                sock.sendall(_etp(
                    f"<Authentication-Request><Protocol>NT ETH POLLING</Protocol>"
                    f"<ProtocolVersion>3.0</ProtocolVersion><AppName>NT UDP Tally</AppName>"
                    f"<AppVersion>9.9</AppVersion><Suite>{suite}</Suite></Authentication-Request>"
                ).encode("ascii"))

                subscribed = False
                buf = ""
                inputs = {i: {} for i in range(MAX_ME + 1)}
                outs = {i: {} for i in range(MAX_ME + 1)}

                sock.settimeout(5.0)   # lets us notice a suite change; a timeout is not a disconnect
                while current():
                    try:
                        data = sock.recv(16384)
                    except socket.timeout:
                        continue
                    if not data:
                        raise OSError("Tally connection closed")
                    buf += data.decode("ascii", "replace")
                    if len(buf) > 4_000_000:          # runaway buffer guard
                        buf = ""
                    while True:
                        s = buf.find("<ETP>")
                        if s < 0:
                            buf = ""
                            break
                        e = buf.find("</ETP>", s)
                        if e < 0:
                            buf = buf[s:]
                            break
                        pkt, buf = buf[s:e + 6], buf[e + 6:]
                        try:
                            root = ET.fromstring(pkt)
                        except ET.ParseError:
                            continue

                        changed_mes = set()
                        for el in root:
                            if el.tag == "Authentication" and not subscribed:
                                subscribed = True
                                for r in _TALLY_REQUESTS:
                                    sock.sendall(_etp(f"<{r}/>").encode("ascii"))
                                sock.sendall(_etp(
                                    f'<TallySubscription-Request><Suite Method="Replace">{suite}</Suite>'
                                    f'</TallySubscription-Request>'
                                ).encode("ascii"))
                                logging.info(f"[TALLY STREAM] Subscribed to real-time TCP stream (suite {suite})")
                            elif el.tag == "VPEInputContribution":
                                for vpe in el.findall("VPE"):
                                    vname = vpe.attrib.get("Name", "").upper()
                                    if vname not in vpe_map: continue
                                    me_idx = vpe_map[vname]
                                    for i in vpe.findall("Input"):
                                        try:
                                            inputs[me_idx][i.attrib.get("Name", "").lower()] = int((i.text or "").strip())
                                        except ValueError: pass
                                    changed_mes.add(me_idx)
                            elif el.tag == "VPEOutputContribution":
                                for vpe in el.findall("VPE"):
                                    vname = vpe.attrib.get("Name", "").upper()
                                    if vname not in vpe_map: continue
                                    me_idx = vpe_map[vname]
                                    for o in vpe.findall("Output"):
                                        outs[me_idx][o.attrib.get("Name", "").lower()] = {
                                            (c.text or "").strip().lower() for c in o if (c.text or "").strip()
                                        }
                                    changed_mes.add(me_idx)

                        for me_idx in changed_mes:
                            a = inputs[me_idx].get("bkgda")
                            b = inputs[me_idx].get("bkgdb")
                            onair = outs[me_idx].get("pgma", set())
                            pgm, pvw = (b, a) if ("bkgdb" in onair and "bkgda" not in onair) else (a, b)
                            if pgm is None or not current():
                                continue
                            cur = {"pgm": pgm, "pvw": pvw}
                            prev = self.tally_state.get(me_idx)
                            if prev == cur:
                                continue
                            self.tally_state[me_idx] = cur
                            logging.info(f"[TALLY STREAM] {me_label(me_idx)}: PGM={pgm} PVW={pvw}")
                            if self.event_callback:
                                self.event_callback({
                                    "event": "tally_change",
                                    "me": me_idx,
                                    "pgm": pgm,
                                    "pvw": pvw,
                                    "initial": prev is None,
                                    "suite": suite
                                })
            except OSError as e:
                if current():
                    logging.warning(f"[TALLY STREAM] Disconnected ({e}); reconnecting...")
            except Exception as e:  # never let the tally thread die silently
                logging.exception(f"[TALLY STREAM] Unexpected error: {e}")
            finally:
                with self._lock:
                    if self._tally_sock is sock:
                        self._tally_sock = None
                if sock:
                    try: sock.close()
                    except OSError: pass
            if not current():
                return
            time.sleep(3.0)


# --------------------------------------------------------------------------- WebSocket layer
def parse_ports(spec):
    """'1=6130:6131,2=6132:6133' -> {1: (6130, 6131), 2: (6132, 6133)}  (suite=MAIN:LISTENER)."""
    out = {}
    if not spec:
        return out
    for item in spec.split(","):
        suite_s, _, pair = item.strip().partition("=")
        main_s, _, lst_s = pair.partition(":")
        suite, main, lst = int(suite_s), int(main_s), int(lst_s)
        if suite not in (1, 2, 3, 4) or not (1 <= main <= 65535 and 1 <= lst <= 65535) or main == lst:
            raise ValueError(f"bad --ports entry '{item}'")
        out[suite] = (main, lst)
    return out


def parse_fps(value):
    """Validate a frame rate (frames per second): finite number, 1-240."""
    try:
        fps = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"fps must be a number (got {value!r})")
    if not (fps == fps and 1.0 <= fps <= 240.0):      # also rejects NaN
        raise ValueError(f"fps must be 1-240 (got {value!r})")
    return fps


def parse_on_off(value):
    """True/False from true/false, 1/0 or 'on'/'off' (anything else, including a missing value, is an error)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("on", "true", "1", "off", "false", "0"):
        return value.strip().lower() in ("on", "true", "1")
    raise ValueError(f"state must be on/off or true/false (got {value!r})")


def _int_in_range(data, key, lo, hi, default=None):
    if key not in data and default is not None:
        v = default
    else:
        v = int(data[key])
    if not lo <= v <= hi:
        raise ValueError(f"{key} must be {lo}-{hi} (got {v})")
    return v


async def handle_message(raw, bridge):
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("message must be a JSON object")
        action = data.get("action")

        # ---- runtime configuration (frame IP / suite) ----
        if data.get("type") == "SET_CONFIG" or action == "set_config":
            cfg = data.get("config") or data
            try:
                new_fps = parse_fps(cfg["fps"]) if cfg.get("fps") is not None else None   # validate first
                changed = await asyncio.to_thread(bridge.configure, cfg.get("ip"), cfg.get("suite"))
                if new_fps is not None:
                    changed = bridge.set_fps(new_fps) or changed
            except (ValueError, OSError) as e:
                # config is rolled back; tell the UI what the bridge is actually using
                return {"status": "error", "action": "set_config",
                        "message": f"{e}", "config": bridge.config_dict()}
            return {"status": "success", "action": "set_config", "changed": changed,
                    "message": ("Config applied" if changed else "Config unchanged"),
                    "config": bridge.config_dict()}

        # ---- frame rate used for {"frames": n} rates: {"action": "set_fps", "fps": 50} ----
        if action == "set_fps":
            if data.get("fps") is None:
                raise ValueError("fps is required")
            changed = bridge.set_fps(data["fps"])
            return {"status": "success", "action": "set_fps", "changed": changed, "fps": bridge.fps,
                    "message": f"Frame rate {bridge.fps:g} fps", "config": bridge.config_dict()}

        # ---- real PGM/PVW status for one M/E (from the tally stream cache) ----
        if action == "status":
            me = _int_in_range(data, "me", 0, MAX_ME, default=0)
            return {"status": "success", "action": "status", "message": "ok",
                    "data": bridge.get_status(me)}

        # ---- telemetry from the UI: nothing to do on this bridge, no reply needed ----
        if action == "remote_record_state":
            return None

        if action == "crosspoint":
            me = _int_in_range(data, "me", 0, MAX_ME, default=0)
            src = _int_in_range(data, "source", 1, 809)
            side = "a" if str(data.get("bus", "pgm")).lower() in ("pgm", "a") else "b"
            ok, msg = await asyncio.to_thread(bridge.send_crosspoint, me, side, src)
        elif action == "transition":
            me = _int_in_range(data, "me", 0, MAX_ME, default=0)
            kind = str(data.get("type", "cut")).lower()
            if kind not in ("cut", "auto", "autotrans"):
                raise ValueError(f"unknown transition type '{kind}'")
            kind = "cut" if kind == "cut" else "auto"
            ok, msg = await asyncio.to_thread(bridge.send_transition, kind, me)
        elif action in ("aux", "aux_route"):
            aux = _int_in_range(data, "aux", 1, AUX_MAX)
            src = _int_in_range(data, "source", 1, 809)
            ok, msg = await asyncio.to_thread(bridge.send_aux, aux, src)
        elif action in ("key", "keyer"):
            me = _int_in_range(data, "me", 0, MAX_ME, default=0)
            keyer = _int_in_range(data, "keyer", 1, KEYER_MAX)
            ok, msg = await asyncio.to_thread(bridge.send_key, me, keyer, parse_on_off(data.get("state")))
        elif action == "rate":
            kind = str(data.get("kind", "transition")).lower()
            if kind not in ("transition", "keyer"):
                raise ValueError(f"unknown rate kind '{kind}'")
            me = _int_in_range(data, "me", 0, MAX_ME, default=0)
            if "frames" in data:
                fps = parse_fps(data["fps"]) if data.get("fps") is not None else bridge.fps   # one-shot override
                seconds = float(data["frames"]) / fps
            else:
                seconds = float(data["seconds"])
            keyer = _int_in_range(data, "keyer", 1, KEYER_MAX, default=1)
            ok, msg = await asyncio.to_thread(bridge.send_rate, kind, me, seconds, keyer)
        elif action == "macro":
            mac = _int_in_range(data, "macro", 1, 999)
            ok, msg = await asyncio.to_thread(bridge.send_macro, mac)
        else:
            return {"status": "ignored", "action": action, "message": "unsupported action"}

        return {"status": "success" if ok else "error", "action": action, "message": msg}
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as e:
        logging.warning(f"[WS] rejected message: {e}")
        return {"status": "error", "action": None, "message": str(e)}


async def serve(args):
    import websockets
    loop = asyncio.get_running_loop()
    ws_clients = set()

    bridge = GVGCPLBridgeUDP(args.ip, suite=args.suite, live=args.live, ports=parse_ports(args.ports),
                             name=args.name, fps=args.fps)
    bridge.module_version = args.version
    logging.info(f"Module version announced to the frame: V{bridge.module_version}")
    logging.info(f"Panel name shown in the frame: '{bridge.name} - Suite {bridge.suite}'")
    logging.info("Local UDP ports (suite: main/listener): " +
                 ", ".join(f"{s}: {p[0]}/{p[1]}" for s, p in sorted(bridge.udp_ports.items())))

    def broadcast_event_from_thread(payload_dict):
        msg_str = json.dumps(payload_dict)
        async def _send_all():
            for ws in list(ws_clients):
                try: await ws.send(msg_str)
                except Exception: pass
        loop.call_soon_threadsafe(lambda: asyncio.create_task(_send_all()))

    bridge.event_callback = broadcast_event_from_thread
    bridge.conn_kwargs.update(aux_sub=not args.no_aux_sub, aux_sub_pid=args.aux_sub_pid, aux_count=AUX_MAX, log_rx=args.log_rx)

    async def ws_handler(websocket, *_):
        ws_clients.add(websocket)
        try:
            # tell the UI what the bridge is really using (suite / IP / live or dry-run / session state)
            await websocket.send(json.dumps({"event": "bridge_config", **bridge.config_dict()}))
            async for message in websocket:
                reply = await handle_message(message, bridge)
                if reply is None:
                    continue
                await websocket.send(json.dumps(reply))
                if reply.get("action") in ("set_config", "set_fps") and reply.get("status") == "success" and reply.get("changed"):
                    broadcast_event_from_thread({"event": "bridge_config", **bridge.config_dict()})
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            ws_clients.discard(websocket)

    if args.live:
        if not bridge.connect():
            raise SystemExit(f"Cannot bind local UDP ports {bridge.main_port}/{bridge.listener_port}; "
                             f"is another copy of the bridge (or Companion) running?")
        bridge.start_tally_listener()

    try:
        async with websockets.serve(ws_handler, args.ws_host, args.ws_port, origins=None):
            logging.info(f"NT UNIVERSAL UDP Bridge listening on ws://{args.ws_host}:{args.ws_port} "
                         f"({'LIVE' if args.live else 'DRY-RUN'}, suite {bridge.suite})")
            await asyncio.Future()
    finally:
        bridge.shutdown()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--suite", type=int, choices=[1, 2, 3, 4], default=1)
    ap.add_argument("--ws-host", default="0.0.0.0")
    ap.add_argument("--ws-port", type=int, default=8765)
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--name", default="NTv2",
                    help="panel name shown in the frame's panel connections, sent as '<name> - Suite N' "
                         "(use a different name per bridge, max 24 printable ASCII chars)")
    ap.add_argument("--ports", default="",
                    help="local UDP ports per suite as suite=MAIN:LISTENER, e.g. --ports 1=6130:6131,2=6132:6133")
    ap.add_argument("--fps", type=float, default=30.0,
                    help="frame rate used to convert {\"frames\": n} transition/keyer rates to seconds (default 30)")
    ap.add_argument("--version", "--Version", dest="version", default=MODULE_VERSION, type=_version_arg,
                    help=f"module version announced to the frame, e.g. --version 20.1.1 (default {MODULE_VERSION}); "
                         f"sent as 'V<version>'")
    ap.add_argument("--aux-sub", action="store_true", help="(default now; kept so old launch scripts still work)")
    ap.add_argument("--no-aux-sub", action="store_true",
                    help="do not subscribe to the aux buses (the UI then only shows the last aux route it sent)")
    ap.add_argument("--aux-sub-pid", type=lambda v: int(v, 0), default=0x104A,
                    help="parameter ID used for the aux subscriptions (default 0x104A - unverified)")
    ap.add_argument("--log-rx", action="store_true",
                    help="log every inbound data packet from the frame (hex), to capture / verify formats")
    ap.add_argument("--log-file", default="",
                    help="also write the log (including --log-rx packets) to this file, e.g. aux_capture.log")
    args = ap.parse_args()
    if args.log_file:
        _fh = logging.FileHandler(args.log_file, encoding="utf-8")
        _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logging.getLogger().addHandler(_fh)
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        logging.info("Bridge stopped (Ctrl+C).")
