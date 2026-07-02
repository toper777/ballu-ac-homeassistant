"""
syncleo UDP protocol client for Ballu AC (devtype=20, protocol=3).

Fully reverse-engineered on fw=1.22, model=ballu_platinum_evolution.

Write commands:
  0x01  Mode/Power  0=off 1=auto 2=cool 3=dry 4=heat 5=fan_only
  0x02  SetTemp     [temp_c, 0x00]  range 16..30
  0x0f  FanSpeed    0=auto 1=low 2=medium 3=high
  0x18  Ionizer     0=off 1=on
  0x1c  Display     0=off 1=on
  0x31  Turbo       0=off 1=on
  0x32  Night       0=off 1=on
  0x42  Swing+Eco   [0x00, v_swing, h_swing, eco, 0x00]
  0x42  Quiet       [0x01, 0x00, quiet]

Read-only (pushed by device):
  0x14  RoomTemp    u8 degrees C
  0x03/0x09/0x1e/0x26/0x29  unknown status fields (always 0)
  0x1f  Capabilities bitmask (0xff)
  0x85/0x87/0x88  HW/Net/Sys info
  0x91  DiagData
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import cryptography.hazmat.primitives._serialization as srlz

_LOGGER = logging.getLogger(__name__)


def _diag(msg: str, *args) -> None:
    """Verbose protocol trace at DEBUG level.

    Silent by default. Enable in configuration.yaml when troubleshooting:

        logger:
          logs:
            custom_components.ballu_ac: debug
    """
    _LOGGER.debug(msg, *args)


# ── crypto ────────────────────────────────────────────────────────────────────

def _rotate(buf: bytes, n: int) -> bytes:
    n = n % len(buf)
    return buf[n:] + buf[:n]


def prepare_keys(device_pubkey_hex: str):
    """X25519 ECDH key exchange. Returns (our_pubkey_bytes, encinkey, encoutkey)."""
    priv = X25519PrivateKey.generate()
    our_pub = bytes(reversed(priv.public_key().public_bytes(
        encoding=srlz.Encoding.Raw, format=srlz.PublicFormat.Raw)))
    dev_pub = X25519PublicKey.from_public_bytes(
        bytes(reversed(bytes.fromhex(device_pubkey_hex))))
    shared = bytes(reversed(priv.exchange(dev_pub)))
    h = hashes.Hash(hashes.SHA256())
    h.update(shared)
    sha = h.finalize()
    return our_pub, sha[:16], sha[16:]


def _enc(key: bytes, iv: bytes, pt: bytes) -> bytes:
    padder = PKCS7(128).padder()
    padded = padder.update(pt) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _enc_nopad(key: bytes, iv: bytes, pt: bytes) -> bytes:
    """AES-CBC encrypt WITHOUT PKCS7 padding (pt must be a multiple of 16).

    Used for the handshake token: it is exactly 16 bytes (one block), and the
    device expects it encrypted with no extra padding block. Adding PKCS7 here
    (as _enc does) appends a full 16-byte pad block, making the handshake 16
    bytes too long — the device then silently ignores it.
    """
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(pt) + enc.finalize()


def _dec(key: bytes, iv: bytes, ct: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    unpad = PKCS7(128).unpadder()
    return unpad.update(pt) + unpad.finalize()


# ── frame builders ─────────────────────────────────────────────────────────────

def build_handshake(our_pub: bytes, encinkey: bytes, encoutkey: bytes,
                    token: bytes) -> bytes:
    # Token is encrypted WITHOUT PKCS7 padding (it is exactly one 16-byte AES
    # block). This matches tools/ballu_cmd.py and the device's expectation.
    enc_tok = _enc_nopad(encoutkey, encinkey, token)
    payload = bytes([0]) + our_pub + enc_tok
    return struct.pack('<BBH', 0, 1, len(payload)) + payload


def build_ack(seq: int, encinkey: bytes, encoutkey: bytes) -> bytes:
    j, k = seq & 0xF, (seq >> 4) & 0xF
    ct = _enc(_rotate(encoutkey, j), _rotate(encinkey, k), bytes([seq]))
    return struct.pack('<BBH', seq, 0, len(ct)) + ct


def build_cmd(seq: int, cmd_type: int, data: bytes,
              encinkey: bytes, encoutkey: bytes) -> bytes:
    j, k = seq & 0xF, (seq >> 4) & 0xF
    ct = _enc(_rotate(encoutkey, j), _rotate(encinkey, k),
              bytes([seq, cmd_type]) + data)
    return struct.pack('<BBH', seq, 1, len(ct)) + ct


def decrypt_frame(data: bytes, encinkey: bytes, encoutkey: bytes):
    """Returns (seq, ftype_str, cmd_type_or_None, payload) or None."""
    if len(data) < 4:
        return None
    seq, ftype, length = struct.unpack('<BBH', data[:4])
    if len(data) != 4 + length:
        return None
    payload = data[4:]
    if ftype == 0:
        return seq, 'ACK', None, payload
    if ftype == 3:
        return seq, 'NAK', None, payload
    if ftype != 1:
        return seq, f'UNK{ftype}', None, payload
    j, k = seq & 0xF, (seq >> 4) & 0xF
    try:
        pt = _dec(_rotate(encinkey, j), _rotate(encoutkey, k), payload)
    except Exception as e:
        # Malformed/undecryptable frame (or spoofed traffic). Keep at DEBUG so a
        # flood of junk UDP packets can't spam the log (log-spam DoS).
        _diag('decrypt error seq=%d: %s', seq, e)
        return None
    if len(pt) < 2 or pt[0] != seq:
        return None
    return seq, 'CMD', pt[1], pt[2:]


# ── device state ──────────────────────────────────────────────────────────────

@dataclass
class ACState:
    """
    Current state of the AC unit, derived from device CMD messages.

    mode='off' means the unit is off. mode=None means not yet received.
    All boolean fields default to None (not yet received from device).
    """

    mode:      Optional[str]  = None   # cmd 0x01: off/auto/cool/dry/heat/fan_only
    set_temp:  Optional[int]  = None   # cmd 0x02: 16..30 °C
    room_temp: Optional[int]  = None   # cmd 0x14: measured °C (read-only)
    fan:       Optional[str]  = None   # cmd 0x0f: auto/low/medium/high
    v_swing:   Optional[bool] = None   # cmd 0x42 [0x00] byte[1]: vertical louver swing
    h_swing:   Optional[bool] = None   # cmd 0x42 [0x00] byte[2]: horizontal louver swing
    eco:       Optional[bool] = None   # cmd 0x42 [0x00] byte[3]: economy mode
    quiet:     Optional[bool] = None   # cmd 0x42 [0x01] byte[2]: quiet mode
    turbo:     Optional[bool] = None   # cmd 0x31
    night:     Optional[bool] = None   # cmd 0x32
    ionizer:   Optional[bool] = None   # cmd 0x18
    display:   Optional[bool] = None   # cmd 0x1c

    MODES = {0: 'off', 1: 'auto', 2: 'cool', 3: 'dry', 4: 'heat', 5: 'fan_only'}
    FANS  = {0: 'auto', 1: 'low', 2: 'medium', 3: 'high'}

    @property
    def is_on(self) -> bool:
        return self.mode not in (None, 'off')

    def apply_cmd(self, cmd_type: int, data: bytes) -> bool:
        """Update state from a device CMD. Returns True if anything changed."""
        before = (self.mode, self.set_temp, self.room_temp, self.fan,
                  self.v_swing, self.h_swing, self.eco, self.quiet,
                  self.turbo, self.night, self.ionizer, self.display)

        if cmd_type == 0x01 and data:
            self.mode = self.MODES.get(data[0], f'?{data[0]}')
        elif cmd_type == 0x02 and data:
            self.set_temp = data[0]
        elif cmd_type == 0x0f and data:
            self.fan = self.FANS.get(data[0], f'?{data[0]}')
        elif cmd_type == 0x14 and data:
            self.room_temp = data[0]
        elif cmd_type == 0x18 and data:
            self.ionizer = bool(data[0])
        elif cmd_type == 0x1c and data:
            self.display = bool(data[0])
        elif cmd_type == 0x31 and data:
            self.turbo = bool(data[0])
        elif cmd_type == 0x32 and data:
            self.night = bool(data[0])
        elif cmd_type == 0x42 and data:
            b = list(data) + [0] * 5
            if b[0] == 0x00:    # swing + eco subtype
                self.v_swing = bool(b[1])
                self.h_swing = bool(b[2])
                self.eco     = bool(b[3])
            elif b[0] == 0x01:  # quiet subtype
                self.quiet = bool(b[2])

        after = (self.mode, self.set_temp, self.room_temp, self.fan,
                 self.v_swing, self.h_swing, self.eco, self.quiet,
                 self.turbo, self.night, self.ionizer, self.display)
        return before != after


# ── async client ──────────────────────────────────────────────────────────────

class SyncleoClient:
    """
    Async UDP client for a single Ballu AC device.

    Each physical AC unit should have its own SyncleoClient instance,
    created from its config entry (host, port, token, pubkey).

    Multiple HA entities share the same client and register callbacks
    via register_state_callback(). All callbacks are fired on state change.
    """

    PING_INTERVAL        = 10.0  # keepalive interval, seconds
    HANDSHAKE_TIMEOUT    = 5.0
    KEEPALIVE_MISS_LIMIT = 3     # consecutive unanswered pings → connection lost

    def __init__(self, host: str, port: int, token_hex: str, pubkey_hex: str):
        self.host       = host
        self.port       = port
        self.token      = bytes.fromhex(token_hex)
        self.pubkey_hex = pubkey_hex

        self.state = ACState()

        # Device info parsed from the handshake response (cmd=0x00).
        # Populated after connect(); None until the handshake completes.
        self.proto:      Optional[int] = None
        self.fw_version: Optional[str] = None

        self._our_pub: bytes = b''
        self._ink:     bytes = b''   # encinkey
        self._outk:    bytes = b''   # encoutkey
        self._outseq   = 0
        self._acked:   set[int] = set()
        self._pending: set[int] = set()
        self._connected = False
        self._hs_done   = False
        self._rx_count  = 0   # datagrams received (debug)
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._callbacks: list[Callable[[ACState], None]] = []
        # Optional callback fired once when the link is considered lost
        # (several keepalives unanswered). Used by __init__ to reload the entry.
        self.on_connection_lost: Optional[Callable[[], None]] = None

    # ── callback registry ─────────────────────────────────────────────────────

    def register_state_callback(self, cb: Callable[[ACState], None]) -> None:
        """Register a callback; called with ACState on every change."""
        if cb not in self._callbacks:
            self._callbacks.append(cb)

    def unregister_state_callback(self, cb: Callable[[ACState], None]) -> None:
        try:
            self._callbacks.remove(cb)
        except ValueError:
            pass

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        self._our_pub, self._ink, self._outk = prepare_keys(self.pubkey_hex)
        loop = asyncio.get_running_loop()

        # Build the UDP socket by hand (plain AF_INET, bound to an ephemeral
        # port) and hand it to asyncio. We send to an explicit destination in
        # _send_raw and accept datagrams from any source.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", 0))
        sock.setblocking(False)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self),
            sock=sock,
        )
        self._transport = transport

        hs = build_handshake(self._our_pub, self._ink, self._outk, self.token)
        _diag("connect dst=%s:%s local=%s handshake=%d bytes",
              self.host, self.port, sock.getsockname(), len(hs))
        self._send_raw(hs)
        deadline = time.monotonic() + self.HANDSHAKE_TIMEOUT
        while not self._hs_done and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        if not self._hs_done:
            _diag("handshake TIMEOUT: %d datagrams received in %.1fs",
                  self._rx_count, self.HANDSHAKE_TIMEOUT)
            await self.disconnect()
            raise TimeoutError('Syncleo handshake timed out')
        _diag("handshake OK (fw=%s proto=%s)", self.fw_version, self.proto)
        asyncio.ensure_future(self._ping_loop())

    async def disconnect(self) -> None:
        _diag("disconnect()")
        self._connected = False
        if self._transport:
            self._transport.close()
            self._transport = None

    # ── commands ──────────────────────────────────────────────────────────────

    async def set_mode(self, mode: str) -> None:
        """Set mode. mode='off' powers the unit off."""
        rev = {v: k for k, v in ACState.MODES.items()}
        if mode not in rev:
            raise ValueError(f'Unknown mode {mode!r}, valid: {sorted(rev)}')
        await self._cmd(0x01, bytes([rev[mode]]))

    async def set_temperature(self, temp: int) -> None:
        if not 16 <= temp <= 30:
            raise ValueError(f'Temperature {temp} out of range 16..30')
        await self._cmd(0x02, bytes([temp, 0x00]))

    async def set_fan(self, fan: str) -> None:
        rev = {v: k for k, v in ACState.FANS.items()}
        if fan not in rev:
            raise ValueError(f'Unknown fan speed {fan!r}')
        await self._cmd(0x0f, bytes([rev[fan]]))

    async def set_swing(self, v: bool, h: bool) -> None:
        """Set louver swing. Economy state is preserved."""
        eco = bool(self.state.eco)
        await self._cmd(0x42, bytes([0x00, int(v), int(h), int(eco), 0x00]))

    async def set_eco(self, on: bool) -> None:
        """Economy mode. Current swing state is preserved."""
        sv = bool(self.state.v_swing)
        sh = bool(self.state.h_swing)
        await self._cmd(0x42, bytes([0x00, int(sv), int(sh), int(on), 0x00]))

    async def set_quiet(self, on: bool) -> None:
        await self._cmd(0x42, bytes([0x01, 0x00, int(on)]))

    async def set_turbo(self, on: bool) -> None:
        await self._cmd(0x31, bytes([int(on)]))

    async def set_night(self, on: bool) -> None:
        await self._cmd(0x32, bytes([int(on)]))

    async def set_ionizer(self, on: bool) -> None:
        await self._cmd(0x18, bytes([int(on)]))

    async def set_display(self, on: bool) -> None:
        await self._cmd(0x1c, bytes([int(on)]))

    # ── internals ─────────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        self._outseq = (self._outseq + 1) % 256
        return self._outseq

    def _send_raw(self, frame: bytes) -> None:
        if not self._transport:
            return
        self._transport.sendto(frame, (self.host, self.port))
        _diag("sent %d bytes -> %s:%s", len(frame), self.host, self.port)

    async def _cmd(self, cmd_type: int, data: bytes, timeout: float = 3.0) -> bool:
        """Send a command and wait for the device ACK. Returns True if ACKed."""
        seq = self._next_seq()
        self._pending.add(seq)
        _diag("cmd 0x%02x seq=%d data=%s — sending", cmd_type, seq, data.hex())
        self._send_raw(build_cmd(seq, cmd_type, data, self._ink, self._outk))
        deadline = time.monotonic() + timeout
        while seq in self._pending and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        if seq in self._pending:
            _diag("cmd 0x%02x seq=%d: NO ACK after %.1fs", cmd_type, seq, timeout)
            _LOGGER.warning('cmd 0x%02x seq=%d: no ACK', cmd_type, seq)
            self._pending.discard(seq)
            return False
        _diag("cmd 0x%02x seq=%d: ACKed", cmd_type, seq)
        return True

    async def async_verify_auth(self, timeout: float = 3.0) -> bool:
        """Confirm the device accepts our commands (token/auth is valid).

        Handshake (cmd=0x00) succeeds even with a wrong token — the device only
        rejects *commands* when the token is wrong. So after connect() we send a
        harmless keepalive and require an ACK to validate credentials.
        """
        return await self._cmd(0xff, b'', timeout=timeout)

    async def _ping_loop(self) -> None:
        _diag("ping-loop started (interval=%ss)", self.PING_INTERVAL)
        misses = 0
        while self._connected:
            await asyncio.sleep(self.PING_INTERVAL)
            if not self._connected:
                break
            seq = self._next_seq()
            _diag("ping seq=%d", seq)
            self._pending.add(seq)
            self._send_raw(build_cmd(seq, 0xff, b'', self._ink, self._outk))
            # Wait briefly for the device's ACK (cleared in _on_datagram).
            await asyncio.sleep(2.0)
            if seq in self._pending:
                self._pending.discard(seq)
                misses += 1
                _diag("keepalive miss #%d (seq=%d)", misses, seq)
                if misses >= self.KEEPALIVE_MISS_LIMIT:
                    _LOGGER.warning(
                        "Ballu AC %s: connection lost (%d keepalives unanswered)",
                        self.host, misses,
                    )
                    self._connected = False
                    if self.on_connection_lost:
                        try:
                            self.on_connection_lost()
                        except Exception:
                            _LOGGER.exception("on_connection_lost callback error")
                    break
            else:
                misses = 0
        _diag("ping-loop exited (connected=%s)", self._connected)

    def _parse_handshake(self, data: bytes) -> None:
        """Parse cmd=0x00 payload: [proto_u16][fw_maj][fw_min][mode][token...]."""
        if len(data) >= 5:
            proto, fw_maj, fw_min, _mode = struct.unpack('<HBBB', data[:5])
            self.proto = proto
            self.fw_version = f'{fw_maj}.{fw_min}'
            _diag("handshake parsed: proto=%d fw=%d.%d mode=%d",
                  proto, fw_maj, fw_min, _mode)

    def _on_datagram(self, data: bytes) -> None:
        self._rx_count += 1
        result = decrypt_frame(data, self._ink, self._outk)
        if not result:
            _diag("rx #%d: %d bytes, decrypt failed / malformed raw=%s",
                  self._rx_count, len(data), data[:16].hex())
            return
        seq, ftype, cmd_type, payload = result
        _diag("rx #%d: seq=%d ftype=%s cmd=%s payload=%s",
              self._rx_count, seq, ftype,
              f"0x{cmd_type:02x}" if cmd_type is not None else None,
              payload.hex() if payload else "")

        if ftype == 'ACK':
            # ACK frames are NOT encrypted, so a LAN host could spoof them.
            # Only honour ACKs once a real (key-validated) handshake completed —
            # this prevents a spoofed ACK from faking a connection before then.
            if self._hs_done:
                self._connected = True
                self._pending.discard(seq)
                _diag("  → ACK seq=%d, pending now=%s", seq, sorted(self._pending))
            else:
                _diag("  → ACK seq=%d ignored (handshake not done)", seq)
            return

        if ftype != 'CMD' or cmd_type is None:
            _diag("  → ignored (ftype=%s)", ftype)
            return

        if seq not in self._acked:
            self._send_raw(build_ack(seq, self._ink, self._outk))
            self._acked.add(seq)
            _diag("  → sent ACK for incoming seq=%d", seq)

        if cmd_type == 0x00:
            self._parse_handshake(payload)
            self._hs_done = True
            self._connected = True
            _diag("  → HANDSHAKE RESPONSE, hs_done=True")
            return

        if cmd_type == 0xff:
            _diag("  → keepalive echo, ignored")
            return

        changed = self.state.apply_cmd(cmd_type, payload)
        _diag("  → state cmd 0x%02x applied, changed=%s state=%s",
              cmd_type, changed, self.state)
        if changed:
            for cb in list(self._callbacks):
                try:
                    cb(self.state)
                except Exception:
                    _LOGGER.exception('state callback error')


class _Protocol(asyncio.DatagramProtocol):
    """asyncio datagram protocol delegating to the owning SyncleoClient."""

    def __init__(self, client: SyncleoClient):
        self._client = client

    def datagram_received(self, data: bytes, addr) -> None:
        self._client._on_datagram(data)

    def error_received(self, exc) -> None:
        _diag("UDP error_received: %r", exc)

    def connection_lost(self, exc) -> None:
        self._client._connected = False
        _diag("UDP connection lost: %r", exc)
