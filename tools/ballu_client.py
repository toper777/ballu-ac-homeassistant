#!/usr/bin/env python3
"""
Ballu AC syncleo UDP client — protocol exploration tool.

Device: ballu_platinum_evolution, fw=1.22, devtype=20, protocol=3
  IP:     192.168.1.50
  Port:   41122
  Token:  set TOKEN_HEX below (from Ballu Home app QR)
  Pubkey: auto-resolved from mDNS at startup (rotates on device reboot)

Usage:
  python ballu_client.py          normal mode
  python ballu_client.py sniff    + raw hex of every frame
"""

import socket, struct, time, sys, threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import ciphers, padding, hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes
import cryptography.hazmat.primitives._serialization as srlz

DEVICE_IP    = "192.168.1.50"
DEVICE_PORT  = 41122
TOKEN_HEX    = ""
DEVICE_PK_HEX= ""   # auto-resolved from mDNS by IP at startup (key rotates on reboot)
VERBOSE = "sniff" in sys.argv


def resolve_pubkey(ip, timeout=8.0):
    """Auto-resolve the device's current X25519 public key from mDNS by IP.

    The key rotates when the device/Wi-Fi module reboots, so we fetch the live
    value from the TXT `public=` field instead of hardcoding it.
    Requires: pip install zeroconf
    """
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError:
        print("[pk] zeroconf not installed — run: pip install zeroconf")
        return None
    import re
    found = {}

    class _L:
        def add_service(self, zc, st, name):
            info = zc.get_service_info(st, name)
            if not info or not info.addresses:
                return
            try:
                if socket.inet_ntoa(info.addresses[0]) != ip:
                    return
            except Exception:
                return
            props = {}
            for k, v in (info.properties or {}).items():
                key = k.decode("utf-8", "replace") if isinstance(k, bytes) else k
                val = v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")
                props[key] = val
            pk = (props.get("public") or "").strip().lower()
            if re.fullmatch(r"[0-9a-fA-F]{64}", pk):
                found["pk"] = pk

        def remove_service(self, *a): pass
        def update_service(self, *a): pass

    print(f"[pk] resolving public key for {ip} via mDNS…")
    zc = Zeroconf()
    ServiceBrowser(zc, "_syncleo._udp.local.", _L())
    waited = 0.0
    while waited < timeout and "pk" not in found:
        time.sleep(0.2)
        waited += 0.2
    zc.close()
    pk = found.get("pk")
    print(f"[pk] public key = {pk}" if pk else f"[pk] FAILED to resolve for {ip}")
    return pk

# ============================================================
# Known protocol map  (fw=1.22, ballu_platinum_evolution)
# ============================================================
#
# cmd  | name            | values / notes
# -----|-----------------|----------------------------------------------
# 0x01 | Mode/Power      | 0=off 1=auto 2=cool 3=dry 4=heat 5=fan_only
# 0x02 | SetTemp         | u8 °C (16..30), second byte always 0x00
# 0x03 | Fan+Swing       | 4 bytes: [fan_spd, v_swing?, h_swing?, flags?]
#      |                 |   fan: 0=auto 1=low 2=med 3=high (4=turbo? 5=quiet?)
# 0x09 | ?               | always 0, purpose unknown
# 0x0f | SleepMode?      | 0=off — suspected
# 0x14 | RoomTemp        | u8 °C  (read-only, auto-push ~30s)
# 0x18 | ?               | always 0
# 0x1c | Display         | 0=screen off  1=screen on
# 0x1e | ?               | always 0
# 0x1f | ?               | always 0xff — possibly capabilities bitmask
# 0x26 | ?               | always 0
# 0x29 | ?               | always 0
# 0x31 | ?               | always 0
# 0x32 | ?               | always 0
# 0x40 | SchedulePreset  | name(utf8) + schedule config
# 0x42 | ScheduleState   | on/off state of presets
# 0x85 | HwInfo          | read-only
# 0x87 | NetworkInfo     | read-only
# 0x88 | SystemInfo      | read-only
# 0x91 | DiagData        | read-only diagnostics
# ============================================================

AC_MODES = {0: 'OFF', 1: 'auto', 2: 'cool', 3: 'dry', 4: 'heat', 5: 'fan_only'}
AC_FAN   = {0: 'auto', 1: 'low', 2: 'medium', 3: 'high', 4: 'turbo?', 5: 'quiet?'}

# State snapshot — updated on every incoming CMD, used to detect deltas
_state: dict[int, bytes] = {}

def parse_cmd(cmd_type: int, data: bytes) -> str:
    if cmd_type == 0x00:
        if len(data) >= 5:
            proto, fw_maj, fw_min, mode = struct.unpack('<HBBB', data[:5])
            token = data[5:].hex() if len(data) > 5 else ''
            return f'HandshakeResponse proto={proto} fw={fw_maj}.{fw_min} mode={mode} token={token}'
        return f'HandshakeResponse {data.hex()}'

    if cmd_type == 0x01:
        val = data[0] if data else '?'
        return f'Mode={AC_MODES.get(val, f"?({val})")}  raw={data.hex()}'

    if cmd_type == 0x02:
        return (f'SetTemp={data[0]}°C  raw={data.hex()}') if data else 'SetTemp?'

    if cmd_type == 0x03:
        # 4 bytes — explore all of them
        b = list(data) + [0] * 4
        fan   = AC_FAN.get(b[0], f'?({b[0]})')
        return (f'Fan/Swing  fan={fan}({b[0]})'
                f'  b1={b[1]}  b2={b[2]}  b3={b[3]}'
                f'  raw={data.hex()}')

    if cmd_type == 0x09:
        return f'Unk0x09  val={data[0] if data else "?"}  raw={data.hex()}'

    if cmd_type == 0x0f:
        val = data[0] if data else '?'
        return f'Unk0x0f  val={val}  raw={data.hex()}'

    if cmd_type == 0x14:
        return (f'RoomTemp={data[0]}°C  raw={data.hex()}') if data else 'RoomTemp?'

    if cmd_type == 0x18:
        return f'Unk0x18  val={data[0] if data else "?"}  raw={data.hex()}'

    if cmd_type == 0x1c:
        val = data[0] if data else '?'
        return f'Display={"ON" if val else "OFF"}  raw={data.hex()}'

    if cmd_type == 0x1e:
        return f'Unk0x1e  val={data[0] if data else "?"}  raw={data.hex()}'

    if cmd_type == 0x1f:
        val = data[0] if data else '?'
        bits = f'{val:08b}' if isinstance(val, int) else '?'
        return f'Unk0x1f  val={val}({bits})  raw={data.hex()}'

    if cmd_type == 0x26:
        return f'Unk0x26  val={data[0] if data else "?"}  raw={data.hex()}'

    if cmd_type == 0x29:
        return f'Unk0x29  val={data[0] if data else "?"}  raw={data.hex()}'

    if cmd_type == 0x31:
        return f'Unk0x31  val={data[0] if data else "?"}  raw={data.hex()}'

    if cmd_type == 0x32:
        return f'Unk0x32  val={data[0] if data else "?"}  raw={data.hex()}'

    if cmd_type == 0x40:
        try:
            name_raw = data[2:] if len(data) > 2 else data
            null = name_raw.find(b'\x00')
            name = name_raw[:null].decode('utf-8', errors='replace') if null >= 0 else '?'
            tail = data[-8:].hex()
            return f'SchedulePreset  name="{name}"  tail={tail}  raw={data.hex()}'
        except Exception:
            return f'SchedulePreset  raw={data.hex()}'

    if cmd_type == 0x42:
        return f'ScheduleState  raw={data.hex()}'

    if cmd_type == 0x85:
        return f'HwInfo  raw={data.hex()}'
    if cmd_type == 0x87:
        return f'NetworkInfo  raw={data.hex()}'
    if cmd_type == 0x88:
        return f'SystemInfo  raw={data.hex()}'
    if cmd_type == 0x91:
        return f'DiagData  {data.hex()}'
    if cmd_type == 0xff:
        return 'Ping'

    return f'UNKNOWN  type={cmd_type:#04x}({cmd_type})  len={len(data)}  data={data.hex()}'

# ---------- crypto ----------

def prepare_keys(device_pubkey_hex: str):
    privkey = X25519PrivateKey.generate()
    our_pub = bytes(reversed(privkey.public_key().public_bytes(
        encoding=srlz.Encoding.Raw, format=srlz.PublicFormat.Raw)))
    dev_pub = X25519PublicKey.from_public_bytes(
        bytes(reversed(bytes.fromhex(device_pubkey_hex))))
    shared = bytes(reversed(privkey.exchange(dev_pub)))
    d = hashes.Hash(hashes.SHA256())
    d.update(shared)
    sha = d.finalize()
    return our_pub, sha[:16], sha[16:]

def rotate(buf: bytes, n: int) -> bytes:
    n = n % len(buf)
    return buf[n:] + buf[:n]

def decrypt_frame(data: bytes, encinkey: bytes, encoutkey: bytes):
    if len(data) < 4:
        return None
    seq, ftype, length = struct.unpack('<BBH', data[:4])
    if len(data) != 4 + length:
        return None
    payload = data[4:]
    if ftype == 0: return seq, 'ACK', payload
    if ftype == 3: return seq, 'NAK', payload
    if ftype != 1: return seq, f'UNK({ftype})', payload
    j, k = seq & 0xF, (seq >> 4) & 0xF
    try:
        dec = ciphers.Cipher(algorithms.AES(rotate(encinkey, j)),
                             modes.CBC(rotate(encoutkey, k))).decryptor()
        pt = dec.update(payload) + dec.finalize()
        unpad = padding.PKCS7(128).unpadder()
        pt = unpad.update(pt) + unpad.finalize()
    except Exception as e:
        return seq, 'CMD', f'decrypt_err: {e}'
    if len(pt) < 2 or pt[0] != seq:
        return seq, 'CMD', f'bad_pt: {pt.hex()}'
    return seq, 'CMD', (pt[1], pt[2:])

def build_handshake(our_pub, encinkey, encoutkey, token):
    enc_tok = ciphers.Cipher(algorithms.AES(encoutkey),
                              modes.CBC(encinkey)).encryptor()
    enc_tok = enc_tok.update(token) + enc_tok.finalize()
    payload = bytes([0]) + our_pub + enc_tok
    return struct.pack('<BBH', 0, 1, len(payload)) + payload

def build_ack(seq, encinkey, encoutkey):
    j, k = seq & 0xF, (seq >> 4) & 0xF
    key, iv = rotate(encoutkey, j), rotate(encinkey, k)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(bytes([seq])) + padder.finalize()
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return struct.pack('<BBH', seq, 0, len(ct)) + ct

def build_cmd_frame(seq, cmd_type, data, encinkey, encoutkey):
    j, k = seq & 0xF, (seq >> 4) & 0xF
    key, iv = rotate(encoutkey, j), rotate(encinkey, k)
    pt = bytes([seq, cmd_type]) + data
    padder = padding.PKCS7(128).padder()
    padded = padder.update(pt) + padder.finalize()
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return struct.pack('<BBH', seq, 1, len(ct)) + ct

# ---------- client ----------

_print_lock = threading.Lock()

def log(msg):
    with _print_lock:
        print(f'\r{msg}', flush=True)

class BallClient:
    def __init__(self):
        self.token = bytes.fromhex(TOKEN_HEX)
        self.our_pub, self.encinkey, self.encoutkey = prepare_keys(DEVICE_PK_HEX)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3.0)
        self.sock.bind(('', 0))
        self.connected = False
        self._hs_done  = False
        self._outseq   = 0
        self._lock     = threading.Lock()
        self._pending  = set()
        self._state    = {}   # cmd_type → last data bytes (for delta detection)

    def _next_seq(self):
        with self._lock:
            self._outseq = (self._outseq + 1) % 256
            return self._outseq

    def _send(self, frame, track=False):
        if track:
            self._pending.add(struct.unpack('<B', frame[:1])[0])
        if VERBOSE:
            print(f'  >> {frame.hex()}')
        self.sock.sendto(frame, (DEVICE_IP, DEVICE_PORT))

    def send_cmd(self, cmd_type: int, data: bytes, label: str = ''):
        seq = self._next_seq()
        frame = build_cmd_frame(seq, cmd_type, data, self.encinkey, self.encoutkey)
        self._send(frame, track=True)
        desc = label or f'cmd={cmd_type:#04x} data={data.hex()}'
        log(f'>>> {desc}  (seq={seq})')
        return seq

    def run(self):
        hs = build_handshake(self.our_pub, self.encinkey, self.encoutkey, self.token)
        log('[*] Connecting...')
        self._send(hs)
        acked = set()
        last_ping = time.time()

        try:
            while True:
                try:
                    raw, _ = self.sock.recvfrom(4096)
                except socket.timeout:
                    raw = None

                if raw:
                    if VERBOSE:
                        log(f'  << {raw.hex()}')
                    result = decrypt_frame(raw, self.encinkey, self.encoutkey)
                    if result:
                        seq, ftype, payload = result
                        ts = time.strftime('%H:%M:%S')

                        if ftype == 'ACK':
                            if not self.connected:
                                log(f'[{ts}] seq={seq} ACK ← handshake OK')
                                self.connected = True
                            elif seq in self._pending:
                                log(f'[{ts}] seq={seq} ACK ← device confirmed ✓')
                                self._pending.discard(seq)

                        elif ftype == 'CMD' and isinstance(payload, tuple):
                            cmd_type, cmd_data = payload

                            # ACK every CMD exactly once
                            if seq not in acked:
                                self._send(build_ack(seq, self.encinkey, self.encoutkey))
                                acked.add(seq)

                            if cmd_type == 0x00:
                                # HandshakeResponse
                                if not self._hs_done:
                                    info = parse_cmd(cmd_type, cmd_data)
                                    log(f'[{ts}] seq={seq} {info}')
                                    self._hs_done = True
                                    self.connected = True
                                    log(f'[{ts}] *** Connected! ***')
                            elif cmd_type == 0xff:
                                pass  # suppress ping spam
                            else:
                                info = parse_cmd(cmd_type, cmd_data)
                                # Mark deltas: [NEW] if first time, [CHG] if changed
                                prev = self._state.get(cmd_type)
                                if prev is None:
                                    marker = '[init]'
                                elif prev != cmd_data:
                                    marker = '[CHANGED]'
                                else:
                                    marker = None  # unchanged, skip

                                if marker or seq not in acked - {seq}:
                                    if prev is None or prev != cmd_data:
                                        log(f'[{ts}] seq={seq} {marker or ""} {info}')
                                        self._state[cmd_type] = cmd_data

                        elif ftype not in ('ACK',):
                            log(f'[{ts}] seq={seq} {ftype}: {payload}')

                if self.connected and time.time() - last_ping > 8:
                    seq = self._next_seq()
                    self._send(build_cmd_frame(seq, 0xff, b'',
                                               self.encinkey, self.encoutkey))
                    last_ping = time.time()

        except Exception as e:
            log(f'[!] {e}')

# ---------- interactive ----------

HELP = """
── Confirmed commands ──────────────────────────────────────────
  mode <off|auto|cool|dry|heat|fan_only>   cmd=0x01
  temp <16..30>                            cmd=0x02
  fan  <0..5>                              cmd=0x03 byte0  (0=auto,1=low,2=med,3=high,4=?,5=?)
  b03  <b0> <b1> <b2> <b3>                 send full cmd=0x03 (4 bytes, explore swing)
  display <on|off>                         cmd=0x1c

── Exploration commands ─────────────────────────────────────────
  raw  <cmd_hex> <data_hex>                e.g.  raw 0f 01
  scan <cmd_hex> <from> <to>              send val 0..N,  e.g.  scan 0f 0 5
  state                                    print current known state

── Other ────────────────────────────────────────────────────────
  help | quit
"""

def interactive(client: BallClient):
    print(HELP)
    try:
        from prompt_toolkit import prompt as pt_prompt
        from prompt_toolkit.patch_stdout import patch_stdout
        def get_line():
            with patch_stdout():
                return pt_prompt('ac> ')
    except ImportError:
        def get_line():
            return input('ac> ')

    while True:
        try:
            line = get_line().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()
        try:
            if cmd == 'quit':
                break

            elif cmd == 'mode' and len(parts) == 2:
                m = {'off':0,'auto':1,'cool':2,'dry':3,'heat':4,'fan_only':5}
                v = m.get(parts[1].lower())
                if v is None: raise ValueError(f'unknown mode {parts[1]}')
                client.send_cmd(0x01, bytes([v]), f'Mode={parts[1]}')

            elif cmd == 'temp' and len(parts) == 2:
                t = int(parts[1])
                if not 16 <= t <= 30: raise ValueError('range 16..30')
                client.send_cmd(0x02, bytes([t, 0x00]), f'SetTemp={t}°C')

            elif cmd == 'fan' and len(parts) == 2:
                v = int(parts[1])
                # keep current swing bytes (unknown — send 0)
                client.send_cmd(0x03, bytes([v, 0, 0, 0]), f'Fan={v}')

            elif cmd == 'b03' and len(parts) == 5:
                b = bytes([int(x) for x in parts[1:5]])
                client.send_cmd(0x03, b, f'Fan/Swing {b.hex()}')

            elif cmd == 'display' and len(parts) == 2:
                v = 1 if parts[1].lower() == 'on' else 0
                client.send_cmd(0x1c, bytes([v]), f'Display={"ON" if v else "OFF"}')

            elif cmd == 'raw' and len(parts) >= 2:
                ct = int(parts[1], 16)
                d  = bytes.fromhex(parts[2]) if len(parts) > 2 else b''
                client.send_cmd(ct, d)

            elif cmd == 'scan' and len(parts) == 4:
                ct   = int(parts[1], 16)
                lo, hi = int(parts[2]), int(parts[3])
                print(f'  Scanning cmd={ct:#04x} val {lo}..{hi} (0.5s apart)')
                for v in range(lo, hi + 1):
                    client.send_cmd(ct, bytes([v]), f'scan cmd={ct:#04x} val={v}')
                    time.sleep(0.5)

            elif cmd == 'state':
                print('\n  Current known state:')
                for k in sorted(client._state):
                    info = parse_cmd(k, client._state[k])
                    print(f'    cmd={k:#04x}: {info}')
                print()

            elif cmd in ('help', '?'):
                print(HELP)

            else:
                print('  Unknown. Type help.')

        except Exception as e:
            print(f'  Error: {e}')


if __name__ == '__main__':
    print(f'Ballu AC — protocol explorer')
    print(f'  {DEVICE_IP}:{DEVICE_PORT}  token={TOKEN_HEX[:8]}...\n')

    if not DEVICE_PK_HEX:
        DEVICE_PK_HEX = resolve_pubkey(DEVICE_IP)
        if not DEVICE_PK_HEX:
            sys.exit(1)

    client = BallClient()
    t = threading.Thread(target=client.run, daemon=True)
    t.start()

    for _ in range(60):
        if client._hs_done: break
        time.sleep(0.1)

    if client._hs_done:
        interactive(client)
    else:
        log('[!] Handshake timeout')
