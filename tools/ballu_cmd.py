#!/usr/bin/env python3
"""
Ballu AC — interactive command shell.
Run in Terminal 2 while ballu_listen.py is running in Terminal 1.

Each command creates its own UDP session (device supports multiple).
State changes are visible in Terminal 1 (the listener).

Usage:
    python ballu_cmd.py
"""

import socket, struct, time, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import ciphers, padding, hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes
import cryptography.hazmat.primitives._serialization as srlz

DEVICE_IP    = "192.168.1.50"
DEVICE_PORT  = 41122
TOKEN_HEX    = ""
DEVICE_PK_HEX= ""   # auto-resolved from mDNS by IP at startup (key rotates on reboot)


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

HELP = """
─────────────────────────────────────────────────────────────────
 Confirmed (fw=1.22, ballu_platinum_evolution)
─────────────────────────────────────────────────────────────────
  mode   <off|auto|cool|dry|heat|fan_only>  cmd=0x01
  temp   <16..30>                           cmd=0x02
  fan    <auto|low|medium|high>             cmd=0x0f  (0=auto 1=low 2=medium 3=high)
  disp   <on|off>                           cmd=0x1c  (screen backlight)
  vswing <on|off>                           cmd=0x42 [00,v,h,eco,00]  vertical louver
  hswing <on|off>                           cmd=0x42 [00,v,h,eco,00]  horizontal louver
  swing42 <v> <h> [eco]                     cmd=0x42 set louvers + economy (0/1)
  quiet  <on|off>                           cmd=0x42 [01,00,q]  quiet mode
  turbo  <on|off>                           cmd=0x31  turbo (boost) mode
  night  <on|off>                           cmd=0x32  night / sleep mode
  eco    <on|off>                           cmd=0x42 byte[3]  economy mode
  ion    <on|off>                           cmd=0x18  ionizer / plasma

─────────────────────────────────────────────────────────────────
 Exploration
─────────────────────────────────────────────────────────────────
  raw  <cmd_hex> <data_hex>   send arbitrary cmd,  e.g.  raw 03 01000000
  scan <cmd_hex> <lo> <hi>    try each val in range, e.g.  scan 26 0 5

  Still unknown — explore by activating feature in Ballu Home app:
    0x03  4 bytes always 00000000  → what is this? try: raw 03 01000000
    0x09  val always 0             → scan 09 0 3
    0x26  val always 0             → scan 26 0 5  (wifi/maintenance?)
    0x29  val always 0             → scan 29 0 3
    0x1e  val always 0             → scan 1e 0 3  (child lock?)
    0x1f  val=0xff (read-only?)    → capabilities bitmask

─────────────────────────────────────────────────────────────────
  help | quit
─────────────────────────────────────────────────────────────────
"""

# ── crypto (same helpers as ballu_listen.py) ──────────────────

def rotate(buf, n):
    n = n % len(buf); return buf[n:] + buf[:n]

def prepare_keys(pubkey_hex):
    priv = X25519PrivateKey.generate()
    our  = bytes(reversed(priv.public_key().public_bytes(srlz.Encoding.Raw, srlz.PublicFormat.Raw)))
    dev  = X25519PublicKey.from_public_bytes(bytes(reversed(bytes.fromhex(pubkey_hex))))
    sh   = bytes(reversed(priv.exchange(dev)))
    h    = hashes.Hash(hashes.SHA256()); h.update(sh); sha = h.finalize()
    return our, sha[:16], sha[16:]

def decrypt_frame(data, ink, outk):
    if len(data) < 4: return None
    seq, ft, ln = struct.unpack('<BBH', data[:4])
    if len(data) != 4 + ln: return None
    if ft == 0: return seq, 'ACK'
    if ft != 1: return None
    j, k = seq & 0xF, (seq >> 4) & 0xF
    try:
        dec = ciphers.Cipher(algorithms.AES(rotate(ink, j)), modes.CBC(rotate(outk, k))).decryptor()
        pt  = dec.update(data[4:]) + dec.finalize()
        up  = padding.PKCS7(128).unpadder(); pt = up.update(pt) + up.finalize()
    except Exception:
        return None
    if len(pt) < 2 or pt[0] != seq: return None
    return seq, 'CMD', pt[1], pt[2:]

def build_handshake(our, ink, outk, token):
    enc = ciphers.Cipher(algorithms.AES(outk), modes.CBC(ink)).encryptor()
    et  = enc.update(token) + enc.finalize()
    pay = bytes([0]) + our + et
    return struct.pack('<BBH', 0, 1, len(pay)) + pay

def build_ack(seq, ink, outk):
    j, k = seq & 0xF, (seq >> 4) & 0xF
    key, iv = rotate(outk, j), rotate(ink, k)
    pd = padding.PKCS7(128).padder(); pt = pd.update(bytes([seq])) + pd.finalize()
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct  = enc.update(pt) + enc.finalize()
    return struct.pack('<BBH', seq, 0, len(ct)) + ct

def build_cmd(seq, cmd_type, data, ink, outk):
    j, k = seq & 0xF, (seq >> 4) & 0xF
    key, iv = rotate(outk, j), rotate(ink, k)
    pt = bytes([seq, cmd_type]) + data
    pd = padding.PKCS7(128).padder(); pt = pd.update(pt) + pd.finalize()
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct  = enc.update(pt) + enc.finalize()
    return struct.pack('<BBH', seq, 1, len(ct)) + ct


class Session:
    """One-shot session: connect, send command, wait for ACK, done."""

    def __init__(self):
        self.token = bytes.fromhex(TOKEN_HEX)
        self.our_pub, self.ink, self.outk = prepare_keys(DEVICE_PK_HEX)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        self.sock.bind(('', 0))
        self.seq      = 0
        self.acked    = set()
        self.hs_done  = False

    def _next_seq(self):
        self.seq = (self.seq + 1) % 256
        return self.seq

    def connect(self):
        hs = build_handshake(self.our_pub, self.ink, self.outk, self.token)
        self.sock.sendto(hs, (DEVICE_IP, DEVICE_PORT))
        deadline = time.time() + 4.0
        while time.time() < deadline:
            try:
                raw, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            r = decrypt_frame(raw, self.ink, self.outk)
            if not r: continue
            if r[1] == 'ACK':
                continue
            if r[1] == 'CMD' and r[2] == 0x00:
                seq = r[0]
                self.sock.sendto(build_ack(seq, self.ink, self.outk),
                                 (DEVICE_IP, DEVICE_PORT))
                self.hs_done = True
                return True
        return False

    def send(self, cmd_type: int, data: bytes, label: str = '') -> bool:
        """Send command, wait for device ACK. Returns True on success."""
        if not self.hs_done:
            if not self.connect():
                print('  [!] Handshake failed')
                return False
        seq = self._next_seq()
        frame = build_cmd(seq, cmd_type, data, self.ink, self.outk)
        self.sock.sendto(frame, (DEVICE_IP, DEVICE_PORT))
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                raw, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                break
            r = decrypt_frame(raw, self.ink, self.outk)
            if not r: continue
            if r[1] == 'ACK' and r[0] == seq:
                desc = label or f'cmd={cmd_type:#04x} {data.hex()}'
                print(f'  ✓ {desc}  (seq={seq})')
                return True
            # ACK any other CMDs that arrive in the meantime
            if r[1] == 'CMD' and r[0] not in self.acked:
                self.sock.sendto(build_ack(r[0], self.ink, self.outk),
                                 (DEVICE_IP, DEVICE_PORT))
                self.acked.add(r[0])
        print(f'  ✗ No ACK for seq={seq} — command may not have worked')
        return False

    def close(self):
        self.sock.close()


def run_shell():
    global DEVICE_PK_HEX
    if not DEVICE_PK_HEX:
        DEVICE_PK_HEX = resolve_pubkey(DEVICE_IP)
        if not DEVICE_PK_HEX:
            sys.exit(1)
    print('Ballu AC — command shell')
    print('Commands are sent to the device; watch Terminal 1 for state changes.')
    print(HELP)

    try:
        from prompt_toolkit import prompt as pt_prompt
        get_line = lambda: pt_prompt('ac> ')
    except ImportError:
        get_line = lambda: input('ac> ')

    sess = Session()

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
                if v is None: raise ValueError(f'unknown mode')
                sess.send(0x01, bytes([v]), f'Mode={parts[1]}')

            elif cmd == 'temp' and len(parts) == 2:
                t = int(parts[1])
                if not 16 <= t <= 30: raise ValueError('range 16..30')
                sess.send(0x02, bytes([t, 0x00]), f'SetTemp={t}°C')

            elif cmd == 'fan' and len(parts) == 2:
                fan_map = {'auto': 0, 'low': 1, 'medium': 2, 'high': 3}
                name = parts[1].lower()
                if name in fan_map:
                    v = fan_map[name]
                elif name.isdigit():
                    v = int(name)
                else:
                    raise ValueError(f'unknown fan speed; valid: auto low medium high (or 0..3)')
                sess.send(0x0f, bytes([v]), f'FanSpeed={name}({v})')

            elif cmd == 'turbo' and len(parts) == 2:
                v = 1 if parts[1].lower() in ('on', '1') else 0
                sess.send(0x31, bytes([v]), f'TurboMode={"ON" if v else "OFF"}')

            elif cmd == 'night' and len(parts) == 2:
                v = 1 if parts[1].lower() in ('on', '1') else 0
                sess.send(0x32, bytes([v]), f'NightMode={"ON" if v else "OFF"}')

            elif cmd == 'vswing' and len(parts) == 2:
                # cmd=0x42: [00, v_swing, h_swing, economy, 00]
                v = 1 if parts[1].lower() in ('on', '1') else 0
                sess.send(0x42, bytes([0x00, v, 0x01, 0x00, 0x00]),
                          f'VSwing={"ON" if v else "OFF"} (cmd=0x42)')

            elif cmd == 'hswing' and len(parts) == 2:
                h = 1 if parts[1].lower() in ('on', '1') else 0
                sess.send(0x42, bytes([0x00, 0x01, h, 0x00, 0x00]),
                          f'HSwing={"ON" if h else "OFF"} (cmd=0x42)')

            elif cmd == 'swing42' and len(parts) >= 3:
                v   = int(parts[1])
                h   = int(parts[2])
                eco = int(parts[3]) if len(parts) > 3 else 0
                sess.send(0x42, bytes([0x00, v, h, eco, 0x00]),
                          f'Swing v={v} h={h} eco={eco} (cmd=0x42)')

            elif cmd == 'eco' and len(parts) == 2:
                e = 1 if parts[1].lower() in ('on', '1') else 0
                # send swing packet with economy bit; preserve vertical=1 horizontal=1 as safe default
                sess.send(0x42, bytes([0x00, 0x01, 0x01, e, 0x00]),
                          f'EcoMode={"ON" if e else "OFF"} (cmd=0x42)')

            elif cmd == 'ion' and len(parts) == 2:
                v = 1 if parts[1].lower() in ('on', '1') else 0
                sess.send(0x18, bytes([v]), f'Ionizer={"ON" if v else "OFF"}')

            elif cmd == 'quiet' and len(parts) == 2:
                q = 1 if parts[1].lower() in ('on','1') else 0
                sess.send(0x42, bytes([0x01, 0x00, q]),
                          f'QuietMode={"ON" if q else "OFF"} (cmd=0x42)')

            elif cmd == 'disp' and len(parts) == 2:
                v = 1 if parts[1].lower() == 'on' else 0
                sess.send(0x1c, bytes([v]), f'Display={"ON" if v else "OFF"}')

            elif cmd == 'raw' and len(parts) >= 2:
                ct = int(parts[1], 16)
                d  = bytes.fromhex(parts[2]) if len(parts) > 2 else b''
                sess.send(ct, d)

            elif cmd == 'scan' and len(parts) == 4:
                ct  = int(parts[1], 16)
                lo, hi = int(parts[2]), int(parts[3])
                print(f'  Scanning cmd={ct:#04x} val {lo}..{hi}')
                print(f'  Watch Terminal 1 for [CHANGED] lines!')
                for v in range(lo, hi + 1):
                    ok = sess.send(ct, bytes([v]), f'scan cmd={ct:#04x} val={v}')
                    time.sleep(0.8)

            elif cmd in ('help', '?'):
                print(HELP)

            else:
                print('  Unknown command. Type help.')

        except Exception as e:
            print(f'  Error: {e}')

    sess.close()


if __name__ == '__main__':
    run_shell()
