#!/usr/bin/env python3
"""
Ballu AC — passive listener.
Run in Terminal 1.  Leave running while you send commands from Terminal 2.

Usage:
    python ballu_listen.py          clean output
    python ballu_listen.py sniff    + raw hex of every frame
    python ballu_listen.py scan     mDNS scan only (find IP + pubkey), then exit
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


# ── mDNS discovery ────────────────────────────────────────────────────────────

def scan_mdns(timeout: float = 8.0) -> list[dict]:
    """
    Discover Ballu AC devices via mDNS (_syncleo._udp.local.).
    Returns list of dicts with keys: name, host, port, pubkey, props.
    Requires: pip install zeroconf
    """
    try:
        from zeroconf import ServiceBrowser, Zeroconf
        from zeroconf.asyncio import AsyncZeroconf
    except ImportError:
        print("[scan] zeroconf not installed — run: pip install zeroconf")
        return []

    found = []

    class _Listener:
        def add_service(self, zc, stype, name):
            info = zc.get_service_info(stype, name)
            if not info:
                return
            host = socket.inet_ntoa(info.addresses[0]) if info.addresses else "?"
            port = info.port or 41122
            props = {}
            for k, v in info.properties.items():
                key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else k
                val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else (v or "")
                props[key] = val
            # The real X25519 public key is in TXT `public`; `curve` is only a
            # numeric curve id (e.g. "29"), not the key.
            pubkey = props.get("public") or props.get("curve", "")
            dev_name = props.get("name", name.split(".")[0])
            found.append({"name": dev_name, "host": host, "port": port,
                           "pubkey": pubkey, "props": props})
            print(f"  ✓ {dev_name}")
            print(f"      host   = {host}")
            print(f"      port   = {port}")
            print(f"      pubkey = {pubkey or '(not found in TXT)'}")
            for k, v in props.items():
                if k not in ("curve", "name"):
                    print(f"      {k} = {v}")

        def remove_service(self, *_): pass
        def update_service(self, *_): pass

    print(f"[scan] Scanning mDNS for _syncleo._udp.local. ({timeout:.0f}s)…")
    zc = Zeroconf()
    browser = ServiceBrowser(zc, "_syncleo._udp.local.", _Listener())
    time.sleep(timeout)
    zc.close()

    if not found:
        print("[scan] No devices found.")
    return found


if "scan" in sys.argv:
    devices = scan_mdns()
    if devices:
        print()
        print("─" * 60)
        print("Set DEVICE_IP in the scripts; the public key is auto-resolved at startup.")
        for d in devices:
            print(f"  DEVICE_IP  = \"{d['host']}\"  (port {d['port']}, pubkey {d['pubkey']})")
            print(f"  # TOKEN_HEX — get from Ballu Home app (Share → QR code)")
    sys.exit(0)

AC_MODES = {0: 'OFF', 1: 'auto', 2: 'cool', 3: 'dry', 4: 'heat', 5: 'fan_only'}
AC_FAN   = {0: 'auto', 1: 'low', 2: 'medium', 3: 'high', 4: '?4', 5: '?5'}

def parse_cmd(cmd_type: int, data: bytes) -> str:
    if cmd_type == 0x00:
        if len(data) >= 5:
            proto, fwmaj, fwmin, mode = struct.unpack('<HBBB', data[:5])
            return f'HandshakeResponse  proto={proto} fw={fwmaj}.{fwmin} mode={mode} token={data[5:].hex()}'
        return f'HandshakeResponse  {data.hex()}'
    if cmd_type == 0x01:
        v = data[0] if data else '?'
        return f'Mode={AC_MODES.get(v, f"?({v})")}  raw={data.hex()}'
    if cmd_type == 0x02:
        return f'SetTemp={data[0]}°C  raw={data.hex()}' if data else 'SetTemp?'
    if cmd_type == 0x03:
        # 4 bytes, purpose still unknown (NOT fan speed — that's 0x0f)
        b = list(data) + [0]*4
        return f'Unk0x03  b0={b[0]}  b1={b[1]}  b2={b[2]}  b3={b[3]}  raw={data.hex()}'
    if cmd_type == 0x09:
        return f'Unk0x09  val={data[0] if data else "?"}  raw={data.hex()}'
    if cmd_type == 0x0f:
        v = data[0] if data else '?'
        spd = AC_FAN.get(v, f'?{v}') if isinstance(v, int) else v
        return f'FanSpeed={spd}({v})  raw={data.hex()}'
    if cmd_type == 0x14:
        return f'RoomTemp={data[0]}°C  raw={data.hex()}' if data else 'RoomTemp?'
    if cmd_type == 0x18:
        v = data[0] if data else '?'
        return f'Ionizer={"ON" if v else "OFF"}  raw={data.hex()}'
    if cmd_type == 0x1c:
        v = data[0] if data else '?'
        return f'Display={"ON" if v else "OFF"}  raw={data.hex()}'
    if cmd_type == 0x1e:
        return f'Unk0x1e  val={data[0] if data else "?"}  raw={data.hex()}'
    if cmd_type == 0x1f:
        v = data[0] if data else 0
        return f'Unk0x1f  val={v}({v:08b})  raw={data.hex()}'
    if cmd_type == 0x26:
        return f'Unk0x26  val={data[0] if data else "?"}  raw={data.hex()}'
    if cmd_type == 0x29:
        return f'Unk0x29  val={data[0] if data else "?"}  raw={data.hex()}'
    if cmd_type == 0x31:
        v = data[0] if data else '?'
        return f'TurboMode={"ON" if v else "OFF"}  raw={data.hex()}'
    if cmd_type == 0x32:
        v = data[0] if data else '?'
        return f'NightMode={"ON" if v else "OFF"}  raw={data.hex()}'
    if cmd_type == 0x40:
        try:
            preset_id = data[:2].hex()
            nr   = data[2:]
            null = nr.find(b'\x00')
            name = nr[:null].decode('utf-8', errors='replace') if null >= 0 else '?'
            cfg  = data[-8:]
            if len(cfg) == 8:
                days_byte, hour, minute, mode, temp, unk5, fan, night = cfg
                enabled = bool(days_byte & 0x80)
                DAY_NAMES = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
                days = '+'.join(DAY_NAMES[i] for i in range(7) if days_byte & (1 << i)) or 'none'
                AC_MODES_S = {0:'off',1:'auto',2:'cool',3:'dry',4:'heat',5:'fan_only'}
                AC_FAN_S   = {0:'auto',1:'low',2:'medium',3:'high'}
                mode_s = AC_MODES_S.get(mode, f'?{mode}')
                fan_s  = AC_FAN_S.get(fan, f'?{fan}')
                return (f'SchedulePreset  id={preset_id}  name="{name}"  '
                        f'enabled={enabled}  days={days}  time={hour:02d}:{minute:02d}  '
                        f'mode={mode_s}  temp={temp}°C  fan={fan_s}  night={"ON" if night else "OFF"}')
        except Exception:
            pass
        return f'SchedulePreset  raw={data.hex()}'
    if cmd_type == 0x42:
        # Two sub-types distinguished by byte[0]:
        #
        # byte[0]==0x00 → Louver swing (5 bytes): [00, v_swing, h_swing, 00, 00]
        #   byte[1]: vertical   0=stop 1=swing
        #   byte[2]: horizontal 0=stop 1=swing
        #
        # byte[0]==0x01 → Quiet mode (3 bytes): [01, 00, quiet]
        #   byte[2]: 0=off 1=on
        # cmd=0x42 has two sub-types by byte[0]:
        #
        # [00, v_swing, h_swing, economy, 00]  → louver + economy
        #   byte[1]: vertical   0=stop 1=swing
        #   byte[2]: horizontal 0=stop 1=swing
        #   byte[3]: economy    0=off  1=on
        #
        # [01, 00, quiet]  → quiet mode
        #   byte[2]: 0=off 1=on
        b = list(data) + [0]*5
        if len(data) >= 1 and b[0] == 0x00:
            v   = 'swing' if b[1] else 'stop'
            h   = 'swing' if b[2] else 'stop'
            eco = 'ON'    if b[3] else 'OFF'
            return f'Swing  vertical={v}  horizontal={h}  economy={eco}  raw={data.hex()}'
        if len(data) >= 1 and b[0] == 0x01:
            q = 'ON' if b[2] else 'OFF'
            return f'QuietMode={q}  raw={data.hex()}'
        return f'Swing/Quiet(?)  raw={data.hex()}'
    if cmd_type == 0x85: return f'HwInfo  raw={data.hex()}'
    if cmd_type == 0x87: return f'NetworkInfo  raw={data.hex()}'
    if cmd_type == 0x88: return f'SystemInfo  raw={data.hex()}'
    if cmd_type == 0x91: return f'DiagData  {data.hex()}'
    if cmd_type == 0xff: return 'Ping'
    return f'UNKNOWN  cmd={cmd_type:#04x}({cmd_type})  len={len(data)}  data={data.hex()}'

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
    pay = data[4:]
    if ft == 0: return seq, 'ACK', None, pay
    if ft == 3: return seq, 'NAK', None, pay
    if ft != 1: return seq, f'UNK{ft}', None, pay
    j, k = seq & 0xF, (seq >> 4) & 0xF
    try:
        dec = ciphers.Cipher(algorithms.AES(rotate(ink, j)), modes.CBC(rotate(outk, k))).decryptor()
        pt  = dec.update(pay) + dec.finalize()
        up  = padding.PKCS7(128).unpadder(); pt = up.update(pt) + up.finalize()
    except Exception as e:
        return seq, 'CMD', None, f'<err:{e}>'
    if len(pt) < 2 or pt[0] != seq: return None
    return seq, 'CMD', pt[1], pt[2:]

def build_ack(seq, ink, outk):
    j, k = seq & 0xF, (seq >> 4) & 0xF
    key, iv = rotate(outk, j), rotate(ink, k)
    pd = padding.PKCS7(128).padder(); pt = pd.update(bytes([seq])) + pd.finalize()
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct  = enc.update(pt) + enc.finalize()
    return struct.pack('<BBH', seq, 0, len(ct)) + ct

def build_handshake(our, ink, outk, token):
    enc = ciphers.Cipher(algorithms.AES(outk), modes.CBC(ink)).encryptor()
    et  = enc.update(token) + enc.finalize()
    pay = bytes([0]) + our + et
    return struct.pack('<BBH', 0, 1, len(pay)) + pay

def build_ping(seq, ink, outk):
    j, k = seq & 0xF, (seq >> 4) & 0xF
    key, iv = rotate(outk, j), rotate(ink, k)
    pd = padding.PKCS7(128).padder(); pt = pd.update(bytes([seq, 0xff])) + pd.finalize()
    enc = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct  = enc.update(pt) + enc.finalize()
    return struct.pack('<BBH', seq, 1, len(ct)) + ct


def main():
    global DEVICE_PK_HEX
    if not DEVICE_PK_HEX:
        DEVICE_PK_HEX = resolve_pubkey(DEVICE_IP)
        if not DEVICE_PK_HEX:
            sys.exit(1)
    token = bytes.fromhex(TOKEN_HEX)
    our_pub, ink, outk = prepare_keys(DEVICE_PK_HEX)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    sock.bind(('', 0))

    hs = build_handshake(our_pub, ink, outk, token)
    print(f'Ballu AC — listener')
    print(f'  {DEVICE_IP}:{DEVICE_PORT}')
    print(f'  Output: all incoming CMDs, only [CHANGED] shown after initial dump')
    print()
    sock.sendto(hs, (DEVICE_IP, DEVICE_PORT))

    acked    = set()
    state    = {}   # cmd_type → data
    outseq   = 0
    hs_done  = False
    last_png = time.time()
    sep_done = False

    try:
        while True:
            try:
                raw, _ = sock.recvfrom(4096)
            except socket.timeout:
                raw = None

            if raw:
                if VERBOSE:
                    print(f'  << {raw.hex()}')
                r = decrypt_frame(raw, ink, outk)
                if not r:
                    continue
                seq, ft, cmd_type, payload = r
                ts = time.strftime('%H:%M:%S')

                if ft == 'ACK':
                    if not hs_done:
                        print(f'[{ts}] ACK ← handshake OK')
                    continue

                if ft != 'CMD':
                    print(f'[{ts}] seq={seq} {ft}: {payload}')
                    continue

                # ACK it
                if seq not in acked:
                    sock.sendto(build_ack(seq, ink, outk), (DEVICE_IP, DEVICE_PORT))
                    acked.add(seq)

                if cmd_type == 0x00:
                    if not hs_done:
                        info = parse_cmd(0, payload)
                        print(f'[{ts}] seq={seq} {info}')
                        print(f'[{ts}] *** Connected — initial state dump: ***')
                        hs_done = True
                    continue

                if cmd_type == 0xff:
                    continue  # suppress ping spam

                info = parse_cmd(cmd_type, payload)
                prev = state.get(cmd_type)

                if prev is None:
                    # Initial dump
                    print(f'[{ts}] seq={seq:3d} [init   ] {info}')
                    state[cmd_type] = payload
                elif prev != payload:
                    if not sep_done:
                        print(f'\n{"─"*60}  live changes below  {"─"*20}\n')
                        sep_done = True
                    print(f'[{ts}] seq={seq:3d} [CHANGED] {info}')
                    print(f'           prev={prev.hex()}  →  new={payload.hex()}')
                    state[cmd_type] = payload
                # unchanged — skip

            # Keepalive ping every 8 s
            if hs_done and time.time() - last_png > 8:
                outseq = (outseq + 1) % 256
                sock.sendto(build_ping(outseq, ink, outk), (DEVICE_IP, DEVICE_PORT))
                last_png = time.time()

    except KeyboardInterrupt:
        print('\n[*] Stopped.')


if __name__ == '__main__':
    main()
