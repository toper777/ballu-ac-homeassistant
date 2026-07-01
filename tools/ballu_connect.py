#!/usr/bin/env python3
"""
Ballu AC syncleo UDP protocol probe.
Tries to handshake with the device using various token candidates.

Usage:
    python3 ballu_connect.py [token_hex]

If token_hex is provided (32 hex chars = 16 bytes), uses it directly.
Otherwise tries a list of candidates.

Device info (from mDNS):
  IP:     192.168.1.50
  Port:   41122
  Pubkey: auto-resolved from mDNS at startup (rotates on device reboot)
  MAC:    AA:BB:CC:DD:EE:FF
"""

import socket
import struct
import time
import sys
import hashlib

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import ciphers, padding, hashes
    from cryptography.hazmat.primitives.ciphers import algorithms, modes
    import cryptography.hazmat.primitives._serialization as srlz
except ImportError:
    print("Install: pip3 install cryptography")
    sys.exit(1)

# --- Device parameters (from mDNS) ---
DEVICE_IP   = "192.168.1.50"
DEVICE_PORT = 41122
DEVICE_PUBKEY_HEX = ""   # auto-resolved from mDNS by IP at startup (key rotates on reboot)
DEVICE_MAC  = "AA:BB:CC:DD:EE:FF"


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

# --- Token candidates to try ---
# Each must be exactly 16 bytes
def make_candidates():
    candidates = {}

    # MQTT password "000000000000" as ASCII, padded with zeros to 16
    mqtt_pass_ascii = b"000000000000" + b"\x00" * 4
    candidates["mqtt_pass_ascii_padded"] = mqtt_pass_ascii

    # MQTT password as hex bytes (6 bytes) padded to 16
    mqtt_pass_hex = bytes.fromhex("000000000000") + b"\x00" * 10
    candidates["mqtt_pass_hex_padded"] = mqtt_pass_hex

    # MAC bytes (6) padded to 16
    mac_bytes = bytes.fromhex(DEVICE_MAC.replace(":", ""))
    candidates["mac_padded"] = mac_bytes + b"\x00" * 10

    # MD5 of MQTT password (16 bytes)
    candidates["md5_mqtt_pass"] = hashlib.md5(b"000000000000").digest()

    # MD5 of MAC
    candidates["md5_mac"] = hashlib.md5(DEVICE_MAC.encode()).digest()

    # MD5 of MAC without colons
    candidates["md5_mac_nocolon"] = hashlib.md5(b"aabbccddeeff").digest()

    # All zeros
    candidates["zeros"] = b"\x00" * 16

    # All 0xFF
    candidates["ones"] = b"\xff" * 16

    return candidates


def prepare_keys(device_pubkey_bytes: bytes):
    """ECDH + SHA256 → encinkey, encoutkey, our pubkey"""
    privkey = X25519PrivateKey.generate()
    our_pubkey = bytes(reversed(
        privkey.public_key().public_bytes(
            encoding=srlz.Encoding.Raw,
            format=srlz.PublicFormat.Raw
        )
    ))
    device_pubkey = X25519PublicKey.from_public_bytes(
        bytes(reversed(device_pubkey_bytes))
    )
    shared_key = bytes(reversed(privkey.exchange(device_pubkey)))

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_key)
    shared_sha256 = digest.finalize()

    encinkey  = shared_sha256[:16]
    encoutkey = shared_sha256[16:]
    return our_pubkey, encinkey, encoutkey


def build_handshake(our_pubkey: bytes, encinkey: bytes, encoutkey: bytes, token: bytes) -> bytes:
    """Build the handshake frame (TYPE=CMD=1, seq=0, cmd_type=0)"""
    # Encrypt token with outkey (key) and inkey (iv) — no byte shuffling for seq=0
    cipher = ciphers.Cipher(algorithms.AES(encoutkey), modes.CBC(encinkey))
    encryptor = cipher.encryptor()
    encrypted_token = encryptor.update(token) + encryptor.finalize()

    payload = bytearray()
    payload.append(0)               # seq = 0
    payload.extend(our_pubkey)      # 32 bytes
    payload.extend(encrypted_token) # 16 bytes

    # Frame header: seq=0, type=CMD(1), length=len(payload)
    header = struct.pack('<BBH', 0, 1, len(payload))
    return bytes(header) + bytes(payload)


def try_token(device_pubkey_bytes: bytes, token: bytes, label: str) -> bool:
    """Send handshake and wait for response. Returns True if got any valid-looking response."""
    our_pubkey, encinkey, encoutkey = prepare_keys(device_pubkey_bytes)
    frame = build_handshake(our_pubkey, encinkey, encoutkey, token)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    src_port = 40000 + (hash(label) % 10000)
    try:
        sock.bind(('', src_port))
    except:
        sock.bind(('', 0))

    print(f"\n[{label}] token={token.hex()}")
    print(f"  Sending {len(frame)} byte handshake to {DEVICE_IP}:{DEVICE_PORT}...")
    sock.sendto(frame, (DEVICE_IP, DEVICE_PORT))

    responses = []
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
            responses.append(data)
            print(f"  << Response ({len(data)} bytes): {data.hex()}")
        except socket.timeout:
            break
    sock.close()

    if not responses:
        print(f"  No response (timeout)")
        return False

    # Check if first response looks like ACK (frame type=0) or CMD with HandshakeResponse
    for r in responses:
        if len(r) >= 4:
            seq, ftype, length = struct.unpack('<BBH', r[:4])
            ftype_name = {0: 'ACK', 1: 'CMD', 2: 'AUX', 3: 'NAK'}.get(ftype, f'?{ftype}')
            print(f"  Frame: seq={seq} type={ftype_name} length={length}")
            if ftype == 0:  # ACK!
                print(f"  *** GOT ACK! This token might be correct! ***")
                return True
            elif ftype == 1 and len(r) > 4:
                # Try to read the handshake response without decryption (length check)
                cmd_byte = r[5] if len(r) > 5 else -1
                print(f"  CMD type={cmd_byte}")
                if cmd_byte == 0:
                    print(f"  *** Looks like HandshakeResponse! ***")
                    return True
    return False


def main():
    global DEVICE_PUBKEY_HEX
    if not DEVICE_PUBKEY_HEX:
        DEVICE_PUBKEY_HEX = resolve_pubkey(DEVICE_IP)
        if not DEVICE_PUBKEY_HEX:
            sys.exit(1)
    device_pubkey_bytes = bytes.fromhex(DEVICE_PUBKEY_HEX)
    print(f"Ballu AC syncleo probe")
    print(f"Device: {DEVICE_IP}:{DEVICE_PORT}")
    print(f"Device pubkey: {DEVICE_PUBKEY_HEX}")

    if len(sys.argv) > 1:
        token_hex = sys.argv[1].strip()
        if len(token_hex) != 32:
            print(f"Error: token must be 32 hex chars (16 bytes), got {len(token_hex)}")
            sys.exit(1)
        candidates = {"from_cmdline": bytes.fromhex(token_hex)}
    else:
        candidates = make_candidates()

    print(f"\nTrying {len(candidates)} token candidate(s)...\n")

    for label, token in candidates.items():
        assert len(token) == 16, f"Token {label} is {len(token)} bytes, expected 16"
        success = try_token(device_pubkey_bytes, token, label)
        if success:
            print(f"\n=== POSSIBLE MATCH: {label} = {token.hex()} ===")
        time.sleep(0.5)

    print("\nDone. If all tokens failed, get the real token from the Ballu Home app:")
    print("  App → device → Share → QR code → scan → look for token= in URL")
    print("  Then run: python3 ballu_connect.py <32_hex_token>")


if __name__ == "__main__":
    main()
