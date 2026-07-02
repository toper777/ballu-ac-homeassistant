# Ballu AC — Home Assistant integration (syncleo protocol)

[![Validate](https://github.com/toper777/ballu-ac-homeassistant/actions/workflows/validate.yml/badge.svg)](https://github.com/toper777/ballu-ac-homeassistant/actions/workflows/validate.yml)
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub release](https://img.shields.io/github/v/release/toper777/ballu-ac-homeassistant)](https://github.com/toper777/ballu-ac-homeassistant/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**English** | [Русский](README.ru.md)

Local control of **Ballu** air conditioners (and other RusClimate devices running
the **syncleo** firmware) in Home Assistant over UDP — no cloud. Built on a
reverse-engineered syncleo protocol (X25519 + AES-CBC over UDP).

> Unofficial integration, not affiliated with Ballu / RusClimate. All names and
> trademarks belong to their respective owners.

## Features

- 🌡️ **Climate**: modes (auto / cool / dry / heat / fan only / off), target
  temperature 16–30 °C, fan speed, louver swing.
- 🎛️ **Presets**: turbo, night, eco, quiet (mutually exclusive).
- 📟 **Sensor**: room temperature.
- 🔌 **Switches**: ionizer, display backlight.
- 📡 **Local & push**: state updates instantly, no cloud polling
  (`iot_class: local_push`).
- 🔍 **Auto-discovery** of devices on the network (mDNS) when adding.
- 🔑 **Self-healing key**: the device's public key changes on reboot — the
  integration re-resolves it from mDNS and reconnects automatically.

## Supported devices

- **Ballu Platinum Evolution** (and other models with a syncleo module, `devtype=20`).
- Firmware `fw=1.22`, `protocol=3`, UDP port `41122`.

Other RusClimate/Polaris syncleo devices with a different `devtype` are not
supported (their command set differs) and are hidden during discovery.

## Installation

### Option A — HACS (recommended)

You need [HACS](https://hacs.xyz/) installed first. Then:

1. Open **HACS** in the Home Assistant sidebar.
2. Click the **⋮** menu (top-right) → **Custom repositories**.
3. Paste the repository URL and pick the category:
   - Repository: `https://github.com/toper777/ballu-ac-homeassistant`
   - Category: **Integration**
   - Click **Add**.
4. Find **Ballu AC (syncleo)** in the list, open it and click **Download**.
5. **Restart Home Assistant** (Settings → System → ⋮ → Restart).

### Option B — Manual

1. Download this repository (Code → Download ZIP, or clone it).
2. Copy the folder `custom_components/ballu_ac/` into your Home Assistant config,
   so you get `<config>/custom_components/ballu_ac/`.
3. **Fully restart** Home Assistant (not just a YAML reload).

## Configuration

### Step 1 — Get the token (from the Ballu Home app)

The **token** is the only secret that is *not* announced on the network, so you
must obtain it once from the official app:

**Ballu Home app** → your device → **Share** → **QR code**.

The QR (its text or URL) contains the token — a 32-character hex string. You can
either scan/copy the QR text, or read the token out of it manually. The device's
public key is **not** needed manually — it's resolved from mDNS automatically.

### Step 2 — Add the integration

1. **Settings → Devices & services → Add integration → “Ballu AC”.**
2. Choose one of three methods:

| Method | What to do |
|--------|-----------|
| **Search the network** (recommended) | Active mDNS scan; pick your AC from the list, then enter the **token**. |
| **QR code** | Paste the QR contents (text or an image URL) from the Ballu Home app; the public key is pulled from mDNS. |
| **Manual** | Enter IP, port, token and public key by hand. |

3. Done — the AC and its entities appear as a device.

> The token is validated during setup: if it's wrong, the device replies to the
> handshake but rejects commands, and the integration will **refuse to create the
> entry** with an "invalid credentials" error — so you won't end up with a dead device.

## Entities

| Entity            | Platform | Description                                |
|-------------------|----------|--------------------------------------------|
| Air conditioner   | climate  | mode, temperature, fan, swing, presets     |
| Room Temperature  | sensor   | room temperature                           |
| Ionizer           | switch   | ionizer                                    |
| Display           | switch   | display backlight                          |

## Automation example

Setting a specific temperature is done with the `climate.set_temperature` service
(the “device action” block has no temperature field — that's a Home Assistant core
limitation, not this integration):

```yaml
action: climate.set_temperature
target:
  entity_id: climate.ballu_ac
data:
  temperature: 22
  hvac_mode: cool
```

## How it works

The syncleo protocol is UDP on port 41122, encrypted:

1. X25519 ECDH exchange with the device's public key (from mDNS TXT `public=`).
2. SHA-256 of the shared secret → AES-CBC keys (rotated per packet sequence).
3. A handshake carrying the auth token, then commands/state in encrypted frames.

Detailed protocol notes and the command map are in [CLAUDE.md](CLAUDE.md).

## Research tools (`tools/`)

Standalone scripts (no Home Assistant required, just `pip install cryptography zeroconf`):

```bash
python tools/ballu_listen.py scan   # find devices on the network (IP, pubkey)
python tools/ballu_listen.py        # passive command listener
python tools/ballu_cmd.py           # interactive command sender
```

Set `DEVICE_IP` and `TOKEN_HEX` at the top of the script first (the public key is
resolved from mDNS automatically).

## Troubleshooting

Enable verbose logs in `configuration.yaml`:

```yaml
logger:
  logs:
    custom_components.ballu_ac: debug
```

- **Device unavailable / handshake times out** — make sure Home Assistant and the
  AC are on the same subnet, and that UDP/mDNS isn't blocked. The public key is
  refreshed automatically if the device rebooted.
- **"Invalid credentials" when adding** — the token is wrong; re-copy it from the
  Ballu Home app QR code.

## Security notes

- **The token is your device password.** It's stored in Home Assistant's config
  and sent (encrypted) to the device. Anyone with your token can control that AC.
- **mDNS discovery trusts the local network.** Discovery and automatic public-key
  refresh take the device address and public key from mDNS announcements. A
  malicious host on the *same LAN* could spoof a syncleo announcement and trick
  the integration into handshaking with it, potentially capturing the token.
  Only add/refresh devices on a network you trust; on segmented networks keep IoT
  and Home Assistant where no untrusted host can spoof mDNS.
- **QR image URLs are fetched server-side** with SSRF guards (http/https only,
  private/loopback addresses blocked, 5 MB size cap). Prefer pasting the QR *text*
  over an image URL when possible.

Found a security issue? Please open an issue (or report privately) on the
[repository](https://github.com/toper777/ballu-ac-homeassistant).

## License

[MIT](LICENSE) © toper777
