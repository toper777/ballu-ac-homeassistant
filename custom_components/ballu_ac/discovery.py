"""mDNS helpers: scan syncleo devices and locate one by its stable identity.

Neither the IP address nor the public key identifies a device over time: the IP
changes with the router / DHCP lease, and the X25519 public key rotates on every
device reboot. The MAC address announced in the TXT record (`macaddr=`, also used
as the service instance name) is the only stable identifier, so relocation looks
devices up by MAC.
"""
from __future__ import annotations

import re

from homeassistant.core import HomeAssistant

from .const import DEFAULT_PORT

SYNCLEO_SERVICE = "_syncleo._udp.local."
# Only these syncleo device types are air conditioners we support. Other
# syncleo gear (e.g. Polaris humidifiers, devtype=77) shares the same mDNS
# service but speaks a different command set.
SUPPORTED_DEVTYPES = {"20"}


def decode_props(raw: dict) -> dict[str, str]:
    """Normalise zeroconf TXT properties (bytes→bytes) to str→str."""
    props: dict[str, str] = {}
    for k, v in (raw or {}).items():
        key = k.decode("ascii", "replace") if isinstance(k, bytes) else str(k)
        val = v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")
        props[key] = val
    return props


def pubkey_from_props(props: dict[str, str]) -> str:
    """Extract the 64-hex X25519 public key from mDNS TXT properties.

    The key is in the `public` field; `curve` is only a numeric curve id
    (e.g. "29") and is accepted only if it happens to be valid 64-hex.
    """
    for field in ("public", "pubkey", "curve"):
        val = (props.get(field) or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", val):
            return val
    return ""


def normalize_mac(raw: str | None) -> str:
    """'AA:BB:CC:DD:EE:01' / 'aa-bb-…' / 'aabbccddee01' → 'aabbccddee01', else ''."""
    hexchars = re.sub(r"[^0-9a-fA-F]", "", raw or "").lower()
    return hexchars if len(hexchars) == 12 else ""


def mac_from_props(props: dict[str, str], instance_name: str = "") -> str:
    """MAC from TXT `macaddr`, falling back to the service instance name."""
    for field in ("macaddr", "mac"):
        mac = normalize_mac(props.get(field))
        if mac:
            return mac
    label = (instance_name or "").split(".")[0]
    return label.lower() if re.fullmatch(r"[0-9a-fA-F]{12}", label) else ""


def is_supported_devtype(props: dict[str, str]) -> bool:
    """A device announcing an unsupported devtype is not an AC we can drive.

    A device that does not announce devtype at all is kept (better to show
    than to hide).
    """
    devtype = props.get("devtype", "")
    return not devtype or devtype in SUPPORTED_DEVTYPES


async def async_scan(hass: HomeAssistant, timeout: float = 5.0) -> list[dict]:
    """Actively browse `_syncleo._udp.local.` and return supported devices.

    Uses Home Assistant's shared Zeroconf instance (creating a raw Zeroconf()
    inside HA is forbidden). Each item: host, port, pubkey, mac, name.
    """
    import asyncio

    from homeassistant.components import zeroconf as ha_zeroconf
    from zeroconf import ServiceStateChange
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo

    aiozc = await ha_zeroconf.async_get_async_instance(hass)
    names: list[str] = []

    # zeroconf invokes handlers with keyword arguments, so the parameter names
    # must match exactly (zeroconf / service_type / name / state_change).
    def _on_change(zeroconf, service_type, name, state_change) -> None:
        if state_change is ServiceStateChange.Added and name not in names:
            names.append(name)

    browser = AsyncServiceBrowser(aiozc.zeroconf, SYNCLEO_SERVICE, handlers=[_on_change])
    try:
        await asyncio.sleep(timeout)
    finally:
        await browser.async_cancel()

    devices: list[dict] = []
    for name in names:
        info = AsyncServiceInfo(SYNCLEO_SERVICE, name)
        if not await info.async_request(aiozc.zeroconf, 3000):
            continue
        addresses = [a for a in info.parsed_addresses() if ":" not in a]  # IPv4 only
        if not addresses:
            continue
        props = decode_props(info.properties)
        if not is_supported_devtype(props):
            continue
        devices.append({
            "host":   addresses[0],
            "port":   info.port or DEFAULT_PORT,
            "pubkey": pubkey_from_props(props),
            "mac":    mac_from_props(props, name),
            "name":   props.get("name") or name.split(".")[0] or "Ballu AC",
        })
    return devices
