"""Runtime mDNS helper: look up a device's current public key by host.

The device's X25519 public key is not permanent — it changes when the device
(or its Wi-Fi module) reboots. We therefore re-resolve it from mDNS whenever a
handshake fails, so a rotated key self-heals instead of requiring the user to
re-enter it.
"""
from __future__ import annotations

import re

from homeassistant.core import HomeAssistant

SYNCLEO_SERVICE = "_syncleo._udp.local."


def pubkey_from_props(props: dict[str, str]) -> str:
    """Extract the 64-hex X25519 public key from mDNS TXT properties.

    The key is in the `public` field; `curve` is only a numeric curve id.
    """
    for field in ("public", "pubkey", "curve"):
        val = (props.get(field) or "").strip().lower()
        if re.fullmatch(r"[0-9a-fA-F]{64}", val):
            return val
    return ""


async def async_pubkey_for_host(
    hass: HomeAssistant, host: str, timeout: float = 5.0
) -> str | None:
    """Scan mDNS and return the current public key announced by `host`.

    Returns None if the device is not found or announces no valid key.
    """
    import asyncio

    from homeassistant.components import zeroconf as ha_zeroconf
    from zeroconf import ServiceStateChange
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo

    aiozc = await ha_zeroconf.async_get_async_instance(hass)
    names: list[str] = []

    def _on_change(zeroconf, service_type, name, state_change) -> None:
        if state_change is ServiceStateChange.Added and name not in names:
            names.append(name)

    browser = AsyncServiceBrowser(aiozc.zeroconf, SYNCLEO_SERVICE, handlers=[_on_change])
    try:
        await asyncio.sleep(timeout)
    finally:
        await browser.async_cancel()

    for name in names:
        info = AsyncServiceInfo(SYNCLEO_SERVICE, name)
        if not await info.async_request(aiozc.zeroconf, 3000):
            continue
        if host not in info.parsed_addresses():
            continue
        props: dict[str, str] = {}
        for k, v in (info.properties or {}).items():
            key = k.decode("ascii", "replace") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")
            props[key] = val
        pk = pubkey_from_props(props)
        if pk:
            return pk
    return None
