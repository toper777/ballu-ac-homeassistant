"""Ballu AC (syncleo UDP protocol) Home Assistant integration."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN, CONF_PUBKEY, DEFAULT_PORT

if TYPE_CHECKING:
    from .syncleo import SyncleoClient

PLATFORMS = [Platform.CLIMATE, Platform.SENSOR, Platform.SWITCH]
_LOGGER    = logging.getLogger(__name__)


def ballu_device_info(client: "SyncleoClient", name: str) -> DeviceInfo:
    """Shared DeviceInfo so all entities group under one HA device.

    sw_version comes from the handshake (cmd=0x00) and is available once
    connect() has completed — i.e. before any platform is set up.
    """
    info = DeviceInfo(
        identifiers={(DOMAIN, f"{client.host}:{client.port}")},
        manufacturer="Ballu",
        name=name,
        model="Platinum Evolution (syncleo)",
    )
    if client.fw_version:
        info["sw_version"] = client.fw_version
    return info


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up one Ballu AC device from a config entry."""
    # Import here to avoid blocking import at module load time
    from .syncleo import SyncleoClient

    host = entry.data[CONF_HOST]

    def _make_client(pubkey: str) -> "SyncleoClient":
        return SyncleoClient(
            host=host,
            port=entry.data[CONF_PORT],
            token_hex=entry.data[CONF_TOKEN],
            pubkey_hex=pubkey,
        )

    client = _make_client(entry.data[CONF_PUBKEY])
    try:
        await client.connect()
    except TimeoutError:
        # The device's X25519 key may have rotated (e.g. after a reboot).
        # Re-resolve it from mDNS and retry once before giving up.
        from .discovery import async_pubkey_for_host

        _LOGGER.warning(
            "Ballu AC %s: handshake failed — refreshing public key via mDNS", host
        )
        new_pubkey = await async_pubkey_for_host(hass, host)
        if new_pubkey and new_pubkey != entry.data[CONF_PUBKEY]:
            _LOGGER.warning(
                "Ballu AC %s: public key changed, updating entry and retrying", host
            )
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, CONF_PUBKEY: new_pubkey}
            )
            client = _make_client(new_pubkey)
            try:
                await client.connect()
            except TimeoutError as exc:
                raise ConfigEntryNotReady(
                    f"Ballu AC {host}: handshake failed after key refresh"
                ) from exc
        else:
            raise ConfigEntryNotReady(
                f"Ballu AC {host}: handshake timed out (device unreachable "
                f"or public key unavailable via mDNS)"
            )

    # Reconnect (incl. picking up a rotated key) if the link drops at runtime.
    client.on_connection_lost = lambda: hass.async_create_task(
        hass.config_entries.async_reload(entry.entry_id)
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = client
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and disconnect the client."""
    if await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        client = hass.data[DOMAIN].pop(entry.entry_id, None)
        if client:
            await client.disconnect()
        return True
    return False
