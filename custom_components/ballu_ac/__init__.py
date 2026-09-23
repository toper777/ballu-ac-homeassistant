"""Ballu AC (syncleo UDP protocol) Home Assistant integration."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, format_mac
from homeassistant.helpers.entity import DeviceInfo

from .const import (
    CONF_DEVICE_KEY,
    CONF_MAC,
    CONF_PUBKEY,
    CONF_UID_BASE,
    DEFAULT_PORT,
    DOMAIN,
)

if TYPE_CHECKING:
    from .syncleo import SyncleoClient

PLATFORMS = [Platform.CLIMATE, Platform.SENSOR, Platform.SWITCH]
_LOGGER    = logging.getLogger(__name__)


def entity_unique_id(entry: ConfigEntry, key: str) -> str:
    """Per-entity unique_id built from the frozen identity, never from the IP."""
    return f"ballu_{entry.data[CONF_UID_BASE]}_{key}"


def ballu_device_info(entry: ConfigEntry, client: "SyncleoClient", name: str) -> DeviceInfo:
    """Shared DeviceInfo so all entities group under one HA device.

    sw_version comes from the handshake (cmd=0x00) and is available once
    connect() has completed — i.e. before any platform is set up.
    """
    info = DeviceInfo(
        identifiers={(DOMAIN, entry.data[CONF_DEVICE_KEY])},
        manufacturer="Ballu",
        name=name,
        model="Platinum Evolution (syncleo)",
    )
    if mac := entry.data.get(CONF_MAC):
        info["connections"] = {(CONNECTION_NETWORK_MAC, format_mac(mac))}
    if client.fw_version:
        info["sw_version"] = client.fw_version
    return info


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """v1 → v2: freeze the identifiers that v1 derived from the IP address.

    v1 computed entity unique_ids and the device identifier from the *current*
    host, so an IP change would have re-created every entity and the device.
    Freezing the existing values keeps entity ids, history and automations intact.
    """
    if entry.version > 2:
        return False  # downgraded from a newer version of the integration
    if entry.version == 1:
        host = entry.data[CONF_HOST]
        port = entry.data.get(CONF_PORT, DEFAULT_PORT)
        hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                CONF_MAC: entry.data.get(CONF_MAC, ""),
                CONF_UID_BASE: host.replace(".", "_"),
                CONF_DEVICE_KEY: f"{host}:{port}",
            },
            version=2,
        )
        _LOGGER.info("Ballu AC %s: migrated config entry to version 2", host)
    return True


@callback
def async_update_connection(hass: HomeAssistant, entry: ConfigEntry, updates: dict) -> bool:
    """Persist new connection data; adopt a newly learned MAC as unique_id.

    Returns True if the entry changed.
    """
    kwargs: dict = {"data": {**entry.data, **updates}}
    mac = updates.get(CONF_MAC)
    if mac and entry.unique_id != mac:
        taken = any(
            other.unique_id == mac
            for other in hass.config_entries.async_entries(DOMAIN)
            if other.entry_id != entry.entry_id
        )
        if taken:
            _LOGGER.warning(
                "Ballu AC %s: another config entry already owns MAC %s — "
                "this device seems to be configured twice", entry.title, mac,
            )
        else:
            kwargs["unique_id"] = mac
    return hass.config_entries.async_update_entry(entry, **kwargs)


def _other_entries_macs(hass: HomeAssistant, entry: ConfigEntry) -> set[str]:
    return {
        mac
        for other in hass.config_entries.async_entries(DOMAIN)
        if other.entry_id != entry.entry_id and (mac := other.data.get(CONF_MAC))
    }


async def _async_connect(hass: HomeAssistant, entry: ConfigEntry) -> "SyncleoClient":
    """Connect at the last known address, or find the device again on the LAN.

    The IP changes with the router / DHCP lease and the public key rotates on
    every device reboot, so on failure the device is re-located via mDNS by a
    *stable* identity. A plain "whoever answers at the old IP" is not enough:
    after a router change that IP may belong to another AC, and the handshake
    succeeds even with a foreign token.
    """
    from .discovery import async_scan
    from .syncleo import SyncleoClient

    data = entry.data
    mac = data.get(CONF_MAC, "")

    def make(host: str, port: int, pubkey: str) -> SyncleoClient:
        return SyncleoClient(
            host=host, port=port, token_hex=data[CONF_TOKEN], pubkey_hex=pubkey
        )

    client = make(data[CONF_HOST], data[CONF_PORT], data[CONF_PUBKEY])
    try:
        await client.connect()
        return client
    except TimeoutError:
        pass

    _LOGGER.warning(
        "Ballu AC %s: no answer at %s — looking for the device on the network "
        "(IP changed or key rotated?)", entry.title, data[CONF_HOST],
    )
    devices = [d for d in await async_scan(hass) if d["pubkey"]]

    # (device, identity_proven) in order of confidence.
    candidates: list[tuple[dict, bool]] = []
    if mac:
        candidates = [(d, True) for d in devices if d["mac"] == mac]
    else:
        # MAC not learned yet. The public key is unique per device boot, so an
        # unchanged key identifies the device even at a new IP. A device merely
        # sitting at the old IP (key rotated) must prove itself with our token.
        claimed = _other_entries_macs(hass, entry)
        candidates = [(d, True) for d in devices if d["pubkey"] == data[CONF_PUBKEY]]
        candidates += [
            (d, False) for d in devices
            if d["host"] == data[CONF_HOST]
            and d["pubkey"] != data[CONF_PUBKEY]
            and d["mac"] not in claimed
        ]

    for dev, proven in candidates:
        client = make(dev["host"], dev["port"], dev["pubkey"])
        try:
            await client.connect()
        except TimeoutError:
            continue
        if not proven and not await client.async_verify_auth():
            await client.disconnect()
            continue
        updates = {
            CONF_HOST: dev["host"], CONF_PORT: dev["port"], CONF_PUBKEY: dev["pubkey"],
        }
        if not mac and dev["mac"]:
            updates[CONF_MAC] = dev["mac"]
        if dev["host"] != data[CONF_HOST]:
            _LOGGER.warning(
                "Ballu AC %s: device moved %s → %s", entry.title, data[CONF_HOST], dev["host"],
            )
        async_update_connection(hass, entry, updates)
        return client

    raise ConfigEntryNotReady(
        f"Ballu AC {entry.title}: device not found at {data[CONF_HOST]} nor on the network"
    )


async def _async_learn_mac(hass: HomeAssistant, entry: ConfigEntry, pubkey: str) -> None:
    """Record the stable MAC of an entry that does not know it yet.

    Matching on the public key we just completed a handshake with ties the mDNS
    record to this very device, whatever its IP.
    """
    from .discovery import async_scan

    for dev in await async_scan(hass):
        if dev["mac"] and dev["pubkey"] == pubkey:
            async_update_connection(hass, entry, {CONF_MAC: dev["mac"]})
            _LOGGER.info("Ballu AC %s: learned MAC %s", entry.title, dev["mac"])
            return


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up one Ballu AC device from a config entry."""
    # Entity/device identity, decided once and then frozen. Migrated v1 entries
    # already carry their legacy IP-derived values.
    if CONF_UID_BASE not in entry.data:
        base = entry.data.get(CONF_MAC) or entry.entry_id
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, CONF_UID_BASE: base, CONF_DEVICE_KEY: base},
        )

    client = await _async_connect(hass, entry)

    # Reconnect (re-locating the device if its IP or key changed) if the link
    # drops at runtime.
    client.on_connection_lost = lambda: hass.async_create_task(
        hass.config_entries.async_reload(entry.entry_id)
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = client
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    if not entry.data.get(CONF_MAC):
        entry.async_create_background_task(
            hass,
            _async_learn_mac(hass, entry, client.pubkey_hex),
            f"ballu_ac learn MAC {entry.entry_id}",
        )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and disconnect the client."""
    if await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        client = hass.data[DOMAIN].pop(entry.entry_id, None)
        if client:
            await client.disconnect()
        return True
    return False
