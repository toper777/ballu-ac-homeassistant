"""The integration must survive the AC's IP changing (e.g. a new Wi-Fi router)."""
from __future__ import annotations

from ipaddress import ip_address

from homeassistant.config_entries import SOURCE_ZEROCONF, ConfigEntryState
from homeassistant.const import CONF_HOST, CONF_NAME, CONF_PORT, CONF_TOKEN
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ballu_ac.const import (
    CONF_DEVICE_KEY, CONF_MAC, CONF_PUBKEY, CONF_UID_BASE, DOMAIN,
)

from .conftest import PORT

OLD_IP, NEW_IP = "192.168.1.10", "192.168.50.20"
MAC_A, MAC_B = "aabbccddee01", "aabbccddee02"
TOKEN_A, TOKEN_B = "a" * 32, "b" * 32
KEY_A1, KEY_A2, KEY_B = "1" * 64, "2" * 64, "3" * 64
LEGACY_UID = "192_168_1_10"
LEGACY_DEVICE = f"{OLD_IP}:{PORT}"


def v1_entry() -> MockConfigEntry:
    """An entry exactly as v0.3.0 created it."""
    return MockConfigEntry(
        domain=DOMAIN, version=1, title="Bedroom", unique_id=LEGACY_DEVICE,
        data={CONF_HOST: OLD_IP, CONF_PORT: PORT, CONF_TOKEN: TOKEN_A,
              CONF_PUBKEY: KEY_A1, CONF_NAME: "Bedroom"},
    )


def v2_entry(mac: str = MAC_A, host: str = OLD_IP, pubkey: str = KEY_A1) -> MockConfigEntry:
    """A migrated entry (legacy ids frozen), with or without a learned MAC."""
    return MockConfigEntry(
        domain=DOMAIN, version=2, title="Bedroom", unique_id=mac or LEGACY_DEVICE,
        data={CONF_HOST: host, CONF_PORT: PORT, CONF_TOKEN: TOKEN_A,
              CONF_PUBKEY: pubkey, CONF_NAME: "Bedroom", CONF_MAC: mac,
              CONF_UID_BASE: LEGACY_UID, CONF_DEVICE_KEY: LEGACY_DEVICE},
    )


async def setup(hass, entry: MockConfigEntry) -> None:
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)


def climate_ids(hass, entry) -> list[tuple[str, str]]:
    return sorted(
        (e.entity_id, e.unique_id)
        for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
        if e.domain == "climate"
    )


def zeroconf(ip: str, mac: str, pubkey: str, devtype: str = "20") -> ZeroconfServiceInfo:
    return ZeroconfServiceInfo(
        ip_address=ip_address(ip), ip_addresses=[ip_address(ip)], port=PORT,
        hostname=f"{mac}.local.", type="_syncleo._udp.local.",
        name=f"{mac}._syncleo._udp.local.",
        properties={"public": pubkey, "curve": "29", "macaddr": ":".join(
            mac[i:i + 2] for i in range(0, 12, 2)), "devtype": devtype},
    )


# ── migration ────────────────────────────────────────────────────────────────

async def test_migration_keeps_entity_and_device_ids(hass, fake_net):
    fake_net.add(OLD_IP, MAC_A, KEY_A1, TOKEN_A)
    entry = v1_entry()
    entry.add_to_hass(hass)
    # The climate entity as v0.3.0 registered it, renamed by the user.
    er.async_get(hass).async_get_or_create(
        "climate", DOMAIN, f"ballu_{LEGACY_UID}_climate",
        config_entry=entry, suggested_object_id="bedroom_ac",
    )

    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)

    assert entry.state is ConfigEntryState.LOADED
    assert entry.version == 2
    assert climate_ids(hass, entry) == [("climate.bedroom_ac", f"ballu_{LEGACY_UID}_climate")]
    assert dr.async_get(hass).async_get_device(identifiers={(DOMAIN, LEGACY_DEVICE)})
    # The stable MAC is learned in the background and becomes the unique_id.
    assert entry.data[CONF_MAC] == MAC_A
    assert entry.unique_id == MAC_A


async def test_migration_of_entry_without_data(hass):
    # "Ignored" discoveries are stored as entries with no data at all.
    from custom_components.ballu_ac import async_migrate_entry

    entry = MockConfigEntry(domain=DOMAIN, version=1, unique_id=LEGACY_DEVICE, data={})
    entry.add_to_hass(hass)

    assert await async_migrate_entry(hass, entry)
    assert entry.version == 2
    assert dict(entry.data) == {}


# ── relocation on setup ──────────────────────────────────────────────────────

async def test_router_change_relocates_by_mac(hass, fake_net):
    # New router: new IP, and the AC rebooted so its public key rotated too.
    fake_net.add(NEW_IP, MAC_A, KEY_A2, TOKEN_A)
    entry = v2_entry()
    await setup(hass, entry)

    assert entry.state is ConfigEntryState.LOADED
    assert entry.data[CONF_HOST] == NEW_IP
    assert entry.data[CONF_PUBKEY] == KEY_A2
    assert climate_ids(hass, entry) == [("climate.bedroom", f"ballu_{LEGACY_UID}_climate")]


async def test_old_ip_taken_by_other_ac_is_not_hijacked(hass, fake_net):
    fake_net.add(OLD_IP, MAC_B, KEY_B, TOKEN_B)   # the neighbour got our old IP
    fake_net.add(NEW_IP, MAC_A, KEY_A2, TOKEN_A)
    entry = v2_entry()
    await setup(hass, entry)

    assert entry.data[CONF_HOST] == NEW_IP
    assert entry.data[CONF_MAC] == MAC_A


async def test_unknown_mac_never_binds_to_foreign_device(hass, fake_net):
    # MAC not learned yet; our AC is gone and another AC now sits at the old IP.
    fake_net.add(OLD_IP, MAC_B, KEY_B, TOKEN_B)
    entry = v2_entry(mac="")
    await setup(hass, entry)

    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert entry.data[CONF_HOST] == OLD_IP
    assert entry.data[CONF_PUBKEY] == KEY_A1


async def test_unknown_mac_found_by_unchanged_key(hass, fake_net):
    # Router swapped without the AC rebooting: same key, new IP.
    fake_net.add(NEW_IP, MAC_A, KEY_A1, TOKEN_A)
    entry = v2_entry(mac="")
    await setup(hass, entry)

    assert entry.state is ConfigEntryState.LOADED
    assert entry.data[CONF_HOST] == NEW_IP
    assert entry.data[CONF_MAC] == MAC_A
    assert entry.unique_id == MAC_A


async def test_unknown_mac_key_rotated_same_ip_needs_our_token(hass, fake_net):
    # Same IP, rebooted (new key): accepted only because it ACKs *our* token.
    fake_net.add(OLD_IP, MAC_A, KEY_A2, TOKEN_A)
    entry = v2_entry(mac="")
    await setup(hass, entry)

    assert entry.state is ConfigEntryState.LOADED
    assert entry.data[CONF_PUBKEY] == KEY_A2
    assert entry.data[CONF_MAC] == MAC_A


# ── passive zeroconf rediscovery ─────────────────────────────────────────────

async def test_zeroconf_updates_known_device_ip(hass, fake_net):
    fake_net.add(OLD_IP, MAC_A, KEY_A1, TOKEN_A)
    entry = v2_entry()
    await setup(hass, entry)

    fake_net.clear()
    fake_net.add(NEW_IP, MAC_A, KEY_A2, TOKEN_A)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zeroconf(NEW_IP, MAC_A, KEY_A2),
    )
    await hass.async_block_till_done(wait_background_tasks=True)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert entry.data[CONF_HOST] == NEW_IP
    assert entry.data[CONF_PUBKEY] == KEY_A2
    assert entry.state is ConfigEntryState.LOADED
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1


async def test_zeroconf_matches_legacy_entry_by_key(hass, fake_net):
    fake_net.add(OLD_IP, MAC_A, KEY_A1, TOKEN_A)
    entry = v2_entry(mac="")
    entry.add_to_hass(hass)  # not set up: the old IP is dead after the router swap

    fake_net.clear()
    fake_net.add(NEW_IP, MAC_A, KEY_A1, TOKEN_A)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zeroconf(NEW_IP, MAC_A, KEY_A1),
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert entry.data[CONF_HOST] == NEW_IP
    assert entry.data[CONF_MAC] == MAC_A
    assert entry.unique_id == MAC_A


async def test_zeroconf_does_not_offer_legacy_entry_with_stale_key(hass, fake_net):
    # Entry has no MAC yet and an outdated key, but the device is at the same IP:
    # it must not be offered as a new device.
    entry = v2_entry(mac="", pubkey=KEY_A1)
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zeroconf(OLD_IP, MAC_A, KEY_A2),
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1


async def test_zeroconf_ignores_non_ac_devices(hass, fake_net):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF},
        data=zeroconf(NEW_IP, MAC_B, KEY_B, devtype="77"),  # Polaris
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "not_supported_device"


# ── options flow ─────────────────────────────────────────────────────────────

async def test_options_flow_changes_host_in_entry_data(hass, fake_net):
    fake_net.add(OLD_IP, MAC_A, KEY_A1, TOKEN_A)
    entry = v2_entry()
    await setup(hass, entry)

    fake_net.clear()
    fake_net.add(NEW_IP, MAC_A, KEY_A1, TOKEN_A)
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"],
        {CONF_NAME: "Bedroom", CONF_HOST: NEW_IP, CONF_PORT: PORT,
         CONF_TOKEN: TOKEN_A, CONF_PUBKEY: KEY_A1},
    )
    await hass.async_block_till_done(wait_background_tasks=True)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.data[CONF_HOST] == NEW_IP          # data, not options
    assert entry.state is ConfigEntryState.LOADED


async def test_options_flow_rejects_wrong_token(hass, fake_net):
    fake_net.add(OLD_IP, MAC_A, KEY_A1, TOKEN_A)
    entry = v2_entry()
    await setup(hass, entry)

    flow = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        flow["flow_id"],
        {CONF_NAME: "Bedroom", CONF_HOST: OLD_IP, CONF_PORT: PORT,
         CONF_TOKEN: TOKEN_B, CONF_PUBKEY: KEY_A1},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_credentials"}
    assert entry.data[CONF_TOKEN] == TOKEN_A
