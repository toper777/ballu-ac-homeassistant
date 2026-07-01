"""Room temperature sensor for Ballu AC."""
from __future__ import annotations

from homeassistant.components.sensor import (
    SensorEntity,
    SensorDeviceClass,
    SensorStateClass,
)
from homeassistant.const import UnitOfTemperature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import DOMAIN, ballu_device_info
from .syncleo import SyncleoClient, ACState


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    client: SyncleoClient = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BalluRoomTempSensor(client, entry.title)])


class BalluRoomTempSensor(SensorEntity):
    """Room temperature reported by the AC unit (cmd=0x14)."""

    _attr_device_class        = SensorDeviceClass.TEMPERATURE
    _attr_state_class         = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_has_entity_name     = True
    _attr_name                = "Room Temperature"
    _attr_icon                = "mdi:thermometer"

    def __init__(self, client: SyncleoClient, device_name: str) -> None:
        self._client = client
        self._attr_unique_id = f'ballu_{client.host.replace(".", "_")}_room_temp'
        self._attr_device_info = ballu_device_info(client, device_name)
        client.register_state_callback(self._on_state_change)

    @property
    def native_value(self) -> int | None:
        return self._client.state.room_temp

    @property
    def available(self) -> bool:
        return self._client._connected and self._client.state.room_temp is not None

    def _on_state_change(self, state: ACState) -> None:
        self.schedule_update_ha_state()
