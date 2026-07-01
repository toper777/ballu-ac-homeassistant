"""Switch entities for Ballu AC boolean features."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import DOMAIN, ballu_device_info
from .syncleo import SyncleoClient, ACState

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    client: SyncleoClient = hass.data[DOMAIN][entry.entry_id]
    name = entry.title
    async_add_entities([
        BalluSwitch(client, name, "ionizer",  "Ionizer",  "mdi:air-filter",
                    lambda s: s.ionizer, client.set_ionizer),
        BalluSwitch(client, name, "display",  "Display",  "mdi:monitor",
                    lambda s: s.display, client.set_display),
    ])


class BalluSwitch(SwitchEntity):
    """Generic boolean switch for a Ballu AC feature."""

    _attr_has_entity_name = True

    def __init__(
        self,
        client: SyncleoClient,
        device_name: str,
        key: str,
        name: str,
        icon: str,
        get_state,   # Callable[[ACState], Optional[bool]]
        set_state,   # Coroutine[bool]
    ) -> None:
        self._client    = client
        self._get_state = get_state
        self._set_state = set_state
        self._attr_name        = name
        self._attr_icon        = icon
        self._attr_unique_id   = f'ballu_{client.host.replace(".", "_")}_{key}'
        self._attr_device_info = ballu_device_info(client, device_name)
        client.register_state_callback(self._on_state_change)

    @property
    def is_on(self) -> bool | None:
        val = self._get_state(self._client.state)
        return bool(val) if val is not None else None

    @property
    def available(self) -> bool:
        return self._client._connected and self._get_state(self._client.state) is not None

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set_state(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set_state(False)

    def _on_state_change(self, state: ACState) -> None:
        self.schedule_update_ha_state()
