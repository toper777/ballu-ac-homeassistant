"""Home Assistant climate entity for Ballu AC via syncleo UDP."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.components.climate.const import (
    FAN_AUTO, FAN_LOW, FAN_MEDIUM, FAN_HIGH,
    SWING_OFF, SWING_ON,
    PRESET_NONE,
)
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import DOMAIN, ballu_device_info
from .syncleo import SyncleoClient, ACState

_LOGGER = logging.getLogger(__name__)

HA_TO_AC: dict[HVACMode, str] = {
    HVACMode.OFF:      'off',
    HVACMode.AUTO:     'auto',
    HVACMode.COOL:     'cool',
    HVACMode.DRY:      'dry',
    HVACMode.HEAT:     'heat',
    HVACMode.FAN_ONLY: 'fan_only',
}
AC_TO_HA: dict[str, HVACMode] = {v: k for k, v in HA_TO_AC.items()}

HA_FAN_TO_AC: dict[str, str] = {
    FAN_AUTO:   'auto',
    FAN_LOW:    'low',
    FAN_MEDIUM: 'medium',
    FAN_HIGH:   'high',
}
AC_FAN_TO_HA: dict[str, str] = {v: k for k, v in HA_FAN_TO_AC.items()}

SWING_VERTICAL   = "vertical"
SWING_HORIZONTAL = "horizontal"
SWING_BOTH       = "both"

VH_TO_SWING: dict[tuple[bool, bool], str] = {
    (False, False): SWING_OFF,
    (True,  False): SWING_VERTICAL,
    (False, True):  SWING_HORIZONTAL,
    (True,  True):  SWING_BOTH,
}
SWING_TO_VH: dict[str, tuple[bool, bool]] = {v: k for k, v in VH_TO_SWING.items()}

PRESET_TURBO = "turbo"
PRESET_NIGHT = "night"
PRESET_ECO   = "eco"
PRESET_QUIET = "quiet"
ALL_PRESETS  = [PRESET_NONE, PRESET_TURBO, PRESET_NIGHT, PRESET_ECO, PRESET_QUIET]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    client: SyncleoClient = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BalluClimate(client, entry.title)])


class BalluClimate(ClimateEntity):
    """Ballu AC climate entity.

    HVAC modes : off / auto / cool / dry / heat / fan_only
    Fan modes  : auto / low / medium / high          (cmd=0x0f)
    Swing modes: off / vertical / horizontal / both  (cmd=0x42)
    Presets    : none / turbo / night / eco / quiet
    """

    _attr_has_entity_name         = True
    _attr_icon                    = "mdi:air-conditioner"
    _attr_temperature_unit        = UnitOfTemperature.CELSIUS
    _attr_min_temp                = 16
    _attr_max_temp                = 30
    _attr_target_temperature_step = 1

    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
        | ClimateEntityFeature.SWING_MODE
        | ClimateEntityFeature.PRESET_MODE
        | ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
    )

    _attr_hvac_modes   = list(HA_TO_AC.keys())
    _attr_fan_modes    = [FAN_AUTO, FAN_LOW, FAN_MEDIUM, FAN_HIGH]
    _attr_swing_modes  = [SWING_OFF, SWING_VERTICAL, SWING_HORIZONTAL, SWING_BOTH]
    _attr_preset_modes = ALL_PRESETS

    def __init__(self, client: SyncleoClient, name: str) -> None:
        self._client = client
        self._attr_name = None  # primary entity takes the device name
        self._attr_unique_id = f'ballu_{client.host.replace(".", "_")}_climate'
        self._attr_device_info = ballu_device_info(client, name)
        self._last_mode: str = 'cool'
        client.register_state_callback(self._on_state_change)

    @property
    def hvac_mode(self) -> HVACMode:
        mode = self._client.state.mode
        if mode is None or mode == 'off':
            return HVACMode.OFF
        return AC_TO_HA.get(mode, HVACMode.OFF)

    @property
    def target_temperature(self) -> int | None:
        return self._client.state.set_temp

    @property
    def current_temperature(self) -> int | None:
        return self._client.state.room_temp

    @property
    def fan_mode(self) -> str:
        return AC_FAN_TO_HA.get(self._client.state.fan or 'auto', FAN_AUTO)

    @property
    def swing_mode(self) -> str:
        s = self._client.state
        return VH_TO_SWING.get((bool(s.v_swing), bool(s.h_swing)), SWING_OFF)

    @property
    def preset_mode(self) -> str:
        s = self._client.state
        if s.turbo: return PRESET_TURBO
        if s.night: return PRESET_NIGHT
        if s.eco:   return PRESET_ECO
        if s.quiet: return PRESET_QUIET
        return PRESET_NONE

    @property
    def available(self) -> bool:
        return self._client._connected

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        ac_mode = HA_TO_AC.get(hvac_mode, 'off')
        if ac_mode != 'off':
            self._last_mode = ac_mode
        await self._client.set_mode(ac_mode)

    async def async_set_temperature(self, **kwargs: Any) -> None:
        temp = kwargs.get(ATTR_TEMPERATURE)
        if temp is not None:
            await self._client.set_temperature(int(temp))

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        await self._client.set_fan(HA_FAN_TO_AC.get(fan_mode, 'auto'))

    async def async_set_swing_mode(self, swing_mode: str) -> None:
        v, h = SWING_TO_VH.get(swing_mode, (False, False))
        await self._client.set_swing(v, h)

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        s = self._client.state
        if preset_mode == PRESET_TURBO:
            if s.night:  await self._client.set_night(False)
            if s.quiet:  await self._client.set_quiet(False)
            if s.eco:    await self._client.set_eco(False)
            await self._client.set_turbo(True)
        elif preset_mode == PRESET_NIGHT:
            if s.turbo:  await self._client.set_turbo(False)
            if s.quiet:  await self._client.set_quiet(False)
            await self._client.set_night(True)
        elif preset_mode == PRESET_ECO:
            if s.turbo:  await self._client.set_turbo(False)
            await self._client.set_eco(True)
        elif preset_mode == PRESET_QUIET:
            if s.turbo:  await self._client.set_turbo(False)
            await self._client.set_quiet(True)
        elif preset_mode == PRESET_NONE:
            if s.turbo:  await self._client.set_turbo(False)
            if s.night:  await self._client.set_night(False)
            if s.eco:    await self._client.set_eco(False)
            if s.quiet:  await self._client.set_quiet(False)

    async def async_turn_on(self) -> None:
        mode = self._client.state.mode
        if mode and mode != 'off':
            self._last_mode = mode
        await self._client.set_mode(self._last_mode)

    async def async_turn_off(self) -> None:
        await self._client.set_mode('off')

    def _on_state_change(self, state: ACState) -> None:
        if state.mode and state.mode != 'off':
            self._last_mode = state.mode
        self.schedule_update_ha_state()
