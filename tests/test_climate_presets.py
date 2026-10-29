"""Регрессия: пресеты взаимоисключающие.

До 0.5.0 выбор eco не выключал quiet/night, а выбор quiet не выключал eco/night. Так как
preset_mode показывает первый включённый флаг (turbo > night > eco > quiet), после eco → quiet
оставался eco (заметил автор PR toper777/ballu-ac-homeassistant#1).
"""

from __future__ import annotations

import pytest

from custom_components.ballu_ac.climate import BalluClimate
from custom_components.ballu_ac.syncleo import ACState

FLAGS = ("turbo", "night", "eco", "quiet")


class _Client:
    """Записывает вызовы set_*; состояние не меняет (как настоящий клиент до push)."""

    def __init__(self, **active: bool) -> None:
        self.state = ACState(**{f: active.get(f, False) for f in FLAGS})
        self.calls: list[tuple[str, bool]] = []
        for f in FLAGS:
            setattr(self, f"set_{f}", self._recorder(f))

    def _recorder(self, flag: str):
        async def setter(on: bool) -> None:
            self.calls.append((flag, on))
        return setter


def _entity(client: _Client) -> BalluClimate:
    entity = BalluClimate.__new__(BalluClimate)
    entity._client = client
    return entity


@pytest.mark.parametrize("target", FLAGS)
async def test_preset_switches_all_others_off(target: str) -> None:
    client = _Client(**{f: True for f in FLAGS})
    await _entity(client).async_set_preset_mode(target)
    others_off = [(f, False) for f in FLAGS if f != target]
    assert client.calls == others_off + [(target, True)]


async def test_eco_to_quiet() -> None:
    client = _Client(eco=True)
    await _entity(client).async_set_preset_mode("quiet")
    assert client.calls == [("eco", False), ("quiet", True)]


async def test_none_switches_everything_off() -> None:
    client = _Client(night=True, quiet=True)
    await _entity(client).async_set_preset_mode("none")
    assert client.calls == [("night", False), ("quiet", False)]
