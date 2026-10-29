"""Регрессия: нули температуры в первую минуту после появления кондиционера в сети.

После включения питания или переподключения к Wi-Fi устройство около минуты присылает
set_temp=0 (cmd=0x02) и room_temp=0 (cmd=0x14), пока основная плата не отдаст настоящие
значения. До 0.4.2 они попадали в состояние, и HA показывал 0 °C в климате и датчике
(видно в истории живого HA 26.10, 28.10 и 29.10.2026 у всех трёх кондиционеров).
"""

from __future__ import annotations

from custom_components.ballu_ac.syncleo import ACState


def test_startup_zeros_are_ignored():
    s = ACState()
    assert not s.apply_cmd(0x02, bytes([0, 0]))
    assert not s.apply_cmd(0x14, bytes([0]))
    assert s.set_temp is None
    assert s.room_temp is None

    assert s.apply_cmd(0x02, bytes([24, 0]))
    assert s.apply_cmd(0x14, bytes([22]))
    assert (s.set_temp, s.room_temp) == (24, 22)


def test_zero_does_not_overwrite_known_values():
    s = ACState(set_temp=24, room_temp=22)
    assert not s.apply_cmd(0x02, bytes([0, 0]))
    assert not s.apply_cmd(0x14, bytes([0]))
    assert (s.set_temp, s.room_temp) == (24, 22)


def test_set_temp_out_of_range_ignored():
    s = ACState()
    for bad in (15, 31, 255):
        s.apply_cmd(0x02, bytes([bad, 0]))
    assert s.set_temp is None
    for ok in (16, 30):
        s.apply_cmd(0x02, bytes([ok, 0]))
        assert s.set_temp == ok
