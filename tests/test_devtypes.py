"""Which syncleo devtypes are treated as supported air conditioners."""
from __future__ import annotations

import pytest

from custom_components.ballu_ac.discovery import is_supported_devtype


@pytest.mark.parametrize("devtype", ["13", "20"])
def test_supported_ac_devtypes(devtype: str) -> None:
    assert is_supported_devtype({"devtype": devtype})


@pytest.mark.parametrize("devtype", ["77", "86", "69"])
def test_other_syncleo_devices_hidden(devtype: str) -> None:
    assert not is_supported_devtype({"devtype": devtype})


def test_missing_devtype_is_kept() -> None:
    assert is_supported_devtype({})
