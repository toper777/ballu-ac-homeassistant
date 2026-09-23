"""Test fixtures: a fake syncleo network instead of real UDP / mDNS."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from custom_components.ballu_ac.syncleo import ACState

PORT = 41122


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture(autouse=True)
def auto_mock_zeroconf(mock_async_zeroconf):
    yield


class FakeNet(dict):
    """ip -> device {"mac", "pubkey", "token"}."""

    def add(self, ip: str, mac: str, pubkey: str, token: str) -> None:
        self[ip] = {"mac": mac, "pubkey": pubkey, "token": token}

    def scan(self) -> list[dict]:
        return [
            {"host": ip, "port": PORT, "pubkey": d["pubkey"], "mac": d["mac"], "name": ip}
            for ip, d in self.items()
        ]


@pytest.fixture
def fake_net():
    net = FakeNet()

    class FakeClient:
        """Mimics the real device: the handshake needs the device's *current*
        public key but NOT the token — only commands check the token."""

        def __init__(self, host, port, token_hex, pubkey_hex):
            self.host, self.port = host, port
            self.token, self.pubkey_hex = token_hex, pubkey_hex
            self.fw_version, self.proto = "1.22", 3
            self.state = ACState()
            self._connected = False
            self.on_connection_lost = None
            self._dev = None

        async def connect(self):
            dev = net.get(self.host)
            if not dev or dev["pubkey"] != self.pubkey_hex:
                raise TimeoutError("Syncleo handshake timed out")
            self._dev, self._connected = dev, True

        async def async_verify_auth(self, timeout: float = 3.0) -> bool:
            return self._dev is not None and self._dev["token"] == self.token

        async def disconnect(self):
            self._connected = False

        def register_state_callback(self, cb):
            pass

        def unregister_state_callback(self, cb):
            pass

    async def fake_scan(hass, timeout: float = 5.0):
        return net.scan()

    with (
        patch("custom_components.ballu_ac.syncleo.SyncleoClient", FakeClient),
        patch("custom_components.ballu_ac.discovery.async_scan", fake_scan),
        patch("custom_components.ballu_ac.config_flow.async_scan", fake_scan),
    ):
        yield net
