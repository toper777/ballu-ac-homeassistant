"""Protocol diagnostics must never expose the handshake device token."""

from __future__ import annotations

import logging
import struct

import pytest

from custom_components.ballu_ac import syncleo


def _client_and_frame(cmd_type: int, payload: bytes):
    """Build a real encrypted device frame without opening a socket."""
    client = syncleo.SyncleoClient("192.0.2.10", 41122, "00" * 16, "00" * 32)
    client._ink = b"i" * 16
    client._outk = b"o" * 16
    seq = 7
    ciphertext = syncleo._enc(
        syncleo._rotate(client._ink, seq & 0xF),
        syncleo._rotate(client._outk, (seq >> 4) & 0xF),
        bytes([seq, cmd_type]) + payload,
    )
    return client, struct.pack("<BBH", seq, 1, len(ciphertext)) + ciphertext


@pytest.mark.parametrize("token_length", [0, 1, 16, 32])
def test_handshake_payload_is_redacted(caplog, token_length) -> None:
    """Initial and retransmitted handshakes keep all token bytes out of logs."""
    token = b"\xa5" * token_length  # Synthetic bytes, never device credentials.
    payload = struct.pack("<HBBB", 3, 1, 22, 2) + token
    client, frame = _client_and_frame(0x00, payload)

    with caplog.at_level(logging.DEBUG, logger=syncleo.__name__):
        client._on_datagram(frame)
        client._on_datagram(frame)

    traces = [record for record in caplog.records if "payload=" in record.getMessage()]
    assert len(traces) == 2
    assert all("cmd=0x00 payload=<redacted>" in record.getMessage() for record in traces)
    if token:
        assert token.hex() not in caplog.text
        assert all(token.hex() not in repr(record.args) for record in caplog.records)
    assert client.proto == 3
    assert client.fw_version == "1.22"
    assert client._hs_done
    assert client._connected


def test_state_payload_remains_available_in_debug_logs(caplog) -> None:
    """Redacting handshake credentials must preserve ordinary state diagnostics."""
    client, frame = _client_and_frame(0x14, bytes([23]))

    with caplog.at_level(logging.DEBUG, logger=syncleo.__name__):
        client._on_datagram(frame)

    assert "cmd=0x14 payload=17" in caplog.text
    assert client.state.room_temp == 23
