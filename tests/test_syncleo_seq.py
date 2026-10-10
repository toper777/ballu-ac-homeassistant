"""Регрессия: ACK входящих фреймов после переполнения номера (seq) через 255 → 0.

Номер входящего фрейма — один байт. Кондиционер сам шлёт keepalive (cmd=0xff) каждые ~5 с,
поэтому seq проходит полный круг примерно за 21–24 минуты. До 0.4.1 клиент запоминал все
увиденные номера и после переполнения не подтверждал seq=0: устройство ~15 раз повторяло
фрейм, затем бросало сессию, и интеграция раз в ~24 минуты писала «connection lost».
"""

from __future__ import annotations

import pytest

from custom_components.ballu_ac import syncleo


@pytest.fixture
def client(monkeypatch):
    """SyncleoClient после handshake; отправленные ACK собираются в client.sent_acks."""
    c = syncleo.SyncleoClient("192.0.2.10", 41122, "00" * 16, "00" * 32)
    c._hs_done = True
    c._connected = True
    c.sent_acks = []
    monkeypatch.setattr(syncleo, "build_ack", lambda seq, ink, outk: ("ACK", seq))
    monkeypatch.setattr(c, "_send_raw", lambda frame: c.sent_acks.append(frame[1]))
    frames = {}
    monkeypatch.setattr(syncleo, "decrypt_frame", lambda data, ink, outk: frames[data])

    def feed(seq: int, cmd: int = 0xFF, payload: bytes = b"") -> None:
        key = bytes([len(frames) % 256]) + len(frames).to_bytes(4, "little")
        frames[key] = (seq, "CMD", cmd, payload)
        c._on_datagram(key)

    c.feed = feed
    return c


def test_ack_after_seq_wrap(client) -> None:
    """После 255 приходит seq=0 — он тоже должен получить ACK."""
    for seq in range(256):
        client.feed(seq)
    client.feed(0)
    client.feed(1)
    assert client.sent_acks[-2:] == [0, 1]
    assert len(client.sent_acks) == 258


def test_retransmission_acked_but_applied_once(client) -> None:
    """Повтор фрейма (ACK потерялся) подтверждается снова, но состояние применяется один раз."""
    changes = []
    client.register_state_callback(lambda state: changes.append(state.room_temp))
    client.feed(5, cmd=0x14, payload=bytes([23]))
    client.feed(5, cmd=0x14, payload=bytes([23]))
    client.feed(5, cmd=0x14, payload=bytes([23]))
    assert client.sent_acks == [5, 5, 5]
    assert changes == [23]


def test_state_change_after_wrap_applied(client) -> None:
    """Изменение состояния с номером, который уже встречался до переполнения, не теряется."""
    changes = []
    client.register_state_callback(lambda state: changes.append(state.room_temp))
    client.feed(7, cmd=0x14, payload=bytes([22]))
    for seq in range(8, 256):
        client.feed(seq)
    for seq in range(0, 7):
        client.feed(seq)
    client.feed(7, cmd=0x14, payload=bytes([24]))
    assert changes == [22, 24]
