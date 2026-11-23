"""QR images must decode without doing blocking work on the HA event loop."""
from __future__ import annotations

import io
import threading
from unittest.mock import patch

from PIL import Image
import pytest
import zxingcpp

from custom_components.ballu_ac import config_flow

QR_TEXT = '{"token":"0123456789abcdef0123456789abcdef"}'
IMAGE_URL = "https://example.com/qr.png"


@pytest.fixture
def qr_png() -> bytes:
    barcode = zxingcpp.create_barcode(QR_TEXT, zxingcpp.BarcodeFormat.QRCode)
    image = Image.fromarray(zxingcpp.write_barcode_to_image(barcode, scale=4))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


async def test_fetch_and_decode_uses_executor(hass, aioclient_mock, qr_png):
    """Exercise the download and real decoder; detect running it on the loop."""
    aioclient_mock.get(IMAGE_URL, content=qr_png)
    loop_thread = threading.get_ident()
    decode = config_flow._decode_qr_image
    decoded_data = []

    def checked_decode(data):
        assert threading.get_ident() != loop_thread
        decoded_data.append(data)
        return decode(data)

    with (
        patch.object(config_flow, "_url_is_safe", return_value=True),
        patch.object(config_flow, "_decode_qr_image", new=checked_decode),
    ):
        assert await config_flow._fetch_and_decode_qr(hass, IMAGE_URL) == QR_TEXT
        assert decoded_data == [qr_png]


@pytest.mark.parametrize("image_data", [b"", b"not an image"])
async def test_invalid_image_returns_none(hass, image_data):
    assert await hass.async_add_executor_job(config_flow._decode_qr_image, image_data) is None


async def test_image_without_qr_returns_none(hass):
    output = io.BytesIO()
    Image.new("RGB", (100, 100), "white").save(output, format="PNG")
    assert await hass.async_add_executor_job(
        config_flow._decode_qr_image, output.getvalue()
    ) is None
