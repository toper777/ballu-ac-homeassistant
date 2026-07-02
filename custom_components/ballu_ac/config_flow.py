"""Config flow for Ballu AC integration.

Heavy imports (syncleo / cryptography) are deferred to inside methods
so that importing this module at load time does not block the event loop.
"""
from __future__ import annotations

import base64
import json
import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_TOKEN, CONF_NAME
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import DOMAIN, CONF_PUBKEY, DEFAULT_PORT

if TYPE_CHECKING:
    from homeassistant.components.zeroconf import ZeroconfServiceInfo

_LOGGER = logging.getLogger(__name__)

CONF_QR_DATA = "qr_data"

# mDNS service type announced by syncleo devices
SYNCLEO_SERVICE = "_syncleo._udp.local."
# Only these syncleo device types are air conditioners we support. Other
# syncleo gear (e.g. Polaris humidifiers, devtype=77) shares the same mDNS
# service but speaks a different command set — hide it from discovery.
SUPPORTED_DEVTYPES = {"20"}
# how long to listen for mDNS announcements during an active scan
DISCOVERY_TIMEOUT = 5.0
# sentinel value in the discovery list meaning "skip and enter manually"
MANUAL_CHOICE = "__manual__"
# sentinel value in the discovery list meaning "scan the network again"
RESCAN_CHOICE = "__rescan__"

# ── QR text parser ────────────────────────────────────────────────────────────

_FIELD_TOKEN  = ("token", "key", "accessToken", "access_token", "t")
_FIELD_IP     = ("ip", "host", "address", "addr", "deviceIp", "device_ip")
_FIELD_PORT   = ("port", "p")
_FIELD_PUBKEY = ("pubkey", "publicKey", "public_key", "curve", "pk")
_FIELD_NAME   = ("name", "deviceName", "device_name", "n")


def _parse_qr_text(text: str) -> dict[str, str]:
    """Extract connection params from QR text (JSON / base64-JSON / URL / bare hex)."""
    text = text.strip()
    result: dict[str, str] = {}

    def _apply(d: dict) -> None:
        for dst, aliases in (
            ("token",  _FIELD_TOKEN),
            ("host",   _FIELD_IP),
            ("port",   _FIELD_PORT),
            ("pubkey", _FIELD_PUBKEY),
            ("name",   _FIELD_NAME),
        ):
            for alias in aliases:
                if alias in d and d[alias]:
                    result.setdefault(dst, str(d[alias]).strip())
                    break

    # 1. URL  syncleo://...?token=...
    if "://" in text or text.startswith("?"):
        try:
            parsed = urlparse(text if "://" in text else f"x://{text}")
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if parsed.hostname:
                params.setdefault("ip", parsed.hostname)
            _apply(params)
            if result:
                return result
        except Exception:
            pass

    # 2. Raw JSON
    try:
        d = json.loads(text)
        if isinstance(d, dict):
            _apply(d)
            if result:
                return result
    except Exception:
        pass

    # 3. Base64-encoded JSON
    try:
        dec = base64.b64decode(text + "==").decode("utf-8", errors="strict")
        d = json.loads(dec)
        if isinstance(d, dict):
            _apply(d)
            if result:
                return result
    except Exception:
        pass

    # 4. Bare 32-char hex = token only
    if re.fullmatch(r"[0-9a-fA-F]{32}", text):
        result["token"] = text.lower()

    return result


async def _decode_qr_image(image_data: bytes) -> str | None:
    """Decode a QR code from image bytes using zxingcpp or pyzbar."""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(image_data))
        try:
            import zxingcpp
            results = zxingcpp.read_barcodes(img)
            if results:
                return results[0].text
        except ImportError:
            pass
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            results = pyzbar_decode(img)
            if results:
                return results[0].data.decode("utf-8")
        except ImportError:
            pass
    except Exception as e:
        _LOGGER.debug("QR image decode error: %s", e)
    return None


_QR_MAX_BYTES = 5 * 1024 * 1024  # cap fetched image size (memory-DoS guard)


async def _url_is_safe(hass, url: str) -> bool:
    """Reject non-http(s) URLs and anything resolving to a private/loopback IP.

    Guards the server-side fetch below against SSRF (e.g. cloud metadata at
    169.254.169.254, localhost admin ports, internal hosts). Best-effort: does
    not fully close DNS-rebinding, but blocks the obvious internal targets.
    """
    import asyncio
    import ipaddress
    import socket

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except Exception:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


async def _fetch_and_decode_qr(hass, url: str) -> str | None:
    """Fetch an image from URL (SSRF-guarded, size-capped) and decode its QR."""
    if not await _url_is_safe(hass, url):
        _LOGGER.warning("QR image URL rejected (unsafe scheme or private address)")
        return None
    try:
        import aiohttp
        from homeassistant.helpers.aiohttp_client import async_get_clientsession

        session = async_get_clientsession(hass)
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return None
            data = b""
            async for chunk in resp.content.iter_chunked(65536):
                data += chunk
                if len(data) > _QR_MAX_BYTES:
                    _LOGGER.warning("QR image exceeds %d bytes — aborting", _QR_MAX_BYTES)
                    return None
            return await _decode_qr_image(data)
    except Exception as e:
        _LOGGER.debug("QR fetch error: %s", e)
    return None


def _norm_token(raw: str) -> str:
    t = raw.strip().replace("-", "").replace(" ", "").lower()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", t):
        raise ValueError("token must be 32 hex chars")
    return t


def _norm_pubkey(raw: str) -> str:
    pk = raw.strip().lower()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", pk):
        raise ValueError("pubkey must be 64 hex chars")
    return pk


def _pubkey_from_props(props: dict[str, str]) -> str:
    """Extract the 64-hex X25519 public key from mDNS TXT properties.

    The real key is announced in the `public` field. `curve` holds only a
    small numeric curve id (e.g. "29"), NOT the key — so it is used only as a
    fallback and accepted only if it happens to be valid 64-hex.
    """
    for field in ("public", "pubkey", "curve"):
        val = (props.get(field) or "").strip().lower()
        if re.fullmatch(r"[0-9a-fA-F]{64}", val):
            return val
    return ""


# ── config flow ───────────────────────────────────────────────────────────────

class BalluConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Ballu AC. Each device = one config entry."""

    VERSION = 1

    def __init__(self) -> None:
        self._host:   str = ""
        self._port:   int = DEFAULT_PORT
        self._pubkey: str = ""
        self._name:   str = "Ballu AC"
        self._token:  str = ""
        self._discovered: dict[str, dict] = {}

    # ── entry point ───────────────────────────────────────────────────────────

    async def async_step_user(self, user_input: dict | None = None):
        """Show method selection using SelectSelector (works in both light and dark theme)."""
        if user_input is not None:
            method = user_input.get("method", "discovery")
            if method == "discovery":
                return await self.async_step_discovery()
            if method == "qr":
                return await self.async_step_qr()
            return await self.async_step_manual()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("method", default="discovery"): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(value="discovery", label="Поиск в сети (рекомендуется)"),
                            selector.SelectOptionDict(value="manual",    label="Ручная настройка"),
                            selector.SelectOptionDict(value="qr",        label="QR-код (из приложения Ballu Home)"),
                        ],
                        mode=selector.SelectSelectorMode.LIST,
                    )
                )
            }),
        )

    # ── active network discovery ──────────────────────────────────────────────

    async def _async_discover_devices(self) -> dict[str, dict]:
        """Actively scan the LAN for syncleo devices via mDNS.

        Uses Home Assistant's shared Zeroconf instance (creating a raw
        Zeroconf() inside HA is forbidden). Returns {f"{host}:{port}": {...}}.
        """
        import asyncio

        from homeassistant.components import zeroconf as ha_zeroconf
        from zeroconf import ServiceStateChange
        from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo

        aiozc = await ha_zeroconf.async_get_async_instance(self.hass)
        names: list[str] = []

        # zeroconf invokes handlers with keyword arguments, so the parameter
        # names must match exactly (zeroconf / service_type / name / state_change).
        def _on_change(zeroconf, service_type, name, state_change) -> None:
            if state_change is ServiceStateChange.Added and name not in names:
                names.append(name)

        browser = AsyncServiceBrowser(
            aiozc.zeroconf, SYNCLEO_SERVICE, handlers=[_on_change]
        )
        try:
            await asyncio.sleep(DISCOVERY_TIMEOUT)
        finally:
            await browser.async_cancel()

        devices: dict[str, dict] = {}
        for name in names:
            info = AsyncServiceInfo(SYNCLEO_SERVICE, name)
            if not await info.async_request(aiozc.zeroconf, 3000):
                continue
            addresses = info.parsed_addresses()
            if not addresses:
                continue
            host = addresses[0]
            port = info.port or DEFAULT_PORT
            props: dict[str, str] = {}
            for k, v in (info.properties or {}).items():
                key = k.decode("ascii", "replace") if isinstance(k, bytes) else str(k)
                val = v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")
                props[key] = val

            # Keep only air conditioners (devtype=20). A device that announces a
            # devtype outside the supported set is skipped; a device that does
            # not announce devtype at all is kept (better to show than to hide).
            devtype = props.get("devtype", "")
            if devtype and devtype not in SUPPORTED_DEVTYPES:
                _LOGGER.debug(
                    "Skipping non-AC syncleo device %s:%s (devtype=%s, vendor=%s)",
                    host, port, devtype, props.get("vendor", "?"),
                )
                continue

            devices[f"{host}:{port}"] = {
                "host":   host,
                "port":   port,
                "pubkey": _pubkey_from_props(props),
                "name":   props.get("name") or name.split(".")[0] or "Ballu AC",
            }
        return devices

    async def _async_pubkey_for_host(self, host: str) -> str:
        """Scan the network and return the public key announced by `host`."""
        for dev in (await self._async_discover_devices()).values():
            if dev["host"] == host and dev["pubkey"]:
                return dev["pubkey"]
        return ""

    async def async_step_discovery(self, user_input: dict | None = None):
        """Scan the network and let the user pick a discovered device."""
        if user_input is not None:
            choice = user_input["device"]
            if choice == RESCAN_CHOICE:
                # Re-enter the step with no input to trigger a fresh scan.
                return await self.async_step_discovery()
            if choice == MANUAL_CHOICE:
                return await self.async_step_manual()
            dev = self._discovered.get(choice)
            if not dev:
                return await self.async_step_manual()
            await self.async_set_unique_id(choice)
            self._abort_if_unique_id_configured()
            self._host   = dev["host"]
            self._port   = dev["port"]
            self._pubkey = dev["pubkey"]
            self._name   = dev["name"]
            return await self.async_step_discovery_token()

        # First entry into this step: perform the scan.
        self._discovered = await self._async_discover_devices()
        if not self._discovered:
            return await self.async_step_no_devices()

        options = []
        for uid, dev in self._discovered.items():
            label = f"{dev['name']} ({dev['host']})"
            if not dev["pubkey"]:
                label += " — ⚠ без ключа"
            options.append(selector.SelectOptionDict(value=uid, label=label))
        options.append(
            selector.SelectOptionDict(value=RESCAN_CHOICE, label="🔄 Повторить поиск")
        )
        options.append(
            selector.SelectOptionDict(value=MANUAL_CHOICE, label="Ввести вручную…")
        )

        return self.async_show_form(
            step_id="discovery",
            data_schema=vol.Schema({
                vol.Required("device"): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=options,
                        mode=selector.SelectSelectorMode.LIST,
                    )
                )
            }),
            description_placeholders={"count": str(len(self._discovered))},
        )

    async def async_step_no_devices(self, user_input: dict | None = None):
        """Shown when the scan found nothing: retry or fall back to manual."""
        if user_input is not None:
            if user_input.get("next_step") == "retry":
                return await self.async_step_discovery()
            return await self.async_step_manual()

        return self.async_show_form(
            step_id="no_devices",
            data_schema=vol.Schema({
                vol.Required("next_step", default="manual"): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(value="manual", label="Ручная настройка"),
                            selector.SelectOptionDict(value="retry",  label="Повторить поиск"),
                        ],
                        mode=selector.SelectSelectorMode.LIST,
                    )
                )
            }),
        )

    async def async_step_discovery_token(self, user_input: dict | None = None):
        """A device was picked from the scan — host/port/pubkey are known.

        The token is the only secret mDNS does not announce: the user can
        paste a QR (text or image URL) to extract it, or type it directly.
        A manually typed token takes precedence over the QR field.
        """
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {
            "host":   self._host,
            "pubkey": self._pubkey or "(не анонсирован устройством)",
        }
        if user_input is not None:
            self._name = user_input.get(CONF_NAME, self._name) or self._name
            token   = str(user_input.get(CONF_TOKEN, "")).strip()
            qr_raw  = str(user_input.get(CONF_QR_DATA, "")).strip()

            # QR is only consulted when no token was typed manually.
            if not token and qr_raw:
                if re.match(r"https?://", qr_raw, re.IGNORECASE):
                    qr_text = await _fetch_and_decode_qr(self.hass, qr_raw)
                    if qr_text is None:
                        errors[CONF_QR_DATA] = "qr_image_failed"
                else:
                    qr_text = qr_raw
                if qr_text and not errors:
                    parsed = _parse_qr_text(qr_text)
                    token = parsed.get("token", "")
                    # Fill pubkey from QR if the device did not announce it.
                    if not self._pubkey and parsed.get("pubkey"):
                        try:
                            self._pubkey = _norm_pubkey(parsed["pubkey"])
                        except ValueError:
                            pass
                    if not token:
                        errors[CONF_QR_DATA] = "qr_no_token"

            if not token and not errors:
                errors[CONF_TOKEN] = "token_required"

            if not errors:
                self._token = token
                data = {
                    CONF_NAME:   self._name,
                    CONF_HOST:   self._host,
                    CONF_PORT:   self._port,
                    CONF_TOKEN:  token,
                    CONF_PUBKEY: self._pubkey,
                }
                verr, vph = await self._validate_and_save(data)
                errors.update(verr)
                placeholders.update(vph)
                if not errors:
                    return self._create_entry(data)

        return self.async_show_form(
            step_id="discovery_token",
            data_schema=vol.Schema({
                vol.Optional(CONF_NAME, default=self._name): str,
                vol.Optional(CONF_QR_DATA, default=""): selector.TextSelector(
                    selector.TextSelectorConfig(multiline=True)
                ),
                vol.Optional(CONF_TOKEN, default=self._token): str,
            }),
            errors=errors,
            description_placeholders=placeholders,
        )

    # ── manual entry ──────────────────────────────────────────────────────────

    async def async_step_manual(self, user_input: dict | None = None):
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        if user_input is not None:
            # Preserve inputs immediately so the form re-shows them on error
            self._name   = user_input.get(CONF_NAME, self._name) or self._name
            self._host   = str(user_input.get(CONF_HOST, self._host)).strip()
            self._port   = int(user_input.get(CONF_PORT, self._port))
            self._token  = str(user_input.get(CONF_TOKEN, self._token)).strip()
            self._pubkey = str(user_input.get(CONF_PUBKEY, self._pubkey)).strip()
            errors, placeholders = await self._validate_and_save(user_input)
            if not errors:
                return self._create_entry(user_input)
        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema({
                vol.Optional(CONF_NAME,   default=self._name):   str,
                vol.Required(CONF_HOST,   default=self._host):   str,
                vol.Optional(CONF_PORT,   default=self._port):   int,
                vol.Required(CONF_TOKEN,  default=self._token):  str,
                vol.Required(CONF_PUBKEY, default=self._pubkey): str,
            }),
            errors=errors,
            description_placeholders=placeholders,
        )

    # ── QR code step ──────────────────────────────────────────────────────────

    async def async_step_qr(self, user_input: dict | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            raw = user_input.get(CONF_QR_DATA, "").strip()
            qr_text = None

            if re.match(r"https?://", raw, re.IGNORECASE):
                qr_text = await _fetch_and_decode_qr(self.hass, raw)
                if qr_text is None:
                    errors[CONF_QR_DATA] = "qr_image_failed"
            else:
                qr_text = raw

            if qr_text and not errors:
                parsed = _parse_qr_text(qr_text)
                if not parsed.get("token"):
                    errors[CONF_QR_DATA] = "qr_no_token"
                else:
                    try:
                        self._token = _norm_token(parsed["token"])
                    except ValueError:
                        errors[CONF_QR_DATA] = "invalid_token"

                if not errors:
                    if parsed.get("host"):   self._host = parsed["host"]
                    if parsed.get("pubkey"):
                        try:
                            self._pubkey = _norm_pubkey(parsed["pubkey"])
                        except ValueError:
                            pass
                    if parsed.get("port"):
                        try:
                            self._port = int(parsed["port"])
                        except ValueError:
                            pass
                    if parsed.get("name"):   self._name = parsed["name"]

                    # QR usually carries the token but not the public key.
                    # Try to fetch it from the device via mDNS automatically.
                    if not self._pubkey:
                        if self._host:
                            found = await self._async_pubkey_for_host(self._host)
                            if found:
                                self._pubkey = found
                        else:
                            devs = await self._async_discover_devices()
                            if len(devs) == 1:
                                only = next(iter(devs.values()))
                                self._host   = only["host"]
                                self._port   = only["port"]
                                self._pubkey = only["pubkey"]

                    return await self.async_step_qr_confirm()

        return self.async_show_form(
            step_id="qr",
            data_schema=vol.Schema({
                vol.Required(CONF_QR_DATA): selector.TextSelector(
                    selector.TextSelectorConfig(multiline=True)
                ),
            }),
            errors=errors,
        )

    async def async_step_qr_confirm(self, user_input: dict | None = None):
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        if user_input is not None:
            self._name   = user_input.get(CONF_NAME, self._name) or self._name
            self._host   = str(user_input.get(CONF_HOST, self._host)).strip()
            self._port   = int(user_input.get(CONF_PORT, self._port))
            self._token  = str(user_input.get(CONF_TOKEN, self._token)).strip()
            self._pubkey = str(user_input.get(CONF_PUBKEY, self._pubkey)).strip()
            errors, placeholders = await self._validate_and_save(user_input)
            if not errors:
                return self._create_entry(user_input)
        return self.async_show_form(
            step_id="qr_confirm",
            data_schema=vol.Schema({
                vol.Optional(CONF_NAME,   default=self._name):   str,
                vol.Required(CONF_HOST,   default=self._host):   str,
                vol.Optional(CONF_PORT,   default=self._port):   int,
                vol.Required(CONF_TOKEN,  default=self._token):  str,
                vol.Required(CONF_PUBKEY, default=self._pubkey): str,
            }),
            errors=errors,
            description_placeholders=placeholders,
        )

    # ── mDNS auto-discovery ───────────────────────────────────────────────────

    async def async_step_zeroconf(self, discovery_info: "ZeroconfServiceInfo"):
        host  = str(discovery_info.host)
        port  = discovery_info.port or DEFAULT_PORT
        raw_props = discovery_info.properties or {}

        # Normalise TXT properties to str→str, then pull the real public key
        # from the `public` field (`curve` is just a numeric curve id).
        props: dict[str, str] = {}
        for k, v in raw_props.items():
            key = k.decode("ascii", "replace") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")
            props[key] = val

        name = props.get("name") or "Ballu AC"

        self._host   = host
        self._port   = port
        self._pubkey = _pubkey_from_props(props)
        self._name   = name

        await self.async_set_unique_id(f"{host}:{port}")
        self._abort_if_unique_id_configured()
        self.context["title_placeholders"] = {"name": self._name, "host": host}
        return await self.async_step_zeroconf_confirm()

    async def async_step_zeroconf_confirm(self, user_input: dict | None = None):
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        if user_input is not None:
            data = {
                CONF_NAME:   user_input.get(CONF_NAME, self._name),
                CONF_HOST:   self._host,
                CONF_PORT:   self._port,
                CONF_TOKEN:  user_input.get(CONF_TOKEN, ""),
                CONF_PUBKEY: self._pubkey,
            }
            errors, placeholders = await self._validate_and_save(data)
            if not errors:
                return self._create_entry(data)
        return self.async_show_form(
            step_id="zeroconf_confirm",
            data_schema=vol.Schema({
                vol.Optional(CONF_NAME,  default=self._name):  str,
                vol.Required(CONF_TOKEN, default=self._token): str,
            }),
            description_placeholders={"host": self._host, "pubkey": self._pubkey,
                                       **placeholders},
            errors=errors,
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _validate_and_save(self, data: dict) -> tuple[dict[str, str], dict[str, str]]:
        """
        Validate credentials and try to connect.
        Returns (errors, description_placeholders).
        description_placeholders['error_detail'] carries a human-readable reason
        that strings.json can inject into the form description via {error_detail}.
        """
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {"error_detail": ""}

        # 1. Format validation
        try:
            token  = _norm_token(data.get(CONF_TOKEN, ""))
        except ValueError:
            errors[CONF_TOKEN] = "invalid_token_format"
            placeholders["error_detail"] = "Токен должен быть ровно 32 hex-символа (0-9, a-f)"
            return errors, placeholders

        try:
            pubkey = _norm_pubkey(data.get(CONF_PUBKEY, ""))
        except ValueError:
            errors[CONF_PUBKEY] = "invalid_pubkey_format"
            placeholders["error_detail"] = "Публичный ключ должен быть ровно 64 hex-символа"
            return errors, placeholders

        host = str(data.get(CONF_HOST, "")).strip()
        if not host:
            errors[CONF_HOST] = "host_required"
            return errors, placeholders

        try:
            port = int(data.get(CONF_PORT, DEFAULT_PORT))
            if not (1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            errors[CONF_PORT] = "invalid_port"
            return errors, placeholders

        # 2. Network validation
        import socket as _socket
        try:
            _socket.inet_aton(host)
        except _socket.error:
            # It's a hostname — try to resolve it
            try:
                import asyncio
                loop = asyncio.get_running_loop()
                await loop.getaddrinfo(host, port)
            except Exception:
                errors[CONF_HOST] = "host_not_resolved"
                placeholders["error_detail"] = f"Не удалось определить адрес: {host}"
                return errors, placeholders

        # 3. Connection test + auth check.
        # Handshake (connect) succeeds even with a wrong token, so we also send
        # a command and require an ACK to confirm the token is actually valid.
        try:
            from .syncleo import SyncleoClient  # lazy import
            client = SyncleoClient(host=host, port=port, token_hex=token, pubkey_hex=pubkey)
            await client.connect()
            try:
                authed = await client.async_verify_auth()
            finally:
                await client.disconnect()
            if not authed:
                errors["base"] = "invalid_credentials"
                placeholders["error_detail"] = (
                    "Устройство ответило на подключение, но не приняло команду — "
                    "скорее всего неверный токен. Проверьте токен в приложении Ballu Home."
                )
                return errors, placeholders
        except TimeoutError:
            errors["base"] = "cannot_connect"
            # error string in strings.json has no placeholders — no need to pass any
        except OSError as exc:
            errors["base"] = "cannot_connect_network"
            placeholders["host"]   = host
            placeholders["port"]   = str(port)
            placeholders["detail"] = exc.strerror or str(exc)
        except Exception as exc:
            _LOGGER.exception("Unexpected error connecting to %s:%s", host, port)
            errors["base"] = "cannot_connect_unknown"
            placeholders["host"]   = host
            placeholders["port"]   = str(port)
            placeholders["detail"] = f"{type(exc).__name__}: {exc}"

        return errors, placeholders

    def _create_entry(self, data: dict):
        name = data.get(CONF_NAME, "Ballu AC") or "Ballu AC"
        return self.async_create_entry(
            title=name,
            data={
                CONF_HOST:   str(data[CONF_HOST]).strip(),
                CONF_PORT:   int(data.get(CONF_PORT, DEFAULT_PORT)),
                CONF_TOKEN:  _norm_token(data[CONF_TOKEN]),
                CONF_PUBKEY: _norm_pubkey(data[CONF_PUBKEY]),
                CONF_NAME:   name,
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return BalluOptionsFlow(config_entry)


class BalluOptionsFlow(config_entries.OptionsFlow):
    """Edit token/pubkey/name without removing the integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry

    async def async_step_init(self, user_input: dict | None = None):
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        d = self._entry.data
        if user_input is not None:
            try:
                token  = _norm_token(user_input[CONF_TOKEN])
                pubkey = _norm_pubkey(user_input[CONF_PUBKEY])
            except ValueError as exc:
                errors["base"] = "invalid_input"
                placeholders["error_detail"] = str(exc)
            else:
                # Verify the new credentials actually work before saving, so a
                # wrong token can't be stored and silently break the device.
                ok, detail = await self._async_verify(d[CONF_HOST], d[CONF_PORT],
                                                      token, pubkey)
                if not ok:
                    errors["base"] = "invalid_credentials"
                    placeholders["error_detail"] = detail
                else:
                    return self.async_create_entry(
                        title=user_input.get(CONF_NAME, d.get(CONF_NAME, "Ballu AC")),
                        data={
                            CONF_HOST:   d[CONF_HOST],
                            CONF_PORT:   d[CONF_PORT],
                            CONF_TOKEN:  token,
                            CONF_PUBKEY: pubkey,
                            CONF_NAME:   user_input.get(CONF_NAME, d.get(CONF_NAME, "")),
                        },
                    )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Optional(CONF_NAME,   default=d.get(CONF_NAME, "Ballu AC")): str,
                vol.Required(CONF_TOKEN,  default=d.get(CONF_TOKEN, "")):        str,
                vol.Required(CONF_PUBKEY, default=d.get(CONF_PUBKEY, "")):       str,
            }),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def _async_verify(self, host: str, port: int, token: str,
                            pubkey: str) -> tuple[bool, str]:
        """Connect and confirm the device accepts a command. (ok, detail)."""
        from .syncleo import SyncleoClient  # lazy import
        try:
            client = SyncleoClient(host=host, port=port, token_hex=token, pubkey_hex=pubkey)
            await client.connect()
            try:
                authed = await client.async_verify_auth()
            finally:
                await client.disconnect()
        except TimeoutError:
            return False, ("Нет ответа от устройства — проверьте, что оно в сети, "
                           "и правильность публичного ключа.")
        except Exception as exc:  # noqa: BLE001
            return False, f"Ошибка подключения: {type(exc).__name__}: {exc}"
        if not authed:
            return False, ("Устройство подключилось, но не приняло команду — "
                           "скорее всего неверный токен.")
        return True, ""
