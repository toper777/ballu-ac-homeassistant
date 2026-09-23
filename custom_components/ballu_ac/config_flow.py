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

from . import async_update_connection
from .const import CONF_MAC, CONF_PUBKEY, DEFAULT_PORT, DOMAIN
from .discovery import (
    async_scan,
    decode_props,
    is_supported_devtype,
    mac_from_props,
    pubkey_from_props,
)

if TYPE_CHECKING:
    from homeassistant.components.zeroconf import ZeroconfServiceInfo

_LOGGER = logging.getLogger(__name__)

CONF_QR_DATA = "qr_data"

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


# ── config flow ───────────────────────────────────────────────────────────────

class BalluConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Ballu AC. Each device = one config entry."""

    VERSION = 2

    def __init__(self) -> None:
        self._host:   str = ""
        self._port:   int = DEFAULT_PORT
        self._pubkey: str = ""
        self._name:   str = "Ballu AC"
        self._token:  str = ""
        self._mac:    str = ""
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

    def _configured(self) -> tuple[set[str], set[str]]:
        """MACs of configured devices, and hosts of entries that lack a MAC."""
        macs: set[str] = set()
        hosts: set[str] = set()
        for entry in self._async_current_entries(include_ignore=False):
            if entry.data.get(CONF_MAC):
                macs.add(entry.data[CONF_MAC])
            else:
                hosts.add(entry.data.get(CONF_HOST, ""))
        return macs, hosts

    async def _async_discover_devices(self) -> dict[str, dict]:
        """Scan the LAN; return not-yet-configured devices keyed by MAC
        (or host:port if a device announces no MAC)."""
        macs, hosts = self._configured()
        devices: dict[str, dict] = {}
        for dev in await async_scan(self.hass, DISCOVERY_TIMEOUT):
            if (dev["mac"] and dev["mac"] in macs) or dev["host"] in hosts:
                continue
            devices[dev["mac"] or f"{dev['host']}:{dev['port']}"] = dev
        return devices

    async def _async_find_host(self, host: str) -> dict | None:
        """Scan the LAN and return the device announced at `host`."""
        for dev in await async_scan(self.hass, DISCOVERY_TIMEOUT):
            if dev["host"] == host:
                return dev
        return None

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
            self._mac    = dev["mac"]
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
                    return await self._async_create_entry(data, self._mac)

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
                return await self._async_create_entry(user_input)
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
                            dev = await self._async_find_host(self._host)
                        else:
                            devs = await self._async_discover_devices()
                            dev = next(iter(devs.values())) if len(devs) == 1 else None
                        if dev:
                            self._host   = dev["host"]
                            self._port   = dev["port"]
                            self._pubkey = dev["pubkey"]
                            self._mac    = dev["mac"]

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
            new_host = str(user_input.get(CONF_HOST, self._host)).strip()
            if new_host != self._host:
                self._mac = ""  # the MAC we resolved belonged to the old address
            self._name   = user_input.get(CONF_NAME, self._name) or self._name
            self._host   = new_host
            self._port   = int(user_input.get(CONF_PORT, self._port))
            self._token  = str(user_input.get(CONF_TOKEN, self._token)).strip()
            self._pubkey = str(user_input.get(CONF_PUBKEY, self._pubkey)).strip()
            errors, placeholders = await self._validate_and_save(user_input)
            if not errors:
                return await self._async_create_entry(user_input, self._mac)
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
        props = decode_props(discovery_info.properties)
        if ":" in host or not is_supported_devtype(props):
            return self.async_abort(reason="not_supported_device")

        mac     = mac_from_props(props, discovery_info.name)
        pubkey  = pubkey_from_props(props)
        updates = {CONF_HOST: host, CONF_PORT: port}
        if pubkey:
            updates[CONF_PUBKEY] = pubkey

        # A device we already know that shows up at a new IP (router swap) or
        # with a new key (reboot): update its entry instead of offering it as new.
        if mac:
            await self.async_set_unique_id(mac)
            self._abort_if_unique_id_configured(updates=updates)

        # Entries that have not learned their MAC yet: the public key is unique
        # per device boot, so a matching key identifies the device at any IP.
        if pubkey:
            for entry in self._async_current_entries(include_ignore=False):
                if entry.data.get(CONF_MAC) or entry.data.get(CONF_PUBKEY) != pubkey:
                    continue
                moved = any(entry.data.get(k) != v for k, v in updates.items())
                if mac:
                    updates[CONF_MAC] = mac
                async_update_connection(self.hass, entry, updates)
                if moved and entry.state in (
                    config_entries.ConfigEntryState.LOADED,
                    config_entries.ConfigEntryState.SETUP_RETRY,
                ):
                    self.hass.config_entries.async_schedule_reload(entry.entry_id)
                return self.async_abort(reason="already_configured")

        if not mac:
            await self.async_set_unique_id(f"{host}:{port}")
            self._abort_if_unique_id_configured()
        self._async_abort_entries_match({CONF_HOST: host, CONF_MAC: ""})

        self._host   = host
        self._port   = port
        self._pubkey = pubkey
        self._mac    = mac
        self._name   = props.get("name") or "Ballu AC"
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
                return await self._async_create_entry(data, self._mac)
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

    async def _async_create_entry(self, data: dict, mac: str = ""):
        host = str(data[CONF_HOST]).strip()
        port = int(data.get(CONF_PORT, DEFAULT_PORT))
        # The MAC is the stable identity (the IP changes with the router).
        # Without it, key on the address until setup learns the MAC via mDNS.
        await self.async_set_unique_id(mac or f"{host}:{port}", raise_on_progress=False)
        self._abort_if_unique_id_configured()
        self._async_abort_entries_match({CONF_HOST: host, CONF_MAC: ""})
        name = data.get(CONF_NAME, "Ballu AC") or "Ballu AC"
        return self.async_create_entry(
            title=name,
            data={
                CONF_HOST:   host,
                CONF_PORT:   port,
                CONF_TOKEN:  _norm_token(data[CONF_TOKEN]),
                CONF_PUBKEY: _norm_pubkey(data[CONF_PUBKEY]),
                CONF_NAME:   name,
                CONF_MAC:    mac,
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return BalluOptionsFlow(config_entry)


class BalluOptionsFlow(config_entries.OptionsFlow):
    """Edit the connection settings of an entry: address, token, key, name.

    Changes are written to entry.data (which setup reads) and the entry is
    reloaded. The address is normally tracked automatically by MAC via mDNS;
    editing it here is the manual fallback when mDNS does not reach HA.
    """

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry

    async def async_step_init(self, user_input: dict | None = None):
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        d = self._entry.data
        if user_input is not None:
            try:
                host   = str(user_input[CONF_HOST]).strip()
                port   = int(user_input.get(CONF_PORT, d.get(CONF_PORT, DEFAULT_PORT)))
                token  = _norm_token(user_input[CONF_TOKEN])
                pubkey = _norm_pubkey(user_input[CONF_PUBKEY])
                if not host or not 1 <= port <= 65535:
                    raise ValueError("invalid host or port")
            except (KeyError, TypeError, ValueError) as exc:
                errors["base"] = "invalid_input"
                placeholders["error_detail"] = str(exc)
            else:
                # Verify the new settings actually work before saving, so a wrong
                # token or address can't be stored and silently break the device.
                ok, detail, pubkey = await self._async_verify(host, port, token, pubkey)
                if not ok:
                    errors["base"] = "invalid_credentials"
                    placeholders["error_detail"] = detail
                else:
                    name = user_input.get(CONF_NAME) or self._entry.title
                    self.hass.config_entries.async_update_entry(
                        self._entry,
                        title=name,
                        data={**d, CONF_HOST: host, CONF_PORT: port, CONF_TOKEN: token,
                              CONF_PUBKEY: pubkey, CONF_NAME: name},
                    )
                    self.hass.config_entries.async_schedule_reload(self._entry.entry_id)
                    return self.async_create_entry(title="", data={})
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Optional(CONF_NAME,   default=self._entry.title):              str,
                vol.Required(CONF_HOST,   default=d.get(CONF_HOST, "")):           str,
                vol.Optional(CONF_PORT,   default=d.get(CONF_PORT, DEFAULT_PORT)): int,
                vol.Required(CONF_TOKEN,  default=d.get(CONF_TOKEN, "")):          str,
                vol.Required(CONF_PUBKEY, default=d.get(CONF_PUBKEY, "")):         str,
            }),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def _async_verify(self, host: str, port: int, token: str,
                            pubkey: str) -> tuple[bool, str, str]:
        """Connect and confirm the device accepts a command → (ok, detail, pubkey).

        On a handshake timeout the key may have rotated: retry once with the key
        the device currently announces at that address.
        """
        from .syncleo import SyncleoClient  # lazy import

        async def attempt(pk: str) -> bool:
            client = SyncleoClient(host=host, port=port, token_hex=token, pubkey_hex=pk)
            await client.connect()
            try:
                return await client.async_verify_auth()
            finally:
                await client.disconnect()

        try:
            try:
                authed = await attempt(pubkey)
            except TimeoutError:
                fresh = next(
                    (dev["pubkey"] for dev in await async_scan(self.hass, DISCOVERY_TIMEOUT)
                     if dev["host"] == host and dev["pubkey"]),
                    "",
                )
                if not fresh or fresh == pubkey:
                    raise
                pubkey = fresh
                authed = await attempt(pubkey)
        except TimeoutError:
            return False, ("Нет ответа от устройства по этому адресу — проверьте IP "
                           "и что кондиционер в сети."), pubkey
        except Exception as exc:  # noqa: BLE001
            return False, f"Ошибка подключения: {type(exc).__name__}: {exc}", pubkey
        if not authed:
            return False, ("Устройство подключилось, но не приняло команду — "
                           "скорее всего неверный токен."), pubkey
        return True, "", pubkey
