# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Ballu AC — Home Assistant Integration (syncleo protocol)

## Обзор проекта

Полная реализация интеграции кондиционеров Ballu (серия Platinum Evolution и другие с прошивкой syncleo) для Home Assistant, основанная на реверс-инжиниринге UDP-протокола syncleo.

- **Модель устройства:** ballu_platinum_evolution
- **Прошивка:** fw=1.22, devtype=20, protocol=3
- **Протокол:** UDP, порт 41122, шифрование X25519+AES-CBC
- **Токен** берётся из приложения Ballu Home (Поделиться → QR), **публичный ключ** — из mDNS
  (TXT `public=`). В репозитории НЕ хранятся; для `tools/` задаются локально (см. ниже).

---

## Команды разработки

В проекте **нет** системы сборки, тестов, линтера, `requirements.txt` или `pyproject.toml`.
Это чистый custom-component для Home Assistant + автономные Python-скрипты в `tools/`.

### Зависимости

```bash
pip install cryptography      # обязательна (X25519, AES-CBC) — заявлена в manifest.json
pip install zeroconf          # для mDNS-обнаружения (scan) и zeroconf config flow
pip install zxingcpp          # ОПЦИОНАЛЬНО — декодирование QR из изображения
```

`homeassistant` импортируется только в `custom_components/ballu_ac/` и доступен внутри
работающего HA — отдельно для запуска `tools/` не нужен.

### Запуск утилит исследования протокола (требуется реальное устройство в сети)

```bash
python tools/ballu_listen.py          # пассивный слушатель команд устройства
python tools/ballu_listen.py sniff    # + raw hex каждого фрейма
python tools/ballu_listen.py scan     # mDNS-сканирование: найти IP и pubkey, затем выход
python tools/ballu_cmd.py             # интерактивная консоль отправки команд
```

В начале каждого скрипта `tools/` задаются `DEVICE_IP` и `TOKEN_HEX` (токен — из приложения
Ballu Home). **Публичный ключ НЕ хардкодится**: `DEVICE_PK_HEX`/`DEVICE_PUBKEY_HEX` пусты, и
скрипты при старте сами резолвят актуальный `public=` из mDNS по `DEVICE_IP` через
`resolve_pubkey()` (ключ меняется при перезагрузке устройства). `python ballu_listen.py scan`
покажет IP/порт/pubkey всех устройств в сети.

### Проверка изменений в интеграции

Автотестов нет. Цикл проверки — ручной, на реальном HA:
1. Скопировать `custom_components/ballu_ac/` в `<config>/custom_components/`
2. **Полный перезапуск** HA (reload интеграции недостаточно — особенно после правки переводов)
3. Настройки → Устройства и службы → Ballu AC

Для быстрой проверки протокольной логики (`syncleo.py`) без HA используйте скрипты `tools/`,
которые содержат самостоятельную копию крипто-/фрейм-логики.

---

## Структура проекта

```
Ballu_AC_homeassistant/
├── CLAUDE.md                          # этот файл
├── custom_components/
│   └── ballu_ac/                      # HA интеграция
│       ├── __init__.py                # setup_entry / unload_entry
│       ├── climate.py                 # ClimateEntity (режимы, темп, вентилятор, свинг, пресеты)
│       ├── config_flow.py             # UI настройки: ручная / QR / zeroconf
│       ├── const.py                   # DOMAIN, CONF_PUBKEY, DEFAULT_PORT
│       ├── discovery.py               # mDNS-резолв актуального pubkey по host (самолечение ключа)
│       ├── manifest.json              # зависимости, zeroconf, версия
│       ├── sensor.py                  # SensorEntity (температура в комнате)
│       ├── strings.json               # строки UI (источник для переводов)
│       ├── switch.py                  # SwitchEntity: ионизатор, дисплей
│       ├── syncleo.py                 # UDP клиент + ACState + криптография
│       ├── brand/                     # self-served бренд-иконки (HA 2026.3+): icon/logo (+@2x)
│       └── translations/
│           ├── en.json                # английский (= strings.json)
│           └── ru.json                # русский (= strings.json)
└── tools/                             # утилиты для исследования протокола
    ├── ballu_listen.py                # пассивный слушатель + mDNS сканер
    ├── ballu_cmd.py                   # интерактивная консоль команд
    ├── ballu_client.py                # базовый UDP клиент
    └── ballu_connect.py               # утилита проверки соединения
```

---

## Протокол syncleo

### Криптография

1. Клиент генерирует X25519 пару ключей
2. ECDH обмен с публичным ключом устройства (TXT `public=` из mDNS — 64 hex.
   ВНИМАНИЕ: `curve=` — это лишь числовой id кривой (напр. "29"), НЕ ключ)
3. SHA-256 от shared secret → первые 16 байт = `encinkey`, следующие 16 = `encoutkey`
4. Все фреймы шифруются AES-CBC с ротацией ключей: `rotate(key, seq & 0xF)` / `rotate(iv, (seq>>4) & 0xF)`
5. Байты ключей/публичных ключей — в **обратном** порядке (little-endian X25519)
6. **ВАЖНО — handshake-токен шифруется БЕЗ PKCS7-padding** (`_enc_nopad`): токен ровно
   16 байт = 1 AES-блок, устройство ждёт ровно 16 зашифрованных байт. Если применить
   обычный `_enc` (с PKCS7), добавляется лишний 16-байтный блок → handshake-фрейм 69 байт
   вместо 53, и устройство **молча его игнорирует** (0 ответов). Команды/ACK (`build_cmd`/
   `build_ack`) наоборот используют `_enc` С padding — их полезная нагрузка не кратна блоку.
7. **ВАЖНО — публичный ключ устройства НЕ постоянен.** При перезагрузке/сбросе Wi-Fi-модуля
   устройство генерирует новую X25519-пару → меняется `public=` в mDNS. Старый сохранённый
   pubkey → неверный ECDH-секрет → handshake молча отвергается (те же симптомы, что и при
   padding-баге: 0 ответов, хотя устройство живо и управляется из родного приложения).
   Поэтому интеграция **сама обновляет ключ из mDNS** (`discovery.py` →
   `async_pubkey_for_host`): при сбое handshake в `async_setup_entry` ключ пере-резолвится,
   запись обновляется, подключение повторяется. Рантайм-потеря связи (≥3 неотвеченных
   keepalive) → `on_connection_lost` → `async_reload` записи → тот же путь самовосстановления.

### Структура фрейма

```
[seq: u8][ftype: u8][length: u16 LE][payload: bytes]
```

- `ftype=0` — ACK
- `ftype=1` — CMD (зашифрованный)
- `ftype=3` — NAK

Расшифрованный payload CMD: `[seq][cmd_type][data...]`

### Рукопожатие

```
CLIENT → DEVICE:  [0x00][0x01][len] [0x00] [our_pub_32] [AES(token)]
DEVICE → CLIENT:  ACK (ftype=0)
DEVICE → CLIENT:  CMD cmd=0x00 [proto_u16][fw_maj][fw_min][mode][token...]
```

---

## Карта команд

### Команды записи (writable)

| cmd  | Название     | Данные                                      | Примечание                          |
|------|-------------|---------------------------------------------|-------------------------------------|
| 0x01 | Mode/Power  | `[0]`=off `[1]`=auto `[2]`=cool `[3]`=dry `[4]`=heat `[5]`=fan_only | |
| 0x02 | SetTemp     | `[temp_c, 0x00]`                            | диапазон 16..30 °C                  |
| 0x0f | FanSpeed    | `[0]`=auto `[1]`=low `[2]`=medium `[3]`=high | |
| 0x18 | Ionizer     | `[0/1]`                                     | ионизатор                           |
| 0x1c | Display     | `[0/1]`                                     | подсветка дисплея                   |
| 0x31 | Turbo       | `[0/1]`                                     | турбо режим                         |
| 0x32 | Night       | `[0/1]`                                     | ночной режим                        |
| 0x42 | Swing+Eco   | `[0x00, v_swing, h_swing, eco, 0x00]`       | субтип 0x00: жалюзи + экономия      |
| 0x42 | Quiet       | `[0x01, 0x00, quiet]`                       | субтип 0x01: тихий режим            |
| 0xff | Keepalive   | `b''` (пустой payload)                      | пинг каждые 10 с, ответ игнорируется |

**Важно:** `set_swing`/`set_eco` (оба cmd=0x42 субтип 0x00) делят один фрейм — при отправке
одного состояние другого читается из `self.state` и пересобирается, чтобы не сбросить его.

### Только чтение (read-only, pushes от устройства)

| cmd  | Название     | Примечание                    |
|------|-------------|-------------------------------|
| 0x14 | RoomTemp    | u8, °C                        |
| 0x03 | Unk0x03     | 4 байта, назначение неизвестно |
| 0x09 | Unk0x09     | 1 байт                        |
| 0x1e | Unk0x1e     | 1 байт                        |
| 0x1f | Capabilities | bitmask (обычно 0xff)         |
| 0x26 | Unk0x26     | 1 байт                        |
| 0x29 | Unk0x29     | 1 байт                        |
| 0x40 | SchedulePreset | 8-байтный tail: days_bitmask, hour, minute, mode, temp, unk, fan, night |
| 0x85 | HwInfo      | строка                        |
| 0x87 | NetworkInfo | строка                        |
| 0x88 | SystemInfo  | строка                        |
| 0x91 | DiagData    | бинарные данные               |

### Формат cmd=0x40 (SchedulePreset)

Последние 8 байт payload:
```
[days_bitmask][hour][minute][mode][temp][unk5][fan][night]
```
- `days_bitmask`: бит 0=Пн, 1=Вт, 2=Ср, 3=Чт, 4=Пт, 5=Сб, 6=Вс, бит 7=enabled
- `mode`, `temp`, `fan` — те же значения что и в 0x01/0x02/0x0f
- Пример (Mon-only, 08:02, cool, 20°C, auto): `01 07 08 02 14 00 00 00`
- Пример (Wed-only, 08:02, cool, 27°C, medium): `04 07 08 02 1b 00 02 00`

---

## Home Assistant интеграция

### Сущности

| Сущность       | Платформа | Описание                                             |
|---------------|-----------|------------------------------------------------------|
| Climate        | climate   | режим, температура, вентилятор, свинг, пресеты       |
| Room Temp      | sensor    | температура в комнате (cmd=0x14), read-only          |
| Ionizer        | switch    | ионизатор (cmd=0x18)                                 |
| Display        | switch    | подсветка дисплея (cmd=0x1c)                         |

### ClimateEntity

- **Режимы** (`hvac_modes`): off, auto, cool, dry, heat, fan_only
- **Температура**: 16..30 °C
- **Вентилятор** (`fan_modes`): auto, low, medium, high
- **Свинг** (`swing_modes`): off, vertical, horizontal, both → маппинг на `(v_swing, h_swing)`
- **Пресеты** (`preset_modes`): none, turbo, night, eco, quiet
  - Взаимоисключающие: установка одного деактивирует остальные
  - eco и quiet используют cmd=0x42 (разные субтипы)
  - turbo → cmd=0x31, night → cmd=0x32

### Архитектура клиента

`SyncleoClient` в `syncleo.py`:
- Один экземпляр на физическое устройство, хранится в `hass.data[DOMAIN][entry_id]`
- `register_state_callback(cb)` / `unregister_state_callback(cb)` — множество колбэков
- Все `set_*` методы асинхронные, ждут ACK до 3 секунд
- `_ping_loop()` — keepalive каждые 10 секунд
- UDP-сокет: создаётся вручную (`socket.socket(AF_INET)` + `bind(("", 0))`, unconnected),
  затем оборачивается в asyncio через `create_datagram_endpoint(sock=...)`. `_send_raw` шлёт
  с явным `(host, port)`, `_Protocol.datagram_received` принимает ответы от любого источника.
- **Отладка**: `_diag()` → `_LOGGER.debug` (молчит по умолчанию). Включается штатным logger
  HA: `logger: logs: custom_components.ballu_ac: debug`.
- Lazy import `cryptography` — внутри `__init__.py` и `config_flow.py` чтобы не блокировать event loop при загрузке

> Историческая заметка: при отладке таймаут handshake долго списывали на сетевой слой
> (connected vs unconnected сокет, Docker/NAT, uvloop). Это были ложные следы — настоящая
> причина в PKCS7-padding токена handshake (см. раздел «Криптография», п.6). Диагноз дал
> `tcpdump`: наш кадр был 69 байт против 53 у рабочего `tools/ballu_cmd.py`. При любых
> сетевых сомнениях первым делом сверяй длину/байты кадра через tcpdump и `ballu_cmd.py`.

### Установка в HA

1. Скопировать `custom_components/ballu_ac/` в `<config>/custom_components/ballu_ac/`
2. Полный перезапуск HA (не просто reload)
3. Настройки → Устройства и службы → Добавить интеграцию → Ballu AC

### Config Flow (UI настройки)

- **Шаг 1** (`async_step_user`): выбор метода — `SelectSelector` LIST (работает в тёмной теме).
  Методы: `discovery` (по умолчанию), `manual`, `qr`.
- **Поиск в сети** (`async_step_discovery`) — **активное** mDNS-сканирование при добавлении:
  - `_async_discover_devices()` использует **общий** экземпляр zeroconf HA через
    `homeassistant.components.zeroconf.async_get_async_instance(hass)` — создавать сырой
    `Zeroconf()` внутри HA ЗАПРЕЩЕНО (в отличие от `tools/ballu_listen.py`).
  - `AsyncServiceBrowser` слушает `_syncleo._udp.local.` `DISCOVERY_TIMEOUT` (5 с), затем
    `AsyncServiceInfo.async_request` добирает host/port/TXT по каждому имени.
  - Фильтр по TXT `devtype`: показываются только кондиционеры (`SUPPORTED_DEVTYPES={"20"}`).
    Прочие syncleo-устройства (напр. Polaris `devtype=77`) скрываются. Устройства без
    поля `devtype` НЕ отсекаются (лучше показать, чем спрятать).
  - Найденные устройства → `SelectSelector` со списком + пункт «Ввести вручную…»
    (`MANUAL_CHOICE`). Устройства без валидного `public=` помечаются «⚠ без ключа».
    Извлечение ключа — общий хелпер `_pubkey_from_props()` (поле `public`, 64 hex).
  - После выбора → `async_step_discovery_token`: host/port/pubkey уже известны, осталось
    указать **token** (mDNS его НЕ анонсирует). Можно вставить QR (текст/URL) ИЛИ ввести
    token вручную; ручной ввод имеет приоритет. Затем `_validate_and_save` → подключение.
  - Ничего не найдено → `async_step_no_devices`: выбор «Ручная настройка» / «Повторить поиск».
- **Ручная настройка** (`async_step_manual`): name, host, port, token (32 hex), pubkey (64 hex)
- **QR-код** (`async_step_qr`): текст QR (JSON/URL/base64/32-char hex) или URL изображения QR
  - URL изображения: скачивается и декодируется через `zxingcpp` или `pyzbar` (опционально)
- **zeroconf** (`async_step_zeroconf`): ПАССИВНОЕ автообнаружение — срабатывает, когда HA сам
  наткнётся на анонс `_syncleo._udp.local.` (не путать с активным `discovery` выше),
  pubkey берётся из TXT `public=` (через `_pubkey_from_props`)
- При ошибке: поля сохраняются, детализированное сообщение об ошибке
- **Проверка авторизации**: `connect()` (handshake) проходит даже с НЕВЕРНЫМ токеном —
  устройство отвергает только команды. Поэтому `_validate_and_save` после `connect()`
  вызывает `client.async_verify_auth()` (шлёт keepalive cmd=0xff, ждёт ACK); нет ACK →
  ошибка `invalid_credentials`, запись НЕ создаётся. Аналогично в `BalluOptionsFlow._async_verify`.
- **OptionsFlow**: редактирование token/pubkey/name без удаления интеграции (с той же проверкой)

### Важные технические детали

- `const.py` — только константы, никаких тяжёлых импортов (иначе HA/Python 3.14 детектирует blocking import)
- `from .syncleo import SyncleoClient` — ТОЛЬКО внутри методов, не на уровне модуля
- `from homeassistant.components.zeroconf import ZeroconfServiceInfo` — только под `TYPE_CHECKING`
- Unique ID **config entry**: `f"{host}:{port}"` (в `config_flow.py`) — предотвращает дублирование устройств
- Unique ID **сущностей** другой: каждая платформа строит свой, напр. climate —
  `f'ballu_{host_с_подчёркиваниями}_climate'`. Не путать с unique ID записи.
- `available` сущностей завязан на внутренний флаг `client._connected` (выставляется по ACK)
- Состояние устройства — push-модель: `SyncleoClient` хранит единый `ACState`, сущности
  читают его через свойства и подписываются через `register_state_callback`; колбэк дёргает
  `schedule_update_ha_state()`. Команды НЕ обновляют локальный стейт оптимистично — ждут push.
- **DeviceInfo**: общий хелпер `ballu_device_info(client, name)` в `__init__.py` группирует все
  сущности под одним HA-устройством (identifiers `(DOMAIN, "host:port")`). `sw_version` берётся
  из `client.fw_version`, которое `_parse_handshake` извлекает из cmd=0x00 во время `connect()`
  (до setup платформ, поэтому версия уже доступна). Climate — primary entity (`_attr_name=None`).
- Переводы: нужны оба файла `translations/en.json` и `translations/ru.json`

---

## Утилиты для исследования протокола

### ballu_listen.py

Пассивный слушатель. Подключается к устройству, выводит все входящие команды.

```bash
python tools/ballu_listen.py          # чистый вывод
python tools/ballu_listen.py sniff    # + raw hex каждого фрейма
python tools/ballu_listen.py scan     # только mDNS сканирование (найти IP и pubkey)
```

`scan` — использует `zeroconf` для обнаружения всех syncleo-устройств в сети и выводит их IP, порт и pubkey. Требует: `pip install zeroconf`.

### ballu_cmd.py

Интерактивная консоль для отправки команд:

```
mode <off|auto|cool|dry|heat|fan_only>
temp <16-30>
fan <auto|low|medium|high>
turbo <on|off>
night <on|off>
eco <on|off>
ion <on|off>
swing <v=0/1> <h=0/1>
swing42 <v> <h> [eco]
display <on|off>
quit
```

---

## Известные проблемы и TODO

- [ ] Проверить работу QR декодирования из URL (требует `zxingcpp` или `pyzbar`)
- [ ] Протестировать активное `discovery` и пассивное `zeroconf` автообнаружение на реальной сети
- [ ] Назначение cmd=0x03, 0x09, 0x1e, 0x26, 0x29 не установлено (всегда 0, read-only)
- [x] Активное mDNS-сканирование сети в config flow со списком устройств (`async_step_discovery`)
- [x] device_info (модель, прошивка) из HandshakeResponse cmd=0x00 (`ballu_device_info`)
- [x] Фикс handshake (PKCS7-padding токена) — подключение и управление работают на реальном HA
- [ ] Опубликовать на GitHub / HACS

## Текущее состояние

Интеграция работает на реальном HA (Docker на Linux, host network):
- ✅ Форма настройки, активный mDNS-поиск, выбор устройства, ввод token
- ✅ Подключение (handshake), управление кондиционером, push-обновление состояния, keepalive
- ✅ Переводы (нужен полный перезапуск HA после копирования файлов)
- Для распространения собирается чистая копия в `Ballu_AC/custom_components/ballu_ac/`
  (см. историю robocopy-команд); там нет `tools/`, `CLAUDE.md`, `__pycache__`.
