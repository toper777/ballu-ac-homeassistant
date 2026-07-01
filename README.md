# Ballu AC — интеграция для Home Assistant (протокол syncleo)

[![Validate](https://github.com/toper777/ballu-ac-homeassistant/actions/workflows/validate.yml/badge.svg)](https://github.com/toper777/ballu-ac-homeassistant/actions/workflows/validate.yml)
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub release](https://img.shields.io/github/v/release/toper777/ballu-ac-homeassistant)](https://github.com/toper777/ballu-ac-homeassistant/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Локальное управление кондиционерами **Ballu** (и другими устройствами RusClimate
с прошивкой **syncleo**) в Home Assistant по UDP — без облака. Основано на
реверс-инжиниринге протокола syncleo (X25519 + AES-CBC поверх UDP).

> Интеграция неофициальная, не связана с Ballu / RusClimate. Названия и товарные
> знаки принадлежат их правообладателям.

## Возможности

- 🌡️ **Климат**: режимы (авто / охлаждение / осушение / нагрев / вентиляция / выкл),
  целевая температура 16–30 °C, скорость вентилятора, качание жалюзи.
- 🎛️ **Пресеты**: турбо, ночной, эко, тихий (взаимоисключающие).
- 📟 **Сенсор**: температура в комнате.
- 🔌 **Переключатели**: ионизатор, подсветка дисплея.
- 📡 **Локально и push**: состояние обновляется мгновенно, без опроса облака
  (`iot_class: local_push`).
- 🔍 **Автообнаружение** устройств в сети (mDNS) при добавлении.
- 🔑 **Самовосстановление ключа**: публичный ключ устройства меняется при
  перезагрузке — интеграция сама пере-резолвит его из mDNS и переподключается.

## Поддерживаемые устройства

- **Ballu Platinum Evolution** (и другие модели с модулем syncleo, `devtype=20`).
- Прошивка `fw=1.22`, `protocol=3`, порт UDP `41122`.

Другие устройства RusClimate/Polaris на syncleo с иным `devtype` не поддерживаются
(команды отличаются) и скрываются при обнаружении.

## Установка

### Через HACS (рекомендуется)

1. HACS → Интеграции → ⋮ → **Пользовательские репозитории**.
2. Добавьте `https://github.com/toper777/ballu-ac-homeassistant`, категория **Integration**.
3. Установите «Ballu AC (syncleo)» и **перезапустите** Home Assistant.

### Вручную

Скопируйте папку `custom_components/ballu_ac/` в `<config>/custom_components/`
и **полностью перезапустите** Home Assistant.

## Настройка

Настройки → Устройства и службы → **Добавить интеграцию** → **Ballu AC**.

Доступны три способа:

- **Поиск в сети** (рекомендуется) — активное mDNS-сканирование, выберите
  кондиционер из списка. Останется указать **токен**.
- **QR-код** — вставьте содержимое QR из приложения Ballu Home (текст или ссылку
  на изображение); публичный ключ подтянется из mDNS автоматически.
- **Ручная настройка** — IP, порт, токен, публичный ключ.

### Где взять токен

Токен — это единственный секрет, который **не** анонсируется по сети:
приложение **Ballu Home** → ваше устройство → **Поделиться** → **QR-код**.
В QR (текст/URL) содержится токен (32 hex-символа).

Публичный ключ брать вручную не нужно — он автоматически определяется из mDNS.

## Сущности

| Сущность          | Платформа | Описание                                   |
|-------------------|-----------|--------------------------------------------|
| Кондиционер       | climate   | режим, температура, вентилятор, жалюзи, пресеты |
| Room Temperature  | sensor    | температура в комнате                       |
| Ionizer           | switch    | ионизатор                                   |
| Display           | switch    | подсветка дисплея                           |

## Пример автоматизации

Установка конкретной температуры выполняется службой `climate.set_temperature`
(в блоке «Действие устройства» температуры нет — это ограничение ядра HA):

```yaml
action: climate.set_temperature
target:
  entity_id: climate.ballu_ac
data:
  temperature: 22
  hvac_mode: cool
```

## Как это работает

Протокол syncleo — UDP на порту 41122 с шифрованием:

1. X25519 ECDH-обмен с публичным ключом устройства (из mDNS TXT `public=`).
2. SHA-256 от общего секрета → ключи AES-CBC (с ротацией по номеру пакета).
3. Handshake с токеном авторизации, затем команды/состояние в шифрованных кадрах.

Подробное описание протокола, карта команд и заметки по реверс-инжинирингу —
в [CLAUDE.md](CLAUDE.md).

## Утилиты для исследования (`tools/`)

Автономные скрипты (не требуют Home Assistant, только `pip install cryptography zeroconf`):

```bash
python tools/ballu_listen.py scan   # найти устройства в сети (IP, pubkey)
python tools/ballu_listen.py        # пассивный слушатель команд
python tools/ballu_cmd.py           # интерактивная отправка команд
```

Перед запуском укажите в начале скрипта `DEVICE_IP` и `TOKEN_HEX`
(публичный ключ определяется автоматически из mDNS).

## Диагностика

При проблемах включите подробные логи в `configuration.yaml`:

```yaml
logger:
  logs:
    custom_components.ballu_ac: debug
```

## Лицензия

[MIT](LICENSE) © toper777
