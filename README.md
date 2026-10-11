# wgau — менеджер клиентов WireGuard

Утилита командной строки для управления клиентами WireGuard-сервера:
генерация ключей, выделение IP, регистрация пиров в `wg0.conf`,
готовые клиентские конфиги и QR-коды для импорта в приложение.

## Возможности

- `add` — полный цикл создания клиента: ключи (`wg genkey`/`genpsk`),
  свободный IP, помеченный пир в `wg0.conf`, папка с `client.conf` и QR-кодом
- `sync` — создать папки для пиров, уже существующих в `wg0.conf`
- `show` — QR-код клиентского конфига прямо в терминале (ASCII)
- `conf` — пересборка `client.conf` из сохранённого `sec.key`
- атомарная запись всех файлов (tmp + rename), ключи и конфиги — `0600`
- пиры в `wg0.conf` помечаются маркерами `# BEGIN_PEER/<name>` — ничего не теряется
  при ручном редактировании файла

## Требования

- Python **3.9+**
- `wireguard-tools` (бинарь `wg` в PATH)
- Запуск от **root** (утилита пишет в `/etc/wireguard/wg0.conf` и `/etc/wgau/`)
- Работающий WireGuard-сервер: `/etc/wireguard/wg0.conf` с секцией `[Interface]`

## Установка

```bash
git clone <ваш-репозиторий> wgau-project
cd wgau-project
pip install .          # или для разработки: pip install -e .

# проверка
wgau --help
```

Установятся зависимости (`qrcode[pil]`) и консольная команда `wgau`.

Без установки можно запускать из корня проекта: `python -m wgau ...`.

## Быстрый старт

```bash
# 1. Первый запуск создаст /etc/wgau/wgau.conf из шаблона
sudo wgau add

# 2. Поправьте конфиг под свой сервер
sudo nano /etc/wgau/wgau.conf

# 3. Создайте первого клиента
sudo wgau add
# Client client1 generated in /etc/wgau/clients/client1
#   IP:     10.7.0.2
#   Config: /etc/wgau/clients/client1/client.conf

# 4. Примените изменения к работающему туннелю (не роняя соединения)
sudo wg syncconf wg0 <(wg-quick strip wg0)

# 5. Покажите QR для импорта в телефон
sudo wgau show client1
```

## Конфигурация

Путь к конфигу ищется в порядке приоритета:

1. флаг `--config` / `-c`
2. переменная окружения `WGAU_CONFIG`
3. `/etc/wgau/wgau.conf` (по умолчанию)

Если файла нет — при первом запуске он создаётся из шаблона.

```ini
[General]
CLIENTS_FOLDER_PATH = /etc/wgau/clients
WIREGUARD_CONFIG_FILE = /etc/wireguard/wg0.conf

[Wireguard]
ENDPOINT = vpn.example.com:51820
ADDRESS_BASE = 10.7.0
DNS_SERVER = 1.1.1.1

[Naming]
CLIENT_PREFIX = client
```

| Опция                | Описание                                                        | Пример               |
|----------------------|-----------------------------------------------------------------|----------------------|
| `CLIENTS_FOLDER_PATH` | абсолютный путь к папке клиентов (создаётся автоматически)      | `/etc/wgau/clients`  |
| `WIREGUARD_CONFIG_FILE` | путь к конфигу сервера                                        | `/etc/wireguard/wg0.conf` |
| `ENDPOINT`           | адрес:порт сервера, попадает в клиентские конфиги               | `vpn.example.com:51820` |
| `ADDRESS_BASE`       | первые три октета клиентской подсети (из `Address` интерфейса)  | `10.7.0`             |
| `DNS_SERVER`         | DNS для клиентов                                                | `1.1.1.1`            |
| `CLIENT_PREFIX`      | префикс имён клиентов (`client1`, `client2`, ...)               | `client`             |

> **Миграция со старой версии (одна脚本-файл):** ключ `ABSALUTE_CLIENTS_FOLDER_PATH`
> переименован в `CLIENTS_FOLDER_PATH` и теперь указывает **сразу** на папку
> клиентов (суффикс `/clients` больше не дописывается):
> было `/etc/wgau/` → стало `/etc/wgau/clients`.

## Команды

### `wgau add`

Создаёт нового клиента:

1. подбирает свободное имя `clientN` (по маркерам в `wg0.conf` + существующим папкам);
2. подбирает свободный IP из диапазона `ADDRESS_BASE.2`–`ADDRESS_BASE.254`
   (по `AllowedIPs` существующих пиров);
3. генерирует приватный/публичный ключи и PSK;
4. атомарно дописывает пир в `wg0.conf`, сохраняя права файла;
5. создаёт папку клиента (см. ниже).

### `wgau sync`

Пробегает по всем пирам в `wg0.conf` и создаёт папку тем, у кого её нет.
Пиры с маркером `# BEGIN_PEER` получают папку с своим именем; без маркера —
`<префикс>_<последний октет IP>` (с предупреждением). В папку пишутся
`pub.key` и `psk.key` из `wg0.conf`; приватного ключа в `wg0.conf` нет, поэтому
`client.conf` не создаётся — положите `sec.key` и выполните `wgau conf <имя>`.

### `wgau show <name>`

Печатает QR-код `clients/<name>/client.conf` в терминале (ASCII-арт,
инвертированный — для тёмного фона).

### `wgau conf <name>`

Пересобирает `client.conf` из сохранённого `sec.key`:
выводит публичный ключ, сверяет с `pub.key`, берёт IP и PSK пира из `wg0.conf`.

```bash
wgau conf client3        # → Config generated: /etc/wgau/clients/client3/client.conf
```

### Папка клиента

```
/etc/wgau/clients/
└── client1/
    ├── sec.key       # приватный ключ клиента        (0600)
    ├── pub.key       # публичный ключ                (0600)
    ├── psk.key       # preshared key                 (0600)
    ├── client.conf   # готовый конфиг для импорта    (0600)
    └── client1.png   # QR-код конфига
```

## Формат wg0.conf

`wgau` не переписывает существующие пиры, только дописывает новые в конец:

```ini
[Interface]
PrivateKey = ...
Address = 10.7.0.1/24

# BEGIN_PEER client1
[Peer]
PublicKey = ...
PresharedKey = ...
AllowedIPs = 10.7.0.2/32
# END_PEER client1
```

Маркеры `# BEGIN_PEER <name>` / `# END_PEER <name>` используются для
идентификации пиров — не удаляйте их при ручном редактировании.
Безымянные пиры тоже поддерживаются (см. `sync`).

## Применение изменений

`wgau` **не перезагружает** туннель сам. После `add` примените изменения:

```bash
# без разрыва соединений:
sudo wg syncconf wg0 <(wg-quick strip wg0)

# или с перезапуском:
sudo systemctl restart wg-quick@wg0
```

## Безопасность

- все ключи и `client.conf` пишутся с правами `0600`;
- запись атомарна (tmp-файл + rename): обрыв посреди записи не оставит
  полуфайл ни в `wg0.conf`, ни в ключах;
- приватные ключи клиентов хранятся **только** в `sec.key` в папке клиента —
  в `wg0.conf` их нет (стандартное поведение WireGuard).

## Разработка

```
wgau/
├── cli.py       # argparse, диспетчеризация команд
├── config.py    # AppConfig, загрузка wgau.conf, шаблоны
├── models.py    # KeyPair, Peer, WgInterface
├── errors.py    # доменные исключения (базовый — WgauError)
├── wg.py        # обёртки над `wg`
├── wgconf.py    # парсинг/дописывание wg0.conf
├── alloc.py     # выделение IP и имён (чистые функции)
├── files.py     # файлы клиента, QR
├── service.py   # сценарии (add/sync/show/conf)
└── templates/   # wgau.conf, client.conf
```

Тесты:

```bash
pip install -e ".[dev]"
pytest
```

Добавление новой команды — три шага:

1. функция в `service.py`;
2. `sub.add_parser(...)` в `cli.py`;
3. строка в диспетчере `main()`.

## Roadmap

- SQLite-хранилище клиентов: имена, IP, даты действия, revoked-флаг
- команды `revoke` / `expire` / `list`
- перегенерация секции пиров `wg0.conf` из БД
- команда `import` — перенос существующих пиров в БД
- авто-применение через `wg syncconf` после мутаций

## Устранение неполадок

| Ошибка | Решение |
|---|---|
| `qrcode is not installed` | `pip install 'qrcode[pil]'` |
| `` `wg` not found `` | `apt install wireguard-tools` |
| `WireGuard config not found: ...` | поправьте `WIREGUARD_CONFIG_FILE` |
| `Peer ... already exists` | имя занято — это защита от дублей |
| `No free IP in 10.7.0.2–10.7.0.254` | подсеть заполнена |
| `sec.key ... does not match pub.key` | в папке лежит чужой приватный ключ |
| `Missing option '...' in ...` | в wgau.conf нет обязательного ключа |

## Лицензия

MIT