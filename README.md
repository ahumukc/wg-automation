# wgau — менеджер клиентов WireGuard

Утилита командной строки для управления клиентами WireGuard-сервера:
генерация ключей, выделение IP, регистрация пиров в `wg0.conf`,
готовые клиентские конфиги и QR-коды для импорта в приложение.

## Возможности

- `add` — полный цикл создания клиента: ключи (`wg genkey`/`genpsk`),
  свободный IP, помеченный пир в `wg0.conf`, папка с `client.conf` и QR-кодом
- `sync` — пометить безымянных пиров маркерами `# BEGIN_PEER`/`# END_PEER`
  и создать папки для существующих пиров
- `show` — QR-код клиентского конфига прямо в терминале (ASCII)
- `conf` — пересборка `client.conf` из сохранённого `sec.key`
- `delete` — удаление клиента: блок пира из `wg0.conf` + папка с ключами и конфигом
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

Без установки — из корня проекта: `PYTHONPATH=src python -m wgau ...`.

## Быстрый старт

```bash
# 1. Первый запуск только создаст /etc/wgau/wgau.conf из шаблона и выйдет
sudo wgau add

# 2. Поправьте конфиг под свой сервер
sudo nano /etc/wgau/wgau.conf

# 3. Создайте первого клиента
sudo wgau add
# Client client1 generated in /etc/wgau/clients/client1
#   IP:     10.7.0.2
#   Config: /etc/wgau/clients/client1/client.conf

# 4. Покажите QR для импорта в телефон
sudo wgau show client1
```

## Конфигурация

Путь к конфигу фиксирован: `/etc/wgau/wgau.conf`.

Если файла нет — при первом запуске любой команды он создаётся из шаблона
(`src/wgau/templates/wgau.conf`), после чего команда сразу завершается,
ничего не меняя. Поправьте конфиг под свой сервер и запустите команду снова.

## Лицензия

MIT