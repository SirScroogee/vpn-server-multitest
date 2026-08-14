# Multitest — проверка сервера для VPN и сетевого трафика

Самостоятельный интерактивный скрипт для проверки Linux VPS и предварительной проверки
Windows-компьютера. Измеряет маршрут, задержку, потери, TCP/UDP-доступность, скорость
`iperf3`, стабильность канала, систему, диск, IP-репутацию, доступность сервисов и DNS.

Скрипт использует только стандартную библиотеку Python. Внешние Linux-утилиты ставятся
отдельным установщиком и автоматически проверяются перед выбранным тестом.

## Установка в Linux

Одной командой:

```bash
curl -fsSL https://raw.githubusercontent.com/SirScroogee/vpn-server-multitest/main/install.sh | sudo sh
```

Или после клонирования репозитория:

```bash
git clone --depth 1 https://github.com/SirScroogee/vpn-server-multitest.git
cd vpn-server-multitest
sudo sh install.sh
multitest
```

Команда `multitest` открывает главное интерактивное меню из любой директории.

Если системные зависимости уже установлены:

```bash
sudo sh install.sh --skip-deps
```

## Запуск без установки

```bash
python3 server_audit.py
```

Подробное описание тестов, аргументов, публичных iperf3-точек и ограничений находится в
[README_RU.md](README_RU.md).
