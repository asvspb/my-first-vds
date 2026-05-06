# Настройка Ubuntu 24.04 для разработки

Набор скриптов для быстрой инициализации и управления VDS на Ubuntu 24.04.

## Скрипты

### `index.sh` — Основная настройка сервера

Полная автоматизация начальной настройки VDS (12 шагов):

1. Очистка зависших пакетов
2. Исправление tzdata
3. Обновление системы
4. Создание пользователя с SSH-ключами
5. SSH — только ключи (пароли отключены)
6. Swap 2GB
7. Автообновления безопасности
8. Файрвол (UFW)
9. Docker
10. Node.js LTS
11. AI CLI утилиты (Gemini, OpenCode, KiloCode, Cline)
12. Системный монитор sysinfo (вывод при SSH-подключении)

### `sysinfo.sh` — Системный монитор

Выводит сводку о состоянии сервера при каждом SSH-подключении:

- OS, ядро, аптайм, модель CPU, load average
- Публичный и локальный IP
- CPU / RAM / Swap с цветовыми прогресс-барами
- Использование дисков
- Статус Docker-контейнеров
- IP источника SSH, активные соединения
- Неудачные попытки входа за 24ч
- Топ процессов по памяти
- Последние логины

### `wg-install.sh` — WireGuard VPN

### `zt-install.sh` — ZeroTier VPN

## Установка

Основная настройка сервера:
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/index.sh | sudo bash
```

Только системный монитор (без полной настройки):
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/sysinfo.sh | sudo tee /etc/profile.d/sysinfo.sh > /dev/null && sudo chmod +x /etc/profile.d/sysinfo.sh
```

WireGuard:
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/wg-install.sh | sudo bash
```

ZeroTier:
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/zt-install.sh | sudo bash
```

## Требования

- Ubuntu 24.04
- Доступ к интернету
- Права суперпользователя (sudo)

## Лицензия

MIT
