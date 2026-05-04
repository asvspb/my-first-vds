# Настройка Ubuntu 24.04 для разработки

Этот скрипт автоматизирует настройку Ubuntu 24.04 для разработки, включая установку необходимых пакетов, настройку SSH, создание файла подкачки, установку Docker, Node.js и AI CLI утилит.

## Особенности

- Обновление системы
- Настройка SSH (отключение входа по паролю)
- Создание файла подкачки (Swap) на 2GB
- Установка Nginx, Git, Python3, Docker
- Установка Node.js (LTS)
- Установка AI CLI утилит (Gemini, OpenCode, KiloCode, Cline)
- Очистка системы

## Использование

Установите скрипт настроек на ваш сервер:
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/index.sh  | sudo bash
```

Установите wireguard на ваш сервер:
```bash
curl -fsSL https://raw.githubusercontent.com/asvspb/my-first-vds/refs/heads/main/wg-install.sh  | sudo bash
```

## Требования

- Ubuntu 24.04
- Доступ к интернету
- Права суперпользователя (sudo)

## Лицензия

Этот проект лицензирован под MIT License - см. файл LICENSE для подробностей.