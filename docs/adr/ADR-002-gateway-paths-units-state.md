# ADR-002: Пути, имена systemd-юнитов и хранилище состояния gateway

- **Дата:** 2026-11-07
- **Статус:** accepted
- **Контекст SPEC:** [SPEC-20261107-gateway-mvp](../team/specs/SPEC-20261107-gateway-mvp.md)

## Контекст

OQ-1/OQ-2 из REQ: нужно зафиксировать имена юнитов, пути конфигов и состояние
`gateway/store.py`. Конвенция проекта (AGENTS.md §5.9): пути через `INSTALL_DIR`
из env (`/opt/ztnet`, `/opt/my-vds`), не хардкодить. Roadmap предлагал
`/opt/vds-gateway/state.json` — это конфликтует с конвенцией.

## Рассмотренные варианты

| Вариант | Плюсы | Минусы |
|---|---|---|
| A. `/opt/vds-gateway/state.json` (как в roadmap) | отдельный префикс, изоляция от ZTNET | нарушает конвенцию INSTALL_DIR; второй «корень» в системе |
| B. `$INSTALL_DIR/gateway/state.json` | соответствует конвенции; лежит рядом с остальным состоянием vds | путь зависит от env (нужно документировать для оператора |

## Решение

**Вариант B.** Состояние: `os.environ.get("INSTALL_DIR", "/opt/my-vds")` +
`/gateway/state.json`, права 0600, владелец root.

Имена и пути (фиксируются на весь MVP):

| Объект | Значение |
|---|---|
| systemd-юнит Xray | `vds-xray.service` (шаблон `systemd/vds-xray.service.tpl`) |
| systemd-юнит Hysteria2 | `vds-hysteria2.service` (шаблон `systemd/vds-hysteria2.service.tpl`) |
| Конфиг Xray | `/usr/local/etc/xray/config.json` (0600) — апстрим-конвенция Xray |
| Бинарь/geodata Xray | `/usr/local/bin/xray`, `/usr/local/share/xray/` |
| Конфиг Hysteria2 | `/etc/hysteria/config.yaml` (0600) — апстрим-конвенция hysteria |
| Сертификаты Hysteria2 | `/etc/hysteria/cert.pem`, `/etc/hysteria/key.pem` (0600) |
| sysctl-тюнинг | шаблон `systemd/../sysctl/99-vds-gateway.conf.tpl` → рендер в `/etc/sysctl.d/99-vds-gateway.conf` |
| Состояние | `$INSTALL_DIR/gateway/state.json` (0600) |

**OQ-2 решён:** `hysteria2 remove --apply` НЕ откатывает sysctl-тюнинг
(BBR/буферы безвредны и полезны для остальных сервисов); это фиксируется в
документации и dry-run-плане remove.

## Последствия

- Положительные: один корень состояния; конвенция соблюдена; имена юнитов
  с префиксом `vds-` не конфликтуют с апстрим-пакетами.
- Отрицательные: оператор должен знать INSTALL_DIR при ручной диагностике —
  `vds gateway status` показывает фактический путь.
- Трудно изменить позже: имена юнитов и пути конфигов попадают в команды
  диагностики/доки — смена только через новый ADR.

## Как откатить

Смена констант в одном модуле (`src/gateway/paths.py` — единая точка путей);
юниты переименовываются reinstall-ом соответствующего протокола.
