# ORCH-20261109-vds-deploy-install

## Мета
- **Тип:** операционный отчёт оркестратора (развёртывание на живой VDS)
- **Автор:** оркестратор (vds-orchestrator)
- **Дата:** 2026-11-09
- **Целевой сервер:** `asv1`, 103.45.247.172 (Ubuntu 24.04.5 LTS, kernel 6.8.0-147, root)
- **Вердикт:** **PASS** — установка VDS Orchestrator v3.0 завершена, CLI работоспособен,
  юнит-тесты на сервере зелёные. Найден один баг в `install.sh` (см. §4, новый P-item для
  TECHDEBT).

## 1. Предусловия и подготовка

| Проверка | Результат |
|---|---|
| SSH root@103.45.247.172 (BatchMode, без пароля) | ✅ |
| ОС | ✅ Ubuntu 24.04.5 LTS — соответствует стеку проекта |
| Чистота портов (`ss -tlnp`) | ✅ только sshd:22 + systemd-resolve; порты 443 TCP/UDP свободны |
| Docker/контейнеры | ✅ нет (0/0) |
| Ресурсы | 1 CPU / 961 MB RAM / 19.7% disk (3.7G used) |

## 2. Выполненная цепочка

| Шаг | Действие | Результат |
|---|---|---|
| 1 | `rsync -az --delete` рабочего дерева → `/opt/my-vds/` (исключены .git, .zcode, venv, кэши) | ✅ |
| 2 | `bash install.sh` на сервере | ⚠️ шаг 1 (apt: python3-venv, python3-dev, gcc, build-essential) — ✅; шаг 2 упал (см. §4) |
| 3 | Доустановка оставшихся шагов скрипта вручную (идемпотентно, ровно по install.sh): venv → pip -r requirements.txt → `/usr/local/bin/vds` симлинк → проверка | ✅ |
| 4 | Верификация: `vds --help` | ✅ все команды на месте (sysinfo, server-setup, zerotier, wireguard, coturn, gateway, xray, hysteria2) |
| 5 | Верификация: `vds sysinfo` | ✅ дашборд корректный |
| 6 | Верификация: `pytest -q` на сервере (pytest доустановлен во venv — dev-dep, в requirements его нет) | ✅ **125 passed, 1 skipped** за 0.80s |

## 3. Состояние сервера после установки

- `/opt/my-vds/` — полный рабочий снапшот репо (commit `438be17` + локальные правки README)
- `/opt/my-vds/venv` — Python 3.12 venv, зависимости установлены (+pytest для приёмки)
- `/usr/local/bin/vds` — глобальный симлинк (`PYTHONPATH=/opt/my-vds`)
- Сервисы (ZeroTier, Xray, Hysteria2, WireGuard, Coturn) — **не устанавливались**; порты 443 свободны
- Изменения системы: apt-пакеты (python3-venv/dev, gcc, build-essential и зависимости)

## 4. Найденный дефект — предложить в TECHDEBT (P6, minor)

**`install.sh:74`** — `cp -r "${SCRIPT_DIR}/"* "${INSTALL_DIR}/"` под `set -e`.

Воспроизведение: скрипт запускается, когда `SCRIPT_DIR == INSTALL_DIR` (наш сценарий:
файлы уже развёрнуты rsync-ом в `/opt/my-vds`, скрипт запущен оттуда). `cp` на самого
себя возвращает ошибку `cp: 'X' and 'X' are the same file` → `set -e` убивает скрипт
после того, как apt-шаг уже выполнен.

**Исправление (одна строка):** guard вида

```bash
if [[ "$(realpath "${SCRIPT_DIR}")" != "$(realpath "${INSTALL_DIR}")" ]]; then
    cp -r "${SCRIPT_DIR}/"* "${INSTALL_DIR}/"
else
    log "Файлы уже в ${INSTALL_DIR} — копирование пропущено"
fi
```

**Влияние на этот прогон:** нет — шаг был скомпенсирован ручной доустановкой (шаг 3 §2).
**Почему не починил сейчас:** продовый инсталлятор правится через роле­вую модель
(architect → coder → tester), а не оркестратором на живом сервере.

## 5. Открытые вопросы для техлида

1. **Согласовать fix install.sh** (§4) — идти через WP или быстрым patch-коммитом.
2. **pytest в requirements** — сейчас его нет; для приёмки на живой VDS доустанавливал
   вручную. Вариант: `requirements-dev.txt` или optional-extra в pyproject.
3. **[VDS]-приёмка** (G6, чеклист 28 пунктов из
   [TEST-20261107-gateway-mvp §8](TEST-20261107-gateway-mvp.md)) — сервер готов
   к ней: порты 443 свободны, CLI установлен. После подтверждения fix'а install.sh
   предлагаю запускать приёмку на этом хосте.
4. `rsync`-развёртывание vs `git clone` (REPO_URL в install.sh): рабочий снапшот
   содержит незакоммиченные правки README — для приёмки лучше зафиксировать
   конкретный commit.

## 6. Следующий шаг

Жду решения техлида по §5.1–5.2, после чего запускаю [VDS]-приёмку (§5.3) на `asv1`.
