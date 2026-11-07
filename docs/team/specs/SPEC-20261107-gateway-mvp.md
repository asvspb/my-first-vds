# SPEC-20261107-gateway-mvp

## Мета
- **Источник:** [REQ-20261107-gateway-mvp](../requirements/REQ-20261107-gateway-mvp.md)
- **Автор:** архитектор (vds-architect)
- **Дата:** 2026-11-07
- **Статус:** approved (G2)
- **ADR:** [ADR-001](../../adr/ADR-001-xray-install-mechanism.md),
  [ADR-002](../../adr/ADR-002-gateway-paths-units-state.md)
- **Допущения REQ закрыты:** OQ-1 → ADR-002; OQ-2 → ADR-002 (sysctl не
  откатывается); OQ-3 → ADR-001; OQ-4 → в MVP только текстовые share-links.

## 1. Цель и решение

Реализовать MVP «gateway» по фазам 0–2 roadmap: закрыть tech-debt P1–P3,
ввести общие примитивы (ProtocolAdapter, netcheck, secrets, units, store),
затем два транспорта — Xray VLESS Reality (TCP 443) и Hysteria2 (UDP 443,
self-signed без домена). Выбор протоколов и архитектуры — см.
[CENSORSHIP-ROADMAP.md](../../CENSORSHIP-ROADMAP.md); механизмы установки и
пути — ADR-001/ADR-002. Все новые модули следуют конвенциям AGENTS.md
(ленивые импорты в main.py, `run_list`, FileLock, 0600, dry-run).

## 2. Архитектура

```
                vds CLI/TUI (src/main.py, ленивые импорты)
                    │
      ┌─────────────┼──────────────┐
      ▼             ▼              ▼
 src/xray/     src/hysteria2/   src/gateway/
 (adapter→     (adapter→        store.py (pydantic, 0600)
 ProtocolAdapter) ProtocolAdapter)  + `gateway status`
      │             │
      └──────┬──────┘
             ▼
   src/core/ protocol.py · netcheck.py · secrets.py · units.py · shell.py
             │
   systemd/vds-xray.service.tpl · vds-hysteria2.service.tpl ·
   sysctl/99-vds-gateway.conf.tpl
```

Потоки: install → netcheck.port_free → secrets.gen → render config →
units.install_unit → systemctl enable. add-client → store.add → re-render
config → restart → share-link в stdout (приватные ключи — никогда).

## 3. Изменения в коде

| Файл | Действие | Назначение |
|---|---|---|
| `src/core/shell.py` | изменить | `load_env(path)` (P1); `docker_exec(container, cmd: str|list)` через `shlex.split` (P3) |
| `src/core/env.py` | (не создаём — load_env живёт в shell.py) | — |
| `src/zerotier/reconcile.py`, `nat.py`, `watchdog.py`, `api.py`, `install.py`, `diagnose.py` | изменить | импорт общего `load_env`; `docker_exec` на списках |
| `pyproject.toml`, `requirements.txt` | изменить | единый источник версий (P2) |
| `src/core/protocol.py` | создать | `ProtocolAdapter` ABC (контракт из roadmap §4.0) |
| `src/core/netcheck.py` | создать | `port_free`, `public_ip`, `port_owner` |
| `src/core/secrets.py` | создать | `gen_uuid`, `gen_password`, `write_secret_atomic` |
| `src/core/units.py` | создать | `install_unit(tpl, name, ctx)`, `unit_active(name)`, `remove_unit(name)` |
| `src/gateway/paths.py` | создать | единая точка путей/имён (ADR-002) |
| `src/gateway/store.py` | создать | `ClientProfile`, `GatewayState`, `load/save/add/remove_client` |
| `src/xray/{adapter,install,clients,config,status}.py` | создать | фаза 1 |
| `src/hysteria2/{adapter,install,clients,status,sysctl}.py` | создать | фаза 2 |
| `systemd/vds-xray.service.tpl`, `systemd/vds-hysteria2.service.tpl`, `systemd/../sysctl/99-vds-gateway.conf.tpl` | создать | шаблоны (положить sysctl-шаблон в `systemd/sysctl/`) |
| `src/main.py` | изменить | подкоманды `xray`, `hysteria2`, `gateway` (лениво) + пункты TUI |
| `tests/` | создать | unit-тесты (см. §6) |

**Публичные интерфейсы (сигнатуры):**

```python
# core/netcheck.py
def port_free(port: int, proto: str = "tcp") -> bool: ...
def port_owner(port: int, proto: str = "tcp") -> str | None: ...  # процесс-владелец для сообщений об ошибке
def public_ip() -> str | None: ...

# core/secrets.py
def gen_uuid() -> str: ...
def gen_password(length: int = 24) -> str: ...
def write_secret_atomic(path: str, data: str, mode: int = 0o600) -> bool: ...

# core/units.py
def install_unit(template: str, name: str, ctx: dict[str, str] = {}) -> bool: ...  # идемпотентен
def unit_active(name: str) -> bool: ...
def remove_unit(name: str) -> bool: ...

# core/protocol.py — как в roadmap §4.0 (install/add_client/remove_client/status/render_share_links/remove)

# gateway/store.py
class ClientProfile(BaseModel): name: str; protocol: str; port: int
    uuid: str | None = None; password: str | None = None
    sni: str | None = None; extra: dict = {}
class GatewayState(BaseModel): version: int = 1; domain: str = ""
    clients: list[ClientProfile] = []; protocols: dict[str, dict] = {}
def load_state(path: str | None = None) -> GatewayState: ...   # битый JSON -> StoreError (читаемая)
def save_state(state: GatewayState, path: str | None = None) -> bool: ...  # атомарно, 0600
```

Ошибки store — через исключение `StoreError(str)` (перехватывается в CLI,
выводится `[error]` без traceback), не через коды возврата.

**CLI-поверхность:**

```bash
vds gateway status
vds xray install [--sni MASK] · add-client NAME · status · remove [--apply]
vds hysteria2 install · add-client NAME · status · remove [--apply]
```

`remove` без `--apply` — dry-run (план: юнит, файлы, клиенты в store).

**Форматы конфигов:** Xray — JSON по VPN-PROTOCOLS §2.1 (Reality, Vision,
`dest`/`serverNames` из `--sni`, дефолт `www.google.com`); Hysteria2 — YAML
по §2.3, но: `tls: {cert,key}` = self-signed (openssl, CN=<ip>, 10 лет),
`masquerade: {type: proxy, proxy: {url: https://download.microsoft.com/ , rewrite: true}}`.
Share-links: `vless://...flow=xtls-rprx-vision#name`,
`hysteria2://pass@ip:443/?sni=<ip>&insecure=1#name`.

## 4. Миграция и совместимость

Ломается ничего: новые подкоманды добавляются, существующие команды ZeroTier
сохраняют поведение (P1/P3 — рефакторинг с сохранением семантики). Формат
`state.json` версионируется (`version: 1`); миграции — при `version != 1`
читаемая ошибка до появления схемы v2.

## 5. Безопасность и отказы

- **Секреты:** uuid/пароли/приватные ключи — только в `state.json` и конфигах
  (0600); в share-link только клиентские поля (uuid/pbk/sid/password — по
  назначению). Маскирование реализовано **точечно** в `status.py` обоих
  протоколов (uuid/password/privateKey → `***` при выводе journal); секреты в
  логи не пишутся вовсе. Глобальный фильтр в `core/logger.py` — перенесён в
  фазу 6 (hardening), решение зафиксировано по итогам G4 (TEST-отчёт,
  дефект №1).
- **Dry-run:** все `remove` — dry-run по умолчанию, `--apply` + подтверждение
  questionary.
- **Откат:** `vds xray remove --apply` / `vds hysteria2 remove --apply` (план в
  dry-run). sysctl не откатывается (ADR-002).
- **Failure modes:** порт занят → отказ до изменений с именем процесса
  (`port_owner`); нет root → отказ до изменений (`os.geteuid()`); обрыв сети
  при загрузке Xray → temp-каталог, atomic rename в конце, повтор succeeds;
  битый state.json → StoreError.

## 6. Тест-план

| Уровень | Что проверяем | Где |
|---|---|---|
| Unit | `load_env`, `docker_exec` список/shlex | `tests/core/test_shell.py` |
| Unit | `netcheck` (мок `run_list`) | `tests/core/test_netcheck.py` |
| Unit | `secrets` (уникальность, 0600, атомарность) | `tests/core/test_secrets.py` |
| Unit | `units` (tmp-префикс, идемпотентность) | `tests/core/test_units.py` |
| Unit | `ProtocolAdapter` контракт | `tests/core/test_protocol.py` |
| Unit | store roundtrip/0600/битый JSON/дубли имени | `tests/gateway/test_store.py` |
| Unit | снапшот-рендер config.json Reality; приватный ключ не в share-link | `tests/xray/test_config.py`, `test_clients.py` |
| Unit | снапшот config.yaml Hysteria2; insecure=1 в ссылке; пароль не в логах | `tests/hysteria2/test_config.py` |
| Unit | рендер sysctl-файла детерминирован | `tests/hysteria2/test_sysctl.py` |
| VDS-чеклист | все AC с меткой [VDS] из REQ (E1–E10, FR-X.1/X.2) | `docs/team/reports/` — заполняет tester+owner |

Все unit-тесты — без root/сети/docker (моки `run_list`, tmp_path).

## 7. Work packages (для кодеров)

| WP | Задача | Файлы | Зависит от | DoD |
|---|---|---|---|---|
| WP-1 | P1–P3: общий `load_env`, `docker_exec` списки, версии; bootstrap `tests/` + pytest dev-dep | `core/shell.py`, `src/zerotier/*`, `pyproject.toml`, `requirements.txt`, `tests/core/test_shell.py` | — | compileall; grep-критерии P1/P3; тесты зелёные |
| WP-2 | core-примитивы: `protocol.py`, `netcheck.py`, `secrets.py`, `units.py` + тесты | `core/*` (новые), `tests/core/*` | WP-1 | pytest зелёный; аннотации везде |
| WP-3 | `gateway/paths.py`, `gateway/store.py`, `gateway status` в CLI + тесты | `src/gateway/*`, `src/main.py`, `tests/gateway/*` | WP-2 (модель) | FR-0.8 AC локально зелёные |
| WP-4 | Xray: adapter/install/clients/config/status, шаблон юнита, CLI+TUI, тесты | `src/xray/*`, `systemd/vds-xray.service.tpl`, `src/main.py`, `tests/xray/*` | WP-3 | FR-1.x [локально]; снапшот-тест |
| WP-5 | Hysteria2: adapter/install/clients/status/sysctl, self-signed, шаблоны, CLI+TUI, тесты | `src/hysteria2/*`, `systemd/*`, `src/main.py`, `tests/hysteria2/*` | WP-4 (main.py) | FR-2.x [локально]; снапшот-тест |

Границы: пересечение файлов между WP — только `src/main.py` (WP-3→4→5
последовательно); WP-2 ∥ WP-3 допустимо (файлы не пересекаются). После WP-5 —
`vds-tester` (unit-прогон + VDS-чеклист для владельца), затем `vds-docs`.

## 8. Риски

| Риск | Вероятность | Влияние | Мера |
|---|---|---|---|
| GitHub недоступен с VDS при загрузке Xray | средняя | блокер install | понятная ошибка + инструкция; mirror вне MVP |
| `xray x25519`/`uuid` отсутствуют до установки бинаря | — | — | ключи генерируем своими `secrets` (uuid4; x25519 — вызовом бинаря после установки, до рендера конфига) |
| Занятый TCP 443 (nginx/coturn) на живом сервере | высокая | блокер фазы 1 | `port_free` до изменений; AC E1 |
| Self-signed Hysteria2 отвергается клиентами | низкая | переделка ссылки | `insecure=1` в share-link (задокументировано как тестовый режим) |
| Отклонение снапшотов конфигов при ревью | низкая | итерация | эталоны фиксируются в WP-4/5 и ревьюятся архитектором |

## 9. Границы изменений

- **Трогаем:** перечисленное в §3.
- **Не трогаем:** `src/zerotier/` кроме импортов load_env/docker_exec;
  `src/wireguard/`, `src/coturn/`, `src/sysinfo/`, `install.sh`; формат
  `topology.json`; TECHDEBT P4–P6.

## 10. Трассируемость

| REQ | WP | Файлы | Тест |
|---|---|---|---|
| FR-0.1–0.3 | WP-1 | shell.py, zerotier/*, pyproject | test_shell.py + grep |
| FR-0.4–0.7 | WP-2 | core/netcheck|secrets|units|protocol.py | tests/core/* |
| FR-0.8 | WP-3 | gateway/store.py, main.py | tests/gateway/test_store.py |
| FR-1.1–1.6, FR-X.1 | WP-4 | src/xray/* | tests/xray/* + VDS-чеклист |
| FR-2.1–2.5, FR-X.2 | WP-5 | src/hysteria2/* | tests/hysteria2/* + VDS-чеклист |

## Следующий шаг

→ `vds-coder`: WP-1, затем WP-2 ∥ WP-3, затем WP-4, WP-5 (по одному отчёту на WP
с verbatim pre-flight). Затем `vds-tester` и `vds-docs`.
