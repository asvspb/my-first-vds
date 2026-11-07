# TEST-20261107-gateway-mvp

## Мета
- **SPEC:** [SPEC-20261107-gateway-mvp](../specs/SPEC-20261107-gateway-mvp.md) ·
  [REQ-20261107-gateway-mvp](../requirements/REQ-20261107-gateway-mvp.md)
- **Автор:** тестировщик (vds-tester)
- **Дата:** 2026-11-07
- **Вердикт:** **PASS** — по всем проверяемым локально AC (см. §7: [VDS]-AC вынесены
  в чеклист владельца §8, дефекты — только minor).

Проверено независимо, отчётам кодеров не доверял: все команды прогнаны сам,
ключевые файлы прочитаны целиком. Продовый код не правился.

## 1. Что проверялось (AC-матрица, выборочно + adversarial)

| AC | Проверка | Результат | Доказательство |
|---|---|---|---|
| FR-0.1 (1 def load_env) | `grep -rn "def load_env" src/` | **PASS** | единственный хит `src/core/shell.py:87`; `python -m compileall -q src` → `exit=0` |
| FR-0.1 (импорты zerotier) | grep `from src.core.shell import ... load_env` в watchdog/reconcile/nat/api/install/diagnose + compileall | **PASS** | см. §5 |
| FR-0.2 (версии) | статическое сравнение pyproject/requirements | **PASS (частично)** | наборы зависимостей совпадают, пины удовлетворяют floor'ам; clean-venv install НЕ прогонялся (см. §7) |
| FR-0.3 (docker_exec списки) | `grep -rn "docker_exec" src/` | **PASS** | все вызовы — списки; `docker_exec(container, cmd: str\|list)` парсит строку через `shlex.split` (shell.py:112–119) |
| FR-0.4–0.7 | `python -m pytest tests/ -q` | **PASS** | `126 passed in 0.91s` (test_netcheck 12, test_secrets 11, test_units 10, test_protocol 5) |
| FR-0.8 (пустое состояние) | `INSTALL_DIR=/tmp/vds-test python -m src.main gateway status` и без env | **PASS** | оба вывода «Состояние пусто», `exit=0`, без traceback (§5) |
| FR-0.8 / E3 (битый JSON) | tmp state `{broken json` → `gateway status` | **PASS** | читаемая StoreError-ошибка, `exit=1`, без traceback (§5) |
| FR-0.8 (0600, roundtrip, дубли/удаление) | чтение store.py + `tests/gateway/test_store.py` (8 тестов) | **PASS** | `save_state`: `os.open(..., 0o600)` + `os.replace`; `add_client`/`remove_client` — StoreError без мутации |
| FR-1.1 [локально] (SNI→dest/serverNames) | чтение `src/xray/config.py` + `tests/xray/test_config.py` (7) | **PASS** | `dest: f"{sni}:{port}"`, `serverNames: [sni]`, дефолт `www.google.com`; рендер детерминирован |
| FR-1.2 [локально] (формат ссылки) | собственный прогон `render_share_link` с фиксированными входами | **PASS** | побайтовое совпадение с форматом из REQ (§5), имя с пробелами/кириллицей — `quote()` |
| FR-1.2 [локально] (приватный ключ не в ссылке) | чтение clients.py + `test_private_key_never_in_link` | **PASS** | в ссылке только `pbk`/`sid`; `privateKey` живёт только в config.json (0600) |
| FR-1.2 (дубликат имени) | store.add_client — StoreError до записи конфига | **PASS** | clients.py:123, исходное состояние не меняется (чистая функция store) |
| FR-1.3 [локально] (не установлен) | `python -m src.main xray status` | **PASS** | «Xray не установлен (нет /usr/local/bin/xray)», `exit=1`, без traceback (§5) |
| FR-1.4 [локально] (нечего удалять) | `python -m src.main xray remove --apply` (не установлен) | **PASS** | «Xray не установлен — нечего удалять.», `exit=0` (§5) |
| FR-1.4 (dry-run по умолчанию) | чтение remove.py + CLI-флаг | **PASS** | без `--apply` — только план; `--apply` → questionary-подтверждение |
| FR-1.5 / FR-2.5 (TUI smoke) | чтение main.py (лениво) | **PASS** | пункты «Управление Xray»/«Управление Hysteria2» в меню, действия install/add-client/status/remove вызывают те же функции |
| FR-2.2 [локально] (insecure=1, формат) | собственный прогон `render_share_link` | **PASS** | `hysteria2://pass@ip:443/?sni=<ip>&insecure=1#name` — точное совпадение (§5) |
| FR-2.2 (пароль не в логах) | чтение clients.py + `test_password_only_in_share_link_line` | **PASS** | пароль печатается только в share-link (клиентское поле по назначению) |
| FR-2.3 [локально] (не установлен) | `python -m src.main hysteria2 status` | **PASS** | читаемое сообщение, `exit=1`, без traceback |
| FR-2.4 [локально] (детерминизм sysctl) | `tests/hysteria2/test_sysctl.py` (5) | **PASS** | в составе 126 passed |
| NFR Root | `python -m src.main xray install` без root (uid=1000) | **PASS** | «Требуется root (запустите через sudo).», `exit=1`, ДО любых изменений (geteuid — первая строка run_install) |
| NFR Shell | `grep -rn "shell=True" src/ tests/` | **PASS** | только legacy `run()` в shell.py (существовал до MVP, не менялся) и `src/system/setup.py:181` (вне скоупа, не менялся); в новом коде — `run_list`/списки |
| NFR Секреты/права | чтение secrets.py, store.py, clients.py, status.py | **PASS** | `write_secret_atomic` (tmp+chmod+`os.replace`), `save_state` (0600), ререндер config.json через `write_secret_atomic(mode=0o600)`; journal маскируется в status (uuid/password/privateKey → `***`) |
| NFR Блокировки | grep FileLock | **PASS** | `xray/install.py:280`, `hysteria2/install.py:334` |
| NFR Ленивые импорты | grep import в main.py | **PASS** | все импорты xray/hysteria2/gateway — внутри функций команд; на уровне модуля только typer/logger |

## 2. Тест-матрица
| Уровень | Кейс | Статус |
|---|---|---|
| Unit | tests/core (50), tests/gateway (8), tests/xray (35), tests/hysteria2 (33) | ✅ 126 passed |
| Integration (Docker loopback) | вне скоупа MVP (SPEC §5 границ, фаза 8 roadmap) | н/д |
| Ручная приёмка CLI | --help × 3, gateway status × 2, status/remove/install негативные | ✅ |

## 3. Негативные и крайние кейсы
- [x] Битый state.json (E3) — читаемая ошибка, exit 1, файл не перезатёрт
- [x] Пустое/отсутствующее состояние — exit 0 без traceback
- [x] Нет root (E5, локальная ветка) — отказ до изменений, без traceback
- [x] Повторный remove --apply при неустановленном (E8) — exit 0 «нечего удалять»
- [x] Неустановленный сервис → status (FR-1.3/2.3) — exit 1, читаемо
- [x] Дубликат имени клиента (E7) — StoreError, без перезаписи (unit)
- [ ] Занятый порт (E1/E2) — ветка прочитана в коде (port_free/port_owner ДО изменений), реальный прогон — [VDS]
- [ ] Обрыв сети при загрузке бинаря (E6) — [VDS]
- [x] Секреты не утекают: grep-ревью вывода + точечные тесты маскирования journal
- [x] Идемпотентность (локальная часть): units/install_unit, store, `_installed()`-ветка install

## 4. Регрессия
Тестов в репозитории до MVP не было (`tests/` создан в WP-1) — регрессии по тестам нет.
Существующие команды zerotier/wireguard/coturn/sysinfo не удалялись; `git status` —
изменённые zerotier-файлы касаются только импортов `load_env`/`docker_exec` (по diff),
`python -m compileall -q src` → exit 0, `python -m src.main --help` показывает все
прежние команды. Полный прогон zerotier-команд не выполнялся (требуют Docker/root —
вне локальной среды), отмечено в §7.

## 5. Доказательства (verbatim)
```
$ python -m compileall -q src; echo exit=$?
exit=0

$ python -m pytest tests/ -q 2>&1 | tail -3
........................................................................ [ 57%]
......................................................                   [100%]
126 passed in 0.91s

$ python -m src.main --help   → команды: sysinfo cleanup server-setup zerotier
  wireguard coturn gateway xray hysteria2; exit=0
$ python -m src.main xray --help        → install/add-client/status/remove; exit=0
$ python -m src.main hysteria2 --help   → install/add-client/status/remove; exit=0

$ rm -rf /tmp/vds-test; INSTALL_DIR=/tmp/vds-test python -m src.main gateway status
 Файл состояния: /tmp/vds-test/gateway/state.json
 Состояние пусто: протоколы не установлены.
exit=0
$ python -m src.main gateway status
 Файл состояния: /opt/my-vds/gateway/state.json
 Состояние пусто: протоколы не установлены.
exit=0

$ echo '{broken json' > /tmp/vds-test/gateway/state.json
$ INSTALL_DIR=/tmp/vds-test python -m src.main gateway status
 Файл состояния: /tmp/vds-test/gateway/state.json
 Не удалось прочитать /tmp/vds-test/gateway/state.json: повреждённый JSON
(Expecting property name enclosed in double quotes: line 1 column 2 (char 1)).
Восстановите файл вручную или удалите его (клиенты будут потеряны).
exit=1

$ python -m src.main xray status      → «Xray не установлен (нет /usr/local/bin/xray).»; exit=1
$ python -m src.main hysteria2 status → «Hysteria2 не установлен (нет /usr/local/bin/hysteria).»; exit=1

$ id -u → 1000
$ python -m src.main xray install --sni www.example.com
 Требуется root (запустите через sudo).
exit=1

$ python -m src.main xray remove           → «Xray не установлен — нечего удалять.»; exit=0
$ python -m src.main xray remove --apply   → «Xray не установлен — нечего удалять.»; exit=0

$ grep -rn "def load_env" src/  → src/core/shell.py:87:def load_env(path: str) -> dict[str, str]:
$ grep -rn "shell=True" src/ tests/ → src/core/shell.py:34 (legacy run, не менялся);
                                     src/system/setup.py:181 (вне скоупа, не менялся)

# Собственная проверка форматов share-link (FR-1.2/FR-2.2)
vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=www.google.com&fp=chrome&pbk=PUBKEY123&sid=ab12&flow=xtls-rprx-vision#%D1%82%D0%B5%D1%81%D1%82%20client
hysteria2://SecretPass123@5.6.7.8:443/?sni=5.6.7.8&insecure=1#phone1
FORMAT OK (exit=0, точное сравнение с эталоном из REQ/SPEC)
```

## 6. Найденные дефекты
| # | Симптом | Воспроизведение | Серьёзность | → DEBUG |
|---|---|---|---|---|
| 1 | SPEC §5 обещает глобальный фильтр маскирования в `core/logger.py` (`uuid\|password\|privateKey\|pbk` → `***`) — фильтра нет; маскирование реализовано точечно (xray/status.py, hysteria2/status.py, journal). AC REQ («в логах замаскирован или отсутствует») выполнено: clients.py секреты в лог не пишет вообще | `cat src/core/logger.py` — нет фильтра | minor (расхождение SPEC↔код, не влияет на AC) | — (решить архитектору: поправить SPEC или добавить фильтр) |
| 2 | `run_remove(yes=...)` существует в API, но CLI не exposes `--yes` (попытка `xray remove --apply --yes` → typer «No such option '--yes'», exit 2). Интерактивный confirm есть — NFR соблюдён | `python -m src.main xray remove --apply --yes` | minor | — |
| 3 | FR-0.2 проверен статически (наборы совпадают, пины ≥ floor'ов pyproject), прогон в чистом venv не выполнялся | — | minor (недопокрытие, не дефект кода) | — |

## 7. Вывод
Локально проверяемая часть MVP работает: синтаксис, 126 unit-тестов, CLI-поверхность
(xray/hysteria2/gateway), негативные ветки (битый JSON, нет root, не установлен,
нечего удалять), форматы share-link побайтово, права 0600, dry-run, блокировки,
ленивые импорты, отсутствие `shell=True` в новом коде, списки в `docker_exec`.

**Не проверено (и почему):**
- Все **[VDS]**-AC — нет живого сервера; вынесены в чеклист владельца (§8).
- FR-0.2 в чистом venv (`pip install -e .` vs `-r requirements.txt`) — статически
  консистентно, реальный прогон не делался.
- Интеграционный прогон zerotier-команд после P1/P3-рефакторинга (Docker/root) —
  только compileall + чтение diff; smoke FR-0.3 остаётся [VDS].
- Идемпотентность двойным install на живом сервере (E4) — [VDS].
- TUI интерактивно (questionary) — проверен smoke-уровнем по коду main.py.

## 8. VDS-чеклист для владельца (частичная приёмка фаз 1–2)

Выполнять на живом VDS (Ubuntu 24.04, root), по порядку. Каждая строка: команда →
ожидаемый результат. Метки AC — из REQ-20261107.

### Подготовка
```
cd <repo> && sudo bash install.sh        # установка пакета (или pip install -e .[dev])
vds --help                                # видны gateway / xray / hysteria2
```

### E5 / NFR Root (нет root)
1. `vds xray install` (без sudo) → `[error] Требуется root`, exit 1, ничего не изменено
2. `vds hysteria2 install` (без sudo) → аналогично

### FR-1.1 / E1 (Xray install, занятый порт)
3. Занять 443: `python3 -m http.server 443 &` → `vds xray install` →
   `[error] Порт 443/tcp занят (владелец: …python3…)` ДО изменений; убить http.server;
   `ss -tlnp | grep :443` — ничего не появилось

### FR-1.1 (чистая установка)
4. `sudo vds xray install` → exit 0
5. `systemctl is-active vds-xray` → `active`
6. `ss -tlnp | grep ':443 '` → xray слушает TCP 443
7. `stat -c '%a' /usr/local/etc/xray/config.json` → `600`
8. Повтор `sudo vds xray install` (E4) → «уже установлен», exit 0, сервис active,
   `config.json` не перегенерирован (сравнить mtime/uuid)

### FR-1.1 (нестандартный SNI)
9. `sudo vds xray install --sni www.cloudflare.com` (на чистой системе) →
   `grep -E 'dest|serverNames' /usr/local/etc/xray/config.json` содержит
   `www.cloudflare.com:443` и `www.cloudflare.com`

### FR-1.2 (add-client на VDS)
10. `sudo vds xray add-client phone` → ссылка `vless://…security=reality&sni=…&fp=chrome&pbk=…&sid=…&flow=xtls-rprx-vision#phone`;
    в выводе НЕТ `privateKey`; импорт в v2rayNG/NekoRay → подключение проходит
11. `sudo vds xray add-client phone` (дубль) → `[error] Клиент с именем 'phone' уже существует.`
12. Визуально: UUID в выводе/логах отсутствует вне share-link (`journalctl -u vds-xray -n 50 | grep -i <uuid>` → пусто)

### FR-1.3 / E9 (status)
13. `sudo vds xray status` → юнит active, «Конфиг валиден (`xray -test` — OK)»,
    порт 443/tcp слушается, journal без секретов
14. Порча конфига: `echo 'x' >> /usr/local/etc/xray/config.json` → `vds xray status`
    → «Конфиг невалиден … FAIL»; восстановить из бэкапа/переустановкой

### FR-X.1 (probe-resistance)
15. С внешней машины: `curl -vk https://<ip>/ --resolve example.com:443:<ip>` →
    TLS-ответ соответствует сайту-маски (dest), нет признаков прокси/сертификата Xray

### FR-2.1 / E2 (Hysteria2)
16. Занять UDP 443 (например `nc -ul 443 &`) → `sudo vds hysteria2 install` →
    `[error] Порт 443/udp занят…` ДО изменений
17. `sudo vds hysteria2 install` → exit 0; `systemctl is-active vds-hysteria2` = active;
    `ss -ulnp | grep ':443 '`; `stat -c '%a' /etc/hysteria/config.yaml` → `600`;
    `openssl x509 -in /etc/hysteria/cert.pem -enddate -noout` → срок ~10 лет
18. Повторный `sudo vds hysteria2 install` (E4) → «уже установлен», сертификат/пароль
    НЕ перегенерированы (сравнить `md5sum /etc/hysteria/cert.pem` до/после)

### FR-2.2 / FR-2.3 / E10
19. `sudo vds hysteria2 add-client mob` → ссылка `hysteria2://…@<ip>:443/?sni=<ip>&insecure=1#mob`;
    подключение клиента в тестовом режиме проходит
20. `sudo vds hysteria2 status` → юнит active, сертификат «осталось N дн.», UDP 443

### FR-2.4 (sysctl)
21. `sysctl net.ipv4.tcp_congestion_control` → `bbr`;
    `cat /etc/sysctl.d/99-vds-gateway.conf` — из шаблона; повторный install — файл не дублируется

### FR-X.2 (коэкспансия на 443)
22. При установленных обоих: `ss -tlnp | grep :443` → xray; `ss -ulnp | grep :443` →
    hysteria2; оба `systemctl is-active` = active

### FR-0.3 (docker_exec smoke, если есть ZTNET-контейнер)
23. `sudo vds zerotier diagnose` (или reconcile) → команды в контейнере работают

### Откат (dry-run/apply)
24. `sudo vds xray remove` → только план (dry-run), ничего не удалено;
    `ss -tlnp | grep :443` — всё ещё слушает
25. `sudo vds xray remove --apply` + подтверждение → юнит disabled, файлы удалены,
    клиенты xray исчезли из `vds gateway status`, порт 443 свободен
26. `sudo vds xray remove --apply` повторно (E8) → «нечего удалять», exit 0
27. Аналогично 24–26 для `vds hysteria2 remove` (sysctl остаётся — by design, ADR-002)

### E6 (обрыв сети, опционально)
28. Эмулировать недоступность GitHub при `xray install` (например `iptables -A OUTPUT
    -d <github_ip> -j REJECT`) → понятная ошибка, «готовых» частичных файлов нет;
    после снятия блока повторный install succeeds

Результаты каждого пункта зафиксировать (команда + вывод) и передать
оркестратору для закрытия [VDS]-части приёмки.
