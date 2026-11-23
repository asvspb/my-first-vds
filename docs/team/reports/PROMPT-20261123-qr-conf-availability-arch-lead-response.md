# PROMPT-20261123-qr-conf-availability — ответ архлида (получен 24.11 01:03 MSK)

> Ответ на мандат 8c67e90. Ключевое: аудит нашёл существующий vpn qr v1 (SPEC-20261118, rev.3.2, G2 PASS) — параллельный фасад не строим, эволюция до v1.1/rev.4. Решения D1–D4 + план WP-QR4…WP-QR7. WP-QR4 можно вести во время окна G6; деплой — после ACCEPT-G6 и вне окна A2.

---

0. Критическая находка аудита по коду (до решений D1–D4)
В докладе PROMPT-20261123-qr-conf-availability-arch-lead.md (§2) пропущена уже реализованная подсистема в ubuntuInstaller@fab43fb:
vpn qr уже существует и принят по doc/specs/SPEC-20261118-vpn-qr.md (rev.3.2, G2 PASS) — коммиты db50bec → 1dcf2bc (WP-QR1) → 48c848a (WP-QR2) → e3abc81 (WP-QR3), зарегистрирован в vpnm/cli.py:234–239 (app.command("qr", ...)(qr_command) — поэтому grep по @app.command его не поймал), реализация в vpnm/qrgen/{cli,models,resolver,builders,redact,render}.py, документирован в doc/vpn-manager.md:80,452–468, покрыт tests/qrgen/.
Что в нём уже работает:
точная 3-осевая таксономия --direct|--relay × --awg|--reality|--xhttp|--hy × --android|--ios|--windows|--macos|--linux (+ --profile, --client, --format qr|uri|png|svg|json, --out, --force, --show-uri);
атомарная запись файлов с правами 0600 (qrgen/render.py:146–191);
санитизация секретов (qrgen/redact.py) и безопасная шапка без секретов (render.py:201–209);
стрип Table = off (builders.py:_sanitize_awg) и предупреждения о коллизии активного пира / отсутствии DNS/PersistentKeepalive (resolver.py:54–62).
Почему инцидент всё равно возможен — реальные 4 дыры vpn qr v1 (то, что реально надо закрывать в v1.1):
Нет синхронизации AWG и релея (реальный R2): vpn qr v1 строго офлайн; vpn profile pull (vpnm/pull.py) тянет только vds gateway links (Xray/Hy2) и хранит в settings.json (vpnm/settings.py) ровно один ssh_host — ни relay_ssh_host, ни пулла AWG .conf с exit (/opt/my-vds/gateway/clients/amneziawg/) и релея (/opt/my-vds/gateway/clients/relay/) нет.
Коллизия имён и несовпадение stem’ов в LOCAL_CONF_DIR (реальный R1): resolver.py читает все AWG-файлы плоско из ~/.awg/*.conf. Из-за этого:
прямой и релейный профили телефона дерутся за одно имя ~/.awg/android.conf (resolver.py:47 и :253);
на exit файлы называются mobile.conf/win.conf/laptop.conf, а резолвер ищет только android.conf/windows.conf/linux.conf;
на ноутбуке часть .conf лежит в ~/.config/vpn-manager/, а resolver.py туда не смотрит (LOCAL_CONF_DIR = ~/.awg).
Эфемерный терминальный QR (реальный R3): дефолтный vpn qr (--format qr) запрещает --out (qrgen/cli.py:55) и ничего не сохраняет; --format png требует ручного --out <path> и не показывает QR/текст.
Мёртвые профили не изолированы (реальный R4): resolver.py:_local_conf_candidates() сканирует все *.conf в ~/.awg/. Если единственный non-relay файл в ~/.awg/ — мёртвый конфиг выключенного asv1, ветка len(local_direct) == 1 молча выдаст его как рабочий --direct --awg.
Архитектурный вывод: новый параллельный фасад не строим. Эволюционируем SPEC-20261118-vpn-qr (v1 → v1.1 / rev.4) поверх существующего движка vpnm/qrgen/.
DECISION D1 — Форма CLI, --qr как опция и матрица «флаг → источник»
Решение: Сохранить существующий vpn qr (с авто-сохранением PNG) и добавить парную команду верхнего уровня vpn conf на том же движке vpnm/qrgen/ с опцией --qr, а сетевую подтяжку авторитетных серверных файлов вынести в vpn sync (и opt-in флаг --sync на обеих командах), оставив vpn qr/vpn conf офлайновыми по умолчанию.
Альтернативы:
Только vpn conf ... --qr (убрать/депрекейтить vpn qr): отказ — vpn qr уже сдан по G2 PASS с 57+ тестами и описан в doc/vpn-manager.md; ломка существующего контракта и мышечной памяти без выигрыша.
Расширить vpn profile qr/config + vpn amneziawg qr: отказ — они разорваны по разным сторам (profiles.json vs ~/.awg) и оперируют локальными именами, а не таксономией route × proto × os. Оставляем их как low-level legacy-команды без слома обратной совместимости.
Ходить по SSH/SCP на каждый вызов vpn qr/vpn conf по умолчанию: отказ — нарушает инвариант SPEC-20261118-vpn-qr (офлайн, быстро, работает в момент блокировки/недоступности SSH к exit или релею) и смешивает read-only рендер с сетевой мутацией локального кэша.
Почему: Один движок (vpnm/qrgen/) обслуживает два естественных сценария без дублирования логики:
vpn conf <оси> [--qr] [--reveal] [--sync] [--no-save] [--out PATH] — основной сценарий оператора: гарантирует локальный файл .conf/.uri (0600), печатает путь к файлу + маскированный текст; с --qr дополнительно рисует QR в терминал и сохраняет PNG (0600) в канонический каталог артефактов.
vpn qr <оси> [--sync] [--no-save] [--format qr|uri|png|svg|json] [--out PATH] [--show-uri|--reveal] — быстрый QR-сценарий; в v1.1 по умолчанию авто-сохраняет PNG (0600) в канонический каталог артефактов и печатает в шапке оба пути (исходный .conf + сохранённый .png), закрывая R3 без потери совместимости с v1 (--no-save отключает запись).
vpn sync [--direct|--relay|--all] [--exit-host H] [--relay-host H] [--include-obfs] [--dry-run] — единственная сетевая точка, которая синхронизирует локальный кэш с авторитетными серверами (read-only на серверах: vds gateway links + scp из клиентских каталогов, без мутации серверов).
Итоговые сигнатуры и матрица «флаг → источник»:
Оси (единые для vpn conf и vpn qr, ровно по одному из группы, как в qrgen/cli.py):
Маршрут: --direct | --relay
Транспорт: --awg | --reality | --xhttp | --hy (--hy2)
Устройство/ОС: --android | --ios | --windows | --macos | --linux (алиас --laptop → linux допустим как синоним, чтобы снять трение из R1)
Уточнение/вывод: --profile NAME, --client ..., --sync (подтянуть с сервера перед выдачей), --qr (на vpn conf), --reveal (алиас --show-uri на vpn qr), --no-save, --out PATH, --force.
Матрица источников (источник правды = сервер, локальный кэш = read-only копия 0600):
Маршрут	Протокол	Серверный источник правды (при vpn sync / --sync)	Локальный кэш (офлайн-резолв vpnm/qrgen)
--direct	--awg	exit_host: /opt/my-vds/gateway/clients/amneziawg/*.conf (AWG_CLIENTS_DIR, scp)	~/.awg/direct/<stem>.conf (fallback: legacy ~/.awg/<stem>.conf с warning, затем активный mode.json с warning о коллизии)
--relay	--awg	relay_host: /opt/my-vds/gateway/clients/relay/*.conf (RELAY_CLIENTS_DIR, scp)	~/.awg/relay/<stem>.conf (fallback: legacy ~/.awg/relay*.conf с warning)
--direct	--reality / --xhttp / --hy	exit_host: vds gateway links [--include-obfs] (ssh)	~/.config/vpn-manager/profiles.json (записи с route=direct / не-relay host)
--relay	--reality	relay_host: vds gateway links (ssh)	~/.config/vpn-manager/profiles.json (записи с route=relay / relay_host)
--relay	--xhttp / --hy	—	Код 3 (EXIT_UNSUPPORTED_COMBO) — на релее инбаундов нет
Что меняется: doc/specs/SPEC-20261118-vpn-qr.md (v1.1 / rev.4), vpnm/settings.py (добавить relay_ssh_host, сохранив ssh_host как exit_host), vpnm/qrgen/{cli,models,resolver,render}.py, новый модуль vpnm/sync.py, регистрация vpn conf и vpn sync в vpnm/cli.py. На сервере (my-first-vds) изменений не требуется (пути уже зафиксированы в src/gateway/paths.py и src/relay/paths.py).
Проверка: CLI-тесты tests/qrgen/test_qrgen_cli.py + tests/test_sync.py: все комбинации осей, отказ --relay --xhttp/--hy (код 3), офлайн-работа без сети по умолчанию, --sync вызывает только ssh/scp через мок run_cmd.
Не проверено: какая именно ревизия ubuntuInstaller установлена сейчас в pipx на управляющем ноутбуке (до закрытия G6 не проверяем и не переставляем); точный список vds gateway links на живом релее (есть ли там Reality-ссылка в state.json релея или она импортируется вручную — нужно проверить на релее перед WP-QR5).
DECISION D2 — Политика секретов, прав доступа и вывода в терминал
Решение: Все локальные файлы (.conf, .uri, .png, .svg, .json) пишутся атомарно с правами 0600 в каталог с правами 0700; вывод в терминал по умолчанию маскирует все секреты (сырые PrivateKey/PresharedKey/UUID/пароли — только по явному --reveal / --show-uri с предупреждением в stderr).
Альтернативы:
Печатать сырой .conf в stdout vpn conf по умолчанию: отказ — случайная вставка вывода терминала в тикет/чат/скриншот сливает PrivateKey и заставляет перевыпускать пир (нарушает инвариант SPEC-20261118-vpn-qr §1.3 и §5 основного пакета).
Сохранять PNG в ~/qrcodes/ (как делалось вручную): отказ — каталог в $HOME часто создаётся с 0755, легко попадает в бэкапы/синхронизации; канонический XDG-путь с 0700 безопаснее и предсказуемее.
Почему: PNG-файл QR-кода для AWG содержит PrivateKey в открытом виде (достаточно zbarimg), а для Reality/Hy2 — uuid/auth/obfs-password. Поэтому PNG по уровню секретности равен .conf:
Каталог артефактов: ~/.local/share/vpn-manager/artifacts/ (переопределяется env VPN_MANAGER_ARTIFACTS_DIR для изоляции в тестах), права каталога 0700, права всех файлов внутри — 0600 (mkstemp + os.fchmod(fd, 0o600) + fsync + os.replace, паттерн уже есть в qrgen/render.py:146–191). При записи --out <custom_path> права файла тоже принудительно 0600, а если родительский каталог world-readable (напр. /tmp) — печатается WARNING в stderr.
Вывод vpn conf по умолчанию:
Шапка: [vpn conf] route | proto | os | client | profile | endpoint | sha256 | origin (local/synced, mtime).
Строки путей: Conf: <path> (0600) и при --qr — QR PNG: <path> (0600).
Тело конфига/URI, пропущенное через vpnm/qrgen/redact.py (PrivateKey = <redacted>, PresharedKey = <redacted>, vless://<redacted>...).
Подсказка: Для сырого текста с секретами: добавьте --reveal.
Вывод с --reveal (и --show-uri на vpn qr): печатает сырой payload в stdout (пригодно для | xclip), в stderr всегда идёт WARNING: вывод содержит секреты — не вставляйте в логи/чаты/git.
Запреты: секреты никогда не передаются в argv (только stdin в qrencode — уже соблюдено в render.py), не пишутся в stdout/stderr ошибок (redact_error), не попадают в vpn guard и git. В доках и фикстурах — только FIXTURE_*, RFC 5737 (192.0.2.x / 198.51.100.x / 203.0.113.x), 11111111-2222-….
Что меняется: SPEC-20261118-vpn-qr.md §1.3, §5, vpnm/qrgen/render.py (авто-сохранение PNG/conf в ARTIFACTS_DIR, режим masked-preview для vpn conf, проверка прав родительского каталога при --out).
Проверка: расширить AC-QR-7 в tests/qrgen/: (a) default vpn conf и vpn qr не содержат FIXTURE_PRIVATE_KEY / UUID ни в stdout, ни в stderr; (b) --reveal содержит payload в stdout и warning в stderr; (c) каталог артефактов 0700, сохранённые .conf и .png — 0600, при перезаписи права не сбрасываются.
Не проверено: текущие права существующих файлов в ~/.config/vpn-manager/*.conf и ~/qrcodes/*.png на живом ноутбуке.
DECISION D3 — Политика именования, маппинга устройств и маркировки мёртвых профилей
Решение: Разделить локальные AWG-конфиги по подкаталогам маршрута (~/.awg/direct/, ~/.awg/relay/, ~/.awg/archive/), ввести таблицу алиасов устройств в резолвере (без переименования серверных пиров), стандартизовать имена артефактов <route>-<proto>-<os>-<profile>.{png,conf} и ввести явный статус archived для мёртвых профилей.
Альтернативы:
Переименовывать существующие пиры на сервере (mobile.conf → android.conf, win.conf → windows.conf): отказ — лишний риск трогать рабочие серверные пиры и state.json ради клиентского удобства.
Автоматически удалять локальные файлы, которых нет на сервере при vpn sync: отказ — деструктивное действие без --apply нарушает базовую конвенцию проекта; локальный файл может быть временным/резервным.
Держать мёртвые .conf в общем ~/.awg/ и полагаться на память оператора: отказ — уже привело к R4 и создаёт ловушку в resolver.py (len(local_direct) == 1).
Почему:
Изоляция маршрутов (убирает коллизию android.conf):
~/.awg/direct/<stem>.conf — пулл с exit_host:/opt/my-vds/gateway/clients/amneziawg/
~/.awg/relay/<stem>.conf — пулл с relay_host:/opt/my-vds/gateway/clients/relay/
~/.awg/archive/<tag>-<stem>.conf — выведенные из эксплуатации (asv1-mobile-awg.conf), резолвер туда не ходит (кроме явного --include-archived).
Legacy ~/.awg/*.conf читается только как fallback с WARNING: устаревшее расположение, выполните vpn sync или перенесите в direct/relay/archive.
Алиасы устройств в resolver.py (убирает разнобой exit vs relay):
android: ("android", "mobile", "phone")
windows: ("windows", "win")
linux: ("linux", "laptop", "desktop")
ios: ("ios", "iphone", "ipad")
macos: ("macos", "mac")
При совпадении ≥2 кандидатов — fail-closed (код 4) со списком найденных имён и подсказкой --profile <NAME> (никаких тихих угадываний).
Детерминированные имена артефактов:
<ARTIFACTS_DIR>/<route>-<proto>-<os>-<profile>.png (напр. direct-awg-android-mobile.png, relay-awg-android-android.png),
для URI-протоколов при сохранении: <ARTIFACTS_DIR>/<route>-<proto>-<os>-<profile>.uri,
для AWG .conf при авто-сохранении уже есть канонический sanitized-файл <ARTIFACTS_DIR>/<route>-<proto>-<os>-<profile>.conf (без Table = off — готовый к переносу на телефон/Windows), а оригинал лежит в ~/.awg/<route>/<profile>.conf.
При изменении payload_sha256 файл перезаписывается атомарно (чтобы старый PNG никогда не рассинхронизировался с новым конфигом).
Маркировка мёртвых профилей (R4):
В profiles.json — аддитивные опциональные поля: "status": "active" | "archived" (отсутствие = "active"), "archived_reason": str, "route": "direct" | "relay", "source_host": str, "synced_at": str.
В AWG .conf — либо перенос в ~/.awg/archive/, либо заголовок # vpnm:status=archived reason=<...> (если файл оставлен на месте, резолвер его пропускает при авто-подборе, а при явном --profile выдаёт код 4 или требует --include-archived с громким WARNING: ARCHIVED).
Команда vpn profile archive <name> --reason "..." [--apply] (dry-run по умолчанию, для записей profiles.json и AWG .conf) + в vpn sync отчёт о «сиротах»: локальные активные профили, которых больше нет на сервере, помечаются в выводе как STALE (absent on server) с подсказкой команды архивации.
Что меняется: SPEC-20261118-vpn-qr.md §3.2, vpnm/qrgen/resolver.py, vpnm/profiles.py (аддитивные метаданные, обратная совместимость со старым profiles.json), vpnm/cli.py (vpn profile archive).
Проверка: юнит-тесты на коллизию direct/android.conf + relay/android.conf, маппинг mobile.conf → --android и win.conf → --windows, пропуск archived-профиля в авто-резолвере (не выбирается даже если он единственный), dry-run/apply для vpn profile archive.
Не проверено: полный перечень файлов в ~/.config/vpn-manager/ и ~/.awg/ на живом ноутбуке (одноразовая чистка mobile-awg.conf → archive/ — ручной шаг оператора после деплоя).
DECISION D4 — План работ (WP-QR4…WP-QR7) и место в очереди циклов
Место в календаре (синхронизировано с docs/team/STATUS.md):
Окно G6 не трогаем: до 2026-11-24 15:24 MSK vpnm на ноутбуке не переустанавливается, vpn-guard.service не перезапускается.
Серверные окна не занимает: весь цикл client-only (ubuntuInstaller), 0 изменений и 0 рестартов на asv2/релее. Может идти параллельно разработке/ревью после закрытия G6; деплой на ноутбук — вместе с клиентским обновлением после ACCEPT-G6 (либо сразу после A2, чтобы не смешивать контур A2 с правками vpnm в момент прогона окна A2).
WP-QR4 — Обновление спецификации (G2-гейт до кода)
Цель: Обновить doc/specs/SPEC-20261118-vpn-qr.md до rev.4 (v1.1): закрепить D1 (vpn conf + --qr, vpn sync, авто-сохранение PNG в vpn qr), D2 (0700/0600, --reveal, ARTIFACTS_DIR), D3 (~/.awg/{direct,relay,archive}, алиасы устройств, status=archived).
Файлы-владелец (ubuntuInstaller): doc/specs/SPEC-20261118-vpn-qr.md.
Зависимости: нет (можно делать уже сейчас, во время G6).
AC: описаны все новые флаги, коды возврата, матрица источников, AC-QR-8…AC-QR-12; нет реальных IP/доменов/секретов.
WP-QR5 — Синхронизация источников и namespace-структура (vpn sync, settings.py, resolver.py)
Цель: Закрыть R1, R2, R4 на уровне данных:
vpnm/settings.py: хранение relay_ssh_host рядом с ssh_host (обратная совместимость).
vpnm/sync.py: read-only пулл с exit_host и relay_host (vds gateway links + scp из AWG_CLIENTS_DIR и RELAY_CLIENTS_DIR в ~/.awg/direct/ и ~/.awg/relay/ с 0600), отчёт imported / updated / skipped / stale, режим --dry-run.
vpnm/qrgen/resolver.py: чтение direct/ и relay/, таблица алиасов устройств (mobile→android, win→windows, laptop→linux), игнорирование archive/ и status=archived, warning на legacy ~/.awg/*.conf.
vpnm/profiles.py: аддитивные поля status, archived_reason, route, source_host, synced_at + функция archive().
Файлы-владелец (ubuntuInstaller): vpnm/settings.py, vpnm/sync.py, vpnm/profiles.py, vpnm/qrgen/resolver.py, vpnm/qrgen/models.py, тесты tests/test_sync.py, tests/qrgen/test_qrgen_resolver.py.
Зависимости: WP-QR4.
AC:
все тесты зелёные под tests/conftest.py (sys_guard, без сети/root, run_cmd/scp замоканы, фикстуры FIXTURE_* + RFC 5737);
direct/mobile.conf + relay/android.conf одновременно резолвятся без коллизии под --direct --android и --relay --android;
архивированный asv1 конфиг никогда не подбирается авто-резолвером;
vpn sync не мутирует сервер (в моках run_cmd только read-only ssh ... vds gateway links, ssh ... ls, scp) и не удаляет локальные файлы.
WP-QR6 — Фасад vpn conf, авто-сохранение PNG в vpn qr, vpn profile archive
Цель: Закрыть R3 и UX-запрос владельца:
vpnm/qrgen/render.py: канонический ARTIFACTS_DIR (0700), авто-сохранение sanitized .conf/.png (0600), masked-вывод для vpn conf по умолчанию + --reveal с stderr-warning.
vpnm/qrgen/cli.py + vpnm/cli.py: регистрация vpn conf (с --qr, --reveal, --sync, --no-save, --out), vpn sync, vpn profile archive (dry-run по умолчанию + --apply); апгрейд vpn qr (авто-сохранение PNG + путь в шапке + --sync + --no-save + алиас --reveal).
Файлы-владелец (ubuntuInstaller): vpnm/qrgen/render.py, vpnm/qrgen/cli.py, vpnm/cli.py, тесты tests/qrgen/test_qrgen_cli.py, tests/qrgen/test_qrgen_render.py.
Зависимости: WP-QR5.
AC:
vpn conf --direct --android --awg сохраняет .conf (0600), печатает путь и маскированный текст без PrivateKey;
vpn conf --direct --android --awg --qr дополнительно печатает QR и сохраняет .png (0600, путь в шапке);
vpn qr --relay --android --awg авто-сохраняет .png (0600) и печатает путь в шапке (--no-save отключает запись);
vpn conf ... --reveal печатает сырой текст в stdout + warning в stderr;
обратная совместимость: все существующие 57+ тестов tests/qrgen/ остаются зелёными (с адаптацией только тех, что проверяли запрет авто-сохранения при дефолтном qr, если такие есть — перенести на --no-save).
WP-QR7 — Документация, docsync и ручная приёмка после G6
Цель: Обновить каноническую доку и прогнать живую приёмку на управляющем ноутбуке.
Файлы-владелец (ubuntuInstaller): doc/vpn-manager.md (таблица команд, раздел vpn qr / vpn conf / vpn sync / архивация, пометка legacy profile qr/config и amneziawg qr), при необходимости запись в my-first-vds/docs/team/STATUS.md.
Зависимости: WP-QR6 + закрытие окна G6 (для живой проверки на ноутбуке).
AC:
в doc/vpn-manager.md нет реальных IP/доменов/секретов (surface-hardening §5);
на живом ноутбуке (после G6): vpn sync подтягивает exit + релей, vpn conf --direct --android --awg --qr и vpn conf --relay --android --awg --qr создают 0600-файлы с валидным QR (zbarimg round-trip совпадает с серверным .conf за вычетом Table = off), мёртвый mobile-awg.conf перенесён в archive/ через vpn profile archive --apply.
Что можно вести параллельно: WP-QR4 (правка спеки) можно начинать немедленно; WP-QR5/WP-QR6 можно кодить и тестировать локально (под моками) без переустановки pipx на ноутбуке, но деплой в рабочий vpn — строго после закрытия G6 (24.11 15:24 MSK) и в паузе вне окна A2.
Основание и не проверено
Основание (открытые файлы):
asvspb/my-first-vds@main: docs/team/reports/PROMPT-20261123-qr-conf-availability-arch-lead.md (8c67e90), src/gateway/paths.py, src/relay/paths.py, src/main.py, docs/team/STATUS.md;
asvspb/ubuntuInstaller@main (fab43fb): doc/specs/SPEC-20261118-vpn-qr.md, doc/vpn-manager.md, scripts/vpn-manager/vpnm/cli.py, vpnm/qrgen/{cli,models,resolver,builders,redact,render}.py, vpnm/pull.py, vpnm/settings.py, vpnm/amneziawg.py, vpnm/profiles.py, tests/conftest.py, история коммитов db50bec..fab43fb.
Не проверено:
установленная версия vpnm в pipx на управляющем ноутбуке и фактическое содержимое ~/.awg/, ~/.config/vpn-manager/, ~/qrcodes/;
поддерживает ли живой релей vds gateway links (есть ли там Reality-профиль в state.json релея или только AWG в clients/relay/);
существующие тесты tests/qrgen/test_qrgen_*.py (их точные ассерты на дефолтный --format qr без записи файла — проверить в начале WP-QR6);
docs/team/reports/PROMPT-20261122-cycle-order-gemini-architect.md целиком не открывался (порядок циклов проверен по docs/team/STATUS.md).