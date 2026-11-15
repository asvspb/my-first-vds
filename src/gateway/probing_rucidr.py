"""RU-CIDR на exit-серверах без релея (SPEC-20261116-probe-response §3).

`ru-cidrs.txt` сегодня ставит relay-модуль — но релея на asv1/asv2 ещё нет,
а вердикт RU-PROBE-SUSPECT (и threat high) без агрегата недостижим. Здесь —
та же загрузка ipdeny БЕЗ relay-специфики (никаких nft-policy/mark/table100):

- `vds gateway probe-watch ru-cidr install --apply` — агрегат →
  /etc/vds-relay/ru-cidrs.txt (тот же путь, что ждёт relay; совместимость)
  + еженедельный таймер vds-probe-rucidr.timer (копия паттерна relay-CIDR);
- `vds gateway probe-watch ru-cidr update --apply` — разовое обновление
  (вызывается и таймером; сбой сети → exit 1, прежний агрегат не трогаем).

Переиспользование src/relay/cidr.py — import (fetch/aggregate), не копипаста.
Без relay-модуля файл независим; relay init при будущем деплое пишет тот же
файл из того же источника — идемпотентно, не конфликтует (SPEC §3).

Dry-run по умолчанию, --apply + FileLock (общий с probe-watch), root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from src.core.logger import console
from src.gateway.probing import (
    LOCK_FILE,
    PROBE_RUCIDR_TIMER,
    PROBE_RUCIDR_UNIT,
    RU_CIDR_FILE,
    _atomic_write,
    _unit_ctx,
)


def update_aggregate(timeout: int = 60, target: Optional[Path] = None) -> int:
    """Скачать ipdeny ru.zone → агрегировать → атомарно записать target (0644).

    0 — успех; 1 — отказ (сеть/парсинг/запись). Прежний агрегат при отказе
    не повреждается (атомарная запись только после успешной загрузки).
    target=None → путь по умолчанию (RU_CIDR_FILE, читается в момент вызова —
    тесты monkeypatch'ят).
    """
    target = target or RU_CIDR_FILE
    import src.relay.cidr as relay_cidr  # лениво: requests в import-chain

    try:
        raw = relay_cidr.fetch(timeout=timeout)
        # ipdeny ru.zone — v4-зона, но формат не гарантирован: v6-строки
        # отбрасываем ДО aggregate (строгий v4-парсер relay.cidr), мусор
        # по-прежнему даёт ValueError → честный отказ без порчи агрегата.
        v4_lines = [ln for ln in raw if ":" not in ln]
        cidrs = relay_cidr.aggregate(v4_lines)
    except (RuntimeError, ValueError, relay_cidr.requests.RequestException) as exc:
        console.print(f"[error][probe-ru] {exc} — агрегат не обновлён.[/error]")
        return 1
    if not _atomic_write(target, "\n".join(cidrs) + "\n", 0o644):
        return 1
    console.print(
        f"[success][probe-ru] RU-CIDR обновлён: {len(cidrs)} агрегатов → {target} "
        "(путь совместим с relay; RU-PROBE-SUSPECT активен).[/success]"
    )
    return 0


def cmd_ru_cidr_install(apply: bool = False) -> int:
    """install: агрегат + еженедельный таймер (идемпотентно, root)."""
    if not apply:
        console.print("[info][probe-ru] DRY-RUN план ru-cidr install:[/info]")
        console.print(f"[info][probe-ru]   1. скачать ipdeny ru.zone → агрегат → {RU_CIDR_FILE} (0644, атомарно)[/info]")
        console.print(f"[info][probe-ru]   2. юниты {PROBE_RUCIDR_UNIT} + {PROBE_RUCIDR_TIMER} из systemd-шаблонов[/info]")
        console.print("[info][probe-ru]   3. systemctl enable --now таймер (еженедельно, Sun 04:40)[/info]")
        console.print("[info][probe-ru] Запустите с --apply для исполнения.[/info]")
        return 0

    from src.core.lock import FileLock
    from src.core.shell import run_list
    from src.core.units import install_unit

    with FileLock(LOCK_FILE):
        if update_aggregate() != 0:
            console.print(
                "[warning][probe-ru] Первичная загрузка не удалась — юниты ставятся, "
                "таймер дотянет агрегат при первом успехе (паттерн relay init).[/warning]"
            )
        ctx = _unit_ctx()
        if not install_unit("vds-probe-rucidr.service.tpl", PROBE_RUCIDR_UNIT, ctx):
            return 1
        if not install_unit("vds-probe-rucidr.timer.tpl", PROBE_RUCIDR_TIMER, ctx):
            return 1
        start = run_list(["systemctl", "enable", "--now", PROBE_RUCIDR_TIMER], timeout=15)
        if not start.ok:
            console.print(
                f"[warning][probe-ru] {PROBE_RUCIDR_TIMER} не включён: "
                f"{start.stderr.strip()} — включите вручную.[/warning]"
            )
    console.print(
        f"[success][probe-ru] RU-CIDR установлен: {RU_CIDR_FILE} + еженедельный "
        f"{PROBE_RUCIDR_TIMER}. Вердикт RU-PROBE-SUSPECT включён (SPEC §3).[/success]"
    )
    return 0


def cmd_ru_cidr_update(apply: bool = False) -> int:
    """update: разовое обновление агрегата (таймер зовёт именно это)."""
    if not apply:
        console.print("[info][probe-ru] DRY-RUN: обновление агрегата ipdeny → "
                      f"{RU_CIDR_FILE} (сбой сети не трогает прежний).[/info]")
        return 0

    from src.core.lock import FileLock

    with FileLock(LOCK_FILE):
        return update_aggregate()
