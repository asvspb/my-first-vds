"""ACME HTTP-01 «окно» 80/tcp (SPEC-20261124-quiet-exit §2, §10 P1-5).

На quiet-exit профиле 80/tcp закрыт всегда (TECHDEBT P39 закрыт веткой
quiet-exit в src/system/ufw.py — широкий `allow 80/tcp` из _PROTOCOL_RULES
туда не попадает). Certbot standalone биндит :80 сам, поэтому окно обязано
открываться ДО вызова certbot и закрываться в finally (P1-5).

Три механизма:
1. renewal-hooks pre/open + post/close — для штатного certbot.timer renew:
   pre-hook открывает окно и ставит маркер /run/vds-acme-80-opened
   (идемпотентно), post-hook выполняется certbot ВСЕГДА (и при ошибке
   выдачи) и закрывает окно по маркеру; tolerant, всегда exit 0.
2. первичная выдача: `vds acme issue --window-80` — open → certbot →
   close в finally (run_issue, install.py).
3. fail-safe периодический чек: `vds acme check-80-window` — если 80/tcp
   открыт, а маркера нет (post-hook упал до закрытия), печатает [warning]
   и возвращает 1 (нужен для таймера/алерта); stale-маркер без правила
   подчищается.
"""
from __future__ import annotations

from pathlib import Path

from src.core.logger import console
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list

# Маркер окна (SPEC §2/P1-5): существует ⇔ окно открыто нашей механикой.
ACME_80_WINDOW_MARKER = Path("/run/vds-acme-80-opened")
# renewal-hooks (pre выполняется перед renew, post — после, certbot вызывает
# post ВСЕГДА, включая неуспешный renew).
ACME_HOOKS_PRE_DIR = Path("/etc/letsencrypt/renewal-hooks/pre")
ACME_HOOKS_POST_DIR = Path("/etc/letsencrypt/renewal-hooks/post")
ACME_WINDOW_OPEN_HOOK = ACME_HOOKS_PRE_DIR / "vds-acme-80-open.sh"
ACME_WINDOW_CLOSE_HOOK = ACME_HOOKS_POST_DIR / "vds-acme-80-close.sh"

_UFW_80_SPEC = "80/tcp"


class WindowHookError(Exception):
    """Сбой установки/исполнения окна 80/tcp."""


def render_open_hook(marker: Path = ACME_80_WINDOW_MARKER) -> str:
    """Текст pre-hook: открыть 80/tcp + маркер. Идемпотентен (ufw сам
    «Skipping adding»; повторный touch маркера безопасен)."""
    return (
        "#!/bin/sh\n"
        "# Автосгенерировано (SPEC-20261124-quiet-exit §2, P1-5): окно HTTP-01.\n"
        "# pre-hook certbot renew: открыть 80/tcp ДО выдачи (standalone биндит :80 сам).\n"
        "# Править руками нельзя — только перегенерация командой.\n"
        f"ufw allow {_UFW_80_SPEC} || exit 1\n"
        f"touch {marker}\n"
        "exit 0\n"
    )


def render_close_hook(marker: Path = ACME_80_WINDOW_MARKER) -> str:
    """Текст post-hook: закрыть 80/tcp по маркеру; certbot вызывает post ВСЕГДА.
    Tolerant (fail-safe ловит периодический чек): любые сбои — не падать."""
    return (
        "#!/bin/sh\n"
        "# Автосгенерировано (SPEC-20261124-quiet-exit §2, P1-5): закрытие окна.\n"
        "# post-hook выполняется certbot ВСЕГДА (и при ошибке renew). Не должен\n"
        "# падать: сбой удаления ловит периодический `vds acme check-80-window`.\n"
        f"if [ -f {marker} ]; then\n"
        f"    ufw delete allow {_UFW_80_SPEC} || true\n"
        f"    rm -f {marker}\n"
        "fi\n"
        "exit 0\n"
    )


def install_window_hooks() -> bool:
    """Записать pre/open + post/close (0755, атомарно). True при успехе."""
    for path, text in (
        (ACME_WINDOW_OPEN_HOOK, render_open_hook()),
        (ACME_WINDOW_CLOSE_HOOK, render_close_hook()),
    ):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            console.print(f"[error][acme-window] mkdir {path.parent}: {exc}[/error]")
            return False
        if not write_secret_atomic(str(path), text, mode=0o755):
            console.print(f"[error][acme-window] не удалось записать {path}[/error]")
            return False
    console.print(
        f"[success][acme-window] Окно 80/tcp: {ACME_WINDOW_OPEN_HOOK} + "
        f"{ACME_WINDOW_CLOSE_HOOK} установлены (certbot.timer подхватит при renew).[/success]"
    )
    return True


def open_80_window(marker: Path = ACME_80_WINDOW_MARKER) -> bool:
    """Открыть окно: ufw allow 80/tcp + маркер (идемпотентно)."""
    res = run_list(["ufw", "allow", _UFW_80_SPEC], timeout=15)
    if not res.ok:
        out = (res.stdout + res.stderr).lower()
        if "skipping adding" not in out and "rule added" not in out:
            console.print(
                f"[error][acme-window] ufw allow 80/tcp не удался: "
                f"{res.stderr.strip() or res.stdout.strip()}[/error]"
            )
            return False
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch(exist_ok=True)
    except OSError as exc:
        console.print(f"[error][acme-window] маркер {marker}: {exc}[/error]")
        return False
    console.print("[info][acme-window] окно 80/tcp открыто (маркер поставлен).[/info]")
    return True


def close_80_window(marker: Path = ACME_80_WINDOW_MARKER) -> bool:
    """Закрыть окно: ufw delete allow 80/tcp + снять маркер (идемпотентно).
    Возвращает False при сбое удаления правила (маркер сохраняется — чек
    поймает расхождение)."""
    had_marker = marker.is_file()
    if not had_marker:
        return True  # окно не открывалось нами — ничего не делаем
    res = run_list(["ufw", "delete", "allow", _UFW_80_SPEC], timeout=15)
    if not res.ok:
        out = (res.stdout + res.stderr).lower()
        if "could not" not in out and "not found" not in out:
            console.print(
                f"[warning][acme-window] ufw delete allow 80/tcp не удался: "
                f"{res.stderr.strip() or res.stdout.strip()} — правило закроет "
                "периодический чек.[/warning]"
            )
            return False
    try:
        marker.unlink(missing_ok=True)
    except OSError as exc:
        console.print(f"[warning][acme-window] маркер {marker} не снят: {exc}[/warning]")
        return False
    console.print("[info][acme-window] окно 80/tcp закрыто (маркер снят).[/info]")
    return True


def ufw_80_open() -> bool:
    """Есть ли сейчас широкое allow 80/tcp в живом ufw (LC_ALL=C)."""
    from src.system.ufw import parse_ufw_status, parse_ufw_added, run_list as _rl  # лениво

    res = _rl(["ufw", "status", "verbose"], timeout=15)
    if not res.ok:
        return False
    snap = parse_ufw_status(res.stdout)
    if snap.status == "inactive":
        res2 = _rl(["ufw", "show", "added"], timeout=15)
        if res2.ok:
            snap.rules.extend(parse_ufw_added(res2.stdout))
    return snap.has("allow", _UFW_80_SPEC)


def check_window_state(marker: Path = ACME_80_WINDOW_MARKER) -> tuple[int, str]:
    """Fail-safe чек (P1-5): маркер/правило должны быть согласованы.

    Возвращает (severity, сообщение): 2 = 80/tcp открыт вне окна (WARN/алерт),
    1 = stale-маркер без правила (подчищен), 0 = согласовано / ufw недоступен.
    """
    open_now = ufw_80_open()
    if open_now and not marker.is_file():
        return 2, (
            "80/tcp ОТКРЫТ вне окна (post-hook не закрыл?) — закройте: "
            "`sudo ufw delete allow 80/tcp` (TECHDEBT P39-профиль: вне окна 80 закрыт)"
        )
    if marker.is_file() and not open_now:
        try:
            marker.unlink(missing_ok=True)
        except OSError:
            return 1, f"stale-маркер {marker} есть, но правило отсутствует (не снят)"
        return 1, f"stale-маркер {marker} подчищен (правило 80/tcp отсутствует)"
    return 0, ""


def run_check_window() -> int:
    """Точка входа `vds acme check-80-window`. 0 — согласовано; 1 — WARN
    (80 открыт вне окна либо stale-маркер)."""
    try:
        severity, msg = check_window_state()
    except Exception as exc:  # noqa: BLE001 — чек не должен ронять таймер
        console.print(f"[warning][acme-window] чек не удался: {exc}[/warning]")
        return 1
    if severity == 0:
        console.print("[info][acme-window] окно 80/tcp: согласовано (закрыто вне окна).[/info]")
        return 0
    console.print(f"[warning][acme-window] {msg}[/warning]")
    return 1
