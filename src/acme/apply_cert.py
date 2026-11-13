"""Подмена self-signed сертификата Hysteria2 на LE (SPEC WP-2, REQ FR-2.2).

Поток `vds hysteria2 apply-cert [--apply|--restore]`:

- dry-run по умолчанию: печатает план (источник LE -> цели /etc/hysteria,
  бэкап `.bak-pre-le`, restart юнита) без изменений;
- `--apply` под FileLock: бэкап текущих cert/key в `.bak-pre-le` (существующий
  бэкап НЕ перезаписывается — он всегда остаётся исходным self-signed, путь
  отката), атомарная запись LE cert/key с 0600 (E9), restart vds-hysteria2;
- `--restore`: возврат self-signed из `.bak-pre-le` (ADR-004 «Как откатить»),
  restart, 0600.

Домен берётся из state.protocols["acme"]["domain"] (пишет WP-1). Приватный
материал (LE privkey) не печатается и не логируется; в выводе — только пути.
"""

import os
import shutil
from pathlib import Path

from src.acme.install import (
    FULLCHAIN_NAME,
    PRIVKEY_NAME,
    _parse_not_after,
)
from src.core.lock import FileLock
from src.core.logger import console
from src.core.shell import run_list
from src.gateway.paths import (
    ACME_LETSENCRYPT_LIVE,
    HYSTERIA2_CERT_PATH,
    HYSTERIA2_KEY_PATH,
    HYSTERIA2_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state

LOCK_FILE = "/var/run/vds-acme-apply.lock"

BACKUP_SUFFIX = ".bak-pre-le"


def _days_left(cert_path: Path) -> int | None:
    """Дней до истечения сертификата через `openssl x509 -enddate` (мокируемо)."""
    result = run_list(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
        timeout=10,
    )
    if not result.ok:
        return None
    try:
        return _parse_not_after(result.stdout.strip())
    except ValueError:
        return None


class ApplyCertError(Exception):
    """Сбой подмены/отката сертификата Hysteria2 (нет домена, нет файлов)."""


def _read_domain(state_path: str | None) -> str:
    """Домен из state.protocols["acme"]["domain"] (WP-1); пусто — LE не выдан."""
    try:
        state = load_state(state_path)
    except StoreError as exc:
        raise ApplyCertError(f"Не удалось прочитать состояние: {exc}") from exc
    meta = state.protocols.get("acme") or {}
    domain = str(meta.get("domain") or "")
    if not domain:
        raise ApplyCertError(
            "Домен LE не найден в состоянии — сначала выполните `vds acme issue`."
        )
    return domain


def _le_paths(domain: str) -> tuple[Path, Path]:
    """Пути LE-сертификата certbot для домена (fullchain/privkey)."""
    live = ACME_LETSENCRYPT_LIVE(domain)
    return live / FULLCHAIN_NAME, live / PRIVKEY_NAME


def _plan(domain: str) -> dict:
    """План операции: источник, цели, бэкапы, юнит (чистая функция, без I/O-мутий)."""
    le_cert, le_key = _le_paths(domain)
    return {
        "domain": domain,
        "source_cert": str(le_cert),
        "source_key": str(le_key),
        "target_cert": str(HYSTERIA2_CERT_PATH),
        "target_key": str(HYSTERIA2_KEY_PATH),
        "backup_cert": str(HYSTERIA2_CERT_PATH) + BACKUP_SUFFIX,
        "backup_key": str(HYSTERIA2_KEY_PATH) + BACKUP_SUFFIX,
        "unit": HYSTERIA2_UNIT,
    }


def _validate_inputs(domain: str) -> None:
    """LE fullchain и privkey должны существовать ДО любых изменений."""
    le_cert, le_key = _le_paths(domain)
    missing = [str(p) for p in (le_cert, le_key) if not p.is_file()]
    if missing:
        raise ApplyCertError(
            "Файлы LE-сертификата не найдены: " + ", ".join(missing)
            + " — сначала выполните `vds acme issue`."
        )


def _copy_0600(source: Path, target: Path) -> None:
    """Атомарно скопировать файл с правами 0600 (E9)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    text = source.read_text(encoding="utf-8")
    tmp = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)


def _set_state_cert_domain(domain: str, state_path: str | None) -> None:
    """Зафиксировать домен развёрнутого сертификата в state (GR-10).

    Ссылки рендерят `sni=<domain>`, а `host` — адрес сервера; без этой записи
    клиенты получат TLS-mismatch, если домен сертификата ≠ state.domain.
    """
    try:
        state = load_state(state_path)
    except StoreError:
        return  # state недоступен — подмена сертификата уже выполнена
    meta = state.protocols.get("hysteria2") or {}
    if not meta.get("installed"):
        return
    meta["cert_domain"] = domain
    try:
        save_state(state, state_path)
    except (StoreError, OSError):
        return


def apply_certificate(dry_run: bool = True, state_path: str | None = None) -> dict:
    """Подменить self-signed сертификат Hysteria2 на LE (REQ FR-2.2).

    dry_run=True (по умолчанию): только план, ничего не пишется.
    dry_run=False: бэкап `.bak-pre-le` (существующий бэкап не перезаписывается),
    копия LE cert/key с 0600, restart vds-hysteria2. Идемпотентно (E4).
    Бросает ApplyCertError при отсутствии домена/файлов.
    """
    domain = _read_domain(state_path)
    plan = _plan(domain)
    result = dict(plan)
    result["dry_run"] = dry_run

    if dry_run:
        result["days_left"] = (
            _days_left(Path(plan["source_cert"]))
            if Path(plan["source_cert"]).is_file()
            else None
        )
        return result

    _validate_inputs(domain)

    with FileLock(LOCK_FILE):
        # Бэкап исходного self-signed; существующий бэкап не перезаписываем,
        # чтобы он всегда указывал на исходные (self-signed) файлы.
        for target_key in ("target_cert", "target_key"):
            target = Path(plan[target_key])
            backup = Path(plan[target_key.replace("target", "backup")])
            if target.is_file() and not backup.exists():
                shutil.copy2(target, backup)
                os.chmod(backup, 0o600)

        _copy_0600(Path(plan["source_cert"]), Path(plan["target_cert"]))
        _copy_0600(Path(plan["source_key"]), Path(plan["target_key"]))

        restart = run_list(["systemctl", "restart", plan["unit"]], timeout=30)
        if not restart.ok:
            raise ApplyCertError(
                f"systemctl restart {plan['unit']} не удался: "
                f"{restart.stderr.strip() or restart.stdout.strip()}. "
                f"Откат: `vds hysteria2 apply-cert --restore` "
                f"(бэкапы {plan['backup_cert']}, {plan['backup_key']})."
            )
        _set_state_cert_domain(domain, state_path)

    result["days_left"] = _days_left(Path(plan["target_cert"]))
    result["restarted"] = True
    return result


def restore_self_signed(state_path: str | None = None) -> dict:
    """Вернуть self-signed сертификат из `.bak-pre-le` (ADR-004 откат).

    Бросает ApplyCertError, если бэкапов нет (нечего восстанавливать).
    """
    domain = _read_domain(state_path)
    plan = _plan(domain)
    missing = [
        plan[key]
        for key in ("backup_cert", "backup_key")
        if not Path(plan[key]).is_file()
    ]
    if missing:
        raise ApplyCertError(
            "Бэкапы self-signed не найдены: " + ", ".join(missing)
            + " — восстанавливать нечего (сертификат, возможно, ещё не подменялся)."
        )

    with FileLock(LOCK_FILE):
        _copy_0600(Path(plan["backup_cert"]), Path(plan["target_cert"]))
        _copy_0600(Path(plan["backup_key"]), Path(plan["target_key"]))
        restart = run_list(["systemctl", "restart", plan["unit"]], timeout=30)
        if not restart.ok:
            raise ApplyCertError(
                f"systemctl restart {plan['unit']} не удался: "
                f"{restart.stderr.strip() or restart.stdout.strip()}."
            )
        _set_state_cert_domain("", state_path)

    return dict(plan, dry_run=False, restored=True)


def run_apply(apply: bool = False, restore: bool = False) -> int:
    """Точка входа `vds hysteria2 apply-cert`. 0 — успех (в т.ч. dry-run)."""
    tag = "[hysteria2]"
    if os.geteuid() != 0:
        console.print(
            f"[error]{tag} Требуется root (запустите через sudo).[/error]"
        )
        return 1

    try:
        if restore:
            info = restore_self_signed()
            console.print(
                f"[success]{tag} Self-signed сертификат восстановлен из бэкапа; "
                f"юнит {info['unit']} перезапущен.[/success]"
            )
            console.print(
                f"[info]{tag} cert: {info['target_cert']}  key: {info['target_key']}[/info]"
            )
            return 0

        info = apply_certificate(dry_run=not apply)
        if info["dry_run"]:
            console.print(
                f"[info]{tag} DRY-RUN. План подмены сертификата Hysteria2 на LE:[/info]"
            )
            console.print(
                f"[info]{tag} Источник: {info['source_cert']}[/info]\n"
                f"[info]{tag} Цели: {info['target_cert']}, {info['target_key']} (0600)[/info]\n"
                f"[info]{tag} Бэкап: {info['backup_cert']}, {info['backup_key']}[/info]\n"
                f"[info]{tag} Restart: systemctl restart {info['unit']}[/info]"
            )
            if info.get("days_left") is not None:
                console.print(
                    f"[info]{tag} Срок LE-сертификата: {info['days_left']} дн.[/info]"
                )
            console.print(
                f"[warning]{tag} Для применения выполните: "
                "`vds hysteria2 apply-cert --apply`.[/warning]"
            )
            return 0

        days = info.get("days_left")
        days_note = f", {days} дн. до истечения" if days is not None else ""
        console.print(
            f"[success]{tag} LE-сертификат применён для {info['domain']}"
            f"{days_note}; юнит {info['unit']} перезапущен.[/success]"
        )
        console.print(
            f"[info]{tag} Бэкап self-signed: {info['backup_cert']}, "
            f"{info['backup_key']} (откат: `vds hysteria2 apply-cert --restore`).[/info]"
        )
        console.print(
            f"[info]{tag} Новые клиенты теперь получат ссылку без insecure=1 "
            "(sni=<домен>); существующие insecure-ссылки продолжают работать.[/info]"
        )
        return 0
    except ApplyCertError as exc:
        console.print(f"[error]{tag} {exc}[/error]")
        return 1
