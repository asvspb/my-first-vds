"""Выдача LE-сертификата на домен (HTTP-01, certbot из apt) — SPEC WP-1, ADR-004.

Поток `vds acme issue`: root-check -> certbot установлен (apt, идемпотентно) ->
порт 80 свободен ДО любых изменений (E2) -> DNS домена резолвится в публичный IP
сервера ДО любых изменений (E1, ADR-004) -> FileLock ->
issue_certificate (certbot certonly --standalone --keep-until-expiring;
валидный сертификат на месте — skip, идемпотентно) -> install_deploy_hook
(renewal-hooks/deploy/vds-hysteria2-cert.sh, скрипт без секретов, 0755) ->
метаданные в gateway store (protocols["acme"]; email в state НЕ пишется — ADR-004).

Секретов в модуле нет: приватный материал сертификата остаётся в
/etc/letsencrypt (права certbot); hook копирует его в /etc/hysteria c 0600 —
сам подменяет WP-2 (apply_cert.py). Всё сетевое/shell — через run_list,
в тестах заменяется моками; реальная выдача выполняется только на [VDS].
"""

import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from src.core.lock import FileLock
from src.core.logger import console
from src.core.netcheck import port_free, port_owner, public_ip
from src.core.secrets import write_secret_atomic
from src.core.shell import run_list
from src.gateway.paths import (
    ACME_HOOKS_DEPLOY_DIR,
    ACME_HYSTERIA2_HOOK_NAME,
    ACME_LETSENCRYPT_LIVE,
    HYSTERIA2_CERT_PATH,
    HYSTERIA2_KEY_PATH,
    HYSTERIA2_UNIT,
)
from src.gateway.store import StoreError, load_state, save_state

LOCK_FILE = "/var/run/vds-acme.lock"

ACME_HTTP_PORT = 80  # HTTP-01 challenge; по архитектуре всегда свободен (ADR-004)
CERTBOT = "certbot"

# Имена файлов в live-каталоге (апстрим-конвенция certbot).
FULLCHAIN_NAME = "fullchain.pem"
PRIVKEY_NAME = "privkey.pem"

_HOOK_UNIT = HYSTERIA2_UNIT.removesuffix(".service")


class AcmeError(Exception):
    """Сбой выдачи/установки сертификата (apt, certbot, DNS, порт, hook)."""


# ---------------------------------------------------------------------------
# Чистые / легко мокируемые примитивы
# ---------------------------------------------------------------------------

def _normalize_ws(text: str) -> str:
    """Схлопнуть последовательности пробелов (notAfter с однозначным днём: 'Mar  1')."""
    return " ".join(text.split())


def _parse_not_after(raw: str, now: datetime | None = None) -> int:
    """Дней до истечения из строки `notAfter=Mar  1 12:00:00 2027 GMT`.

    Чистая функция; locale-независима (считаем C-локаль openssl, как в тестах).
    Отрицательное значение = сертификат истёк.
    """
    value = _normalize_ws(raw)
    if value.startswith("notAfter="):
        value = value[len("notAfter="):]
    moment = now or datetime.now(timezone.utc)
    expires = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    return (expires - moment).days


def dns_resolves_to(domain: str, ip: str) -> bool:
    """Резолвится ли домен A-записью в указанный IP (E1, ADR-004).

    Сетевой примитив (socket) — в тестах заменяется моком; при сбое
    резолва возвращаем False (консервативно, как port_free в netcheck).
    """
    try:
        resolved = socket.gethostbyname(domain)
    except OSError:
        return False
    return resolved == ip


def cert_days_left(cert_path: Path) -> int | None:
    """Дней до истечения сертификата через `openssl x509 -enddate`; None при сбое."""
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


def cert_exists(domain: str) -> bool:
    """Live-каталог certbot с fullchain на месте (сертификат уже выдавался)."""
    return (ACME_LETSENCRYPT_LIVE(domain) / FULLCHAIN_NAME).is_file()


def certbot_installed() -> bool:
    """Установлен ли certbot (exit 0 на `certbot --version`)."""
    return run_list([CERTBOT, "--version"], timeout=10).ok


# ---------------------------------------------------------------------------
# Мутирующие шаги (под FileLock, только после всех проверок)
# ---------------------------------------------------------------------------

def install_certbot() -> int:
    """Установить certbot из apt (ADR-004: нулевая github-зависимость).

    Возвращает 0 при успехе; ошибки apt — читаемое сообщение, 1.
    """
    result = run_list(["apt-get", "install", "-y", "certbot"], timeout=300)
    if not result.ok or not certbot_installed():
        console.print(
            f"[error][acme] apt-get install certbot не удался: "
            f"{result.stderr.strip() or result.stdout.strip()}[/error]"
        )
        return 1
    console.print("[success][acme] certbot установлен из apt.[/success]")
    return 0


def _certbot_issue_args(domain: str, email: str) -> list[str]:
    """Аргументы выдачи (ADR-004): standalone на :80, идемпотентно."""
    return [
        CERTBOT, "certonly", "--standalone",
        "-d", domain,
        "--non-interactive",
        "--agree-tos",
        "-m", email,
        "--keep-until-expiring",
    ]


def issue_certificate(domain: str, email: str) -> dict:
    """Выдать LE-сертификат; идемпотентно (SPEC: валиден — skip, ничего не
    перегенерировано).

    Возвращает {"cert": путь к fullchain, "days_left": int, "issued": bool};
    `issued=False` — сертификат уже был и валиден, certbot не запускался.
    Бросает AcmeError при сбое certbot.
    """
    fullchain = ACME_LETSENCRYPT_LIVE(domain) / FULLCHAIN_NAME

    if cert_exists(domain):
        days_left = cert_days_left(fullchain)
        if days_left is not None and days_left > 0:
            return {"cert": str(fullchain), "days_left": days_left, "issued": False}

    result = run_list(_certbot_issue_args(domain, email), timeout=120)
    if not result.ok or not fullchain.is_file():
        raise AcmeError(
            f"certbot не выдал сертификат для {domain}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    days_left = cert_days_left(fullchain)
    if days_left is None:
        raise AcmeError(
            f"Сертификат {fullchain} выдан, но не читается openssl (проверьте вручную)."
        )
    return {"cert": str(fullchain), "days_left": days_left, "issued": True}


def render_deploy_hook(domain: str) -> str:
    """Текст deploy-hook (ADR-004): срабатывает только при фактическом продлении.

    Секретов в hook нет (только домен и пути); приватный материал копируется
    с 0600 на месте назначения.
    """
    return (
        "#!/bin/sh\n"
        "# Автосгенерировано `vds acme issue` (ADR-004, SPEC WP-1); править руками\n"
        "# на сервере нельзя — только перегенерация командой.\n"
        "# Срабатывает certbot renew ТОЛЬКО при фактическом продлении сертификата.\n"
        "set -e\n"
        f'DOMAIN="{domain}"\n'
        f'CERT_DIR="/etc/letsencrypt/live/$DOMAIN"\n'
        f'HYS_CERT="{HYSTERIA2_CERT_PATH}"\n'
        f'HYS_KEY="{HYSTERIA2_KEY_PATH}"\n'
        f'UNIT="{HYSTERIA2_UNIT}"\n'
        "\n"
        "mkdir -p \"$(dirname \"$HYS_CERT\")\"\n"
        "# Бэкап текущих (self-signed) файлов перед подменой — путь отката WP-2.\n"
        "[ -f \"$HYS_CERT\" ] && cp -a \"$HYS_CERT\" \"$HYS_CERT.bak-pre-le\"\n"
        "[ -f \"$HYS_KEY\" ] && cp -a \"$HYS_KEY\" \"$HYS_KEY.bak-pre-le\"\n"
        "install -m 0600 \"$CERT_DIR/" + FULLCHAIN_NAME + "\" \"$HYS_CERT\"\n"
        "install -m 0600 \"$CERT_DIR/" + PRIVKEY_NAME + "\" \"$HYS_KEY\"\n"
        f"systemctl restart {_HOOK_UNIT}\n"
    )


def install_deploy_hook(domain: str) -> bool:
    """Установить deploy-hook (0755, атомарно); True при успехе.

    Уже установленный hook с тем же содержимым — перезапись идемпотентна
    (тот же текст), права выставляются заново.
    """
    hook_path = ACME_HOOKS_DEPLOY_DIR / ACME_HYSTERIA2_HOOK_NAME
    try:
        hook_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[error][acme] Не удалось создать каталог хуков: {exc}[/error]")
        return False
    if not write_secret_atomic(str(hook_path), render_deploy_hook(domain), mode=0o755):
        return False
    console.print(
        f"[success][acme] Deploy-hook установлен: {hook_path} "
        "(автопродление certbot.timer подхватит его при продлении).[/success]"
    )
    return True


def _save_state_meta(domain: str, cert_path: str, state_path: str | None) -> None:
    """Метаданные acme в gateway store (email НЕ сохраняем — ADR-004)."""
    state = load_state(state_path)
    state.protocols["acme"] = {
        "installed": True,
        "domain": domain,
        "cert_path": cert_path,
        "hook": str(ACME_HOOKS_DEPLOY_DIR / ACME_HYSTERIA2_HOOK_NAME),
    }
    save_state(state, state_path)


# ---------------------------------------------------------------------------
# Точка входа CLI
# ---------------------------------------------------------------------------

def _validate_domain(domain: str) -> bool:
    """Формат домена: одна метка не пуста, без пробелов и схем; DNS-чек отдельно."""
    if not domain or " " in domain or "/" in domain or "@" in domain:
        return False
    labels = domain.rstrip(".").split(".")
    return len(labels) >= 2 and all(labels)


def run_issue(
    domain: str,
    email: str,
    dry_run: bool = False,
    state_path: str | None = None,
) -> int:
    """Точка входа `vds acme issue`. 0 — успех (в т.ч. «уже выдан» / dry-run)."""
    tag = "[acme]"
    if os.geteuid() != 0:
        console.print(f"[error]{tag} Требуется root (запустите через sudo).[/error]")
        return 1

    if not _validate_domain(domain):
        console.print(
            f"[error]{tag} Некорректный домен: {domain!r} "
            "(ожидалось имя вида example.com).[/error]"
        )
        return 1

    # E1 (ADR-004): DNS -> публичный IP сервера, ДО любых изменений.
    ip = public_ip()
    if not ip:
        console.print(
            f"[error]{tag} Не удалось определить публичный IP (api.ipify.org) — "
            "он нужен для сверки с DNS-записью домена.[/error]"
        )
        return 1
    if not dns_resolves_to(domain, ip):
        console.print(
            f"[error]{tag} Домен {domain} не резолвится в {ip} (E1). "
            "Исправьте DNS-запись и повторите — изменения не производились.[/error]"
        )
        return 1

    # E2: порт 80 должен быть свободен ДО любых изменений.
    if not port_free(ACME_HTTP_PORT, "tcp"):
        owner = port_owner(ACME_HTTP_PORT, "tcp")
        owner_info = f" (владелец: {owner})" if owner else ""
        console.print(
            f"[error]{tag} Порт {ACME_HTTP_PORT}/tcp занят{owner_info} — HTTP-01 "
            "невозможен (E2). Освободите порт и повторите; изменения не производились.[/error]"
        )
        return 1

    already = cert_exists(domain)
    steps = [
        "1) certbot из apt (если не установлен)",
        "2) certbot certonly --standalone "
        f"-d {domain} --keep-until-expiring"
        + ("  (уже выдан и валиден — будет пропущен)" if already else ""),
        f"3) deploy-hook {ACME_HOOKS_DEPLOY_DIR / ACME_HYSTERIA2_HOOK_NAME}",
        "4) метаданные acme в gateway store",
    ]
    if dry_run:
        console.print(f"[info]{tag} DRY-RUN. План:[/info]\n" + "\n".join(steps))
        console.print(
            f"[info]{tag} Проверки пройдены: DNS {domain} -> {ip}, "
            f"порт {ACME_HTTP_PORT}/tcp свободен. Изменений не выполнено.[/info]"
        )
        return 0

    if not certbot_installed():
        if install_certbot() != 0:
            return 1

    with FileLock(LOCK_FILE):
        try:
            info = issue_certificate(domain, email)
        except AcmeError as exc:
            console.print(f"[error]{tag} {exc}[/error]")
            return 1

        if not info["issued"]:
            console.print(
                f"[success]{tag} Сертификат уже есть и валиден "
                f"({info['days_left']} дн.) — перегенерация не требуется.[/success]"
            )
        else:
            console.print(
                f"[success]{tag} Сертификат выдан: {info['cert']} "
                f"({info['days_left']} дн. до истечения).[/success]"
            )

        if not install_deploy_hook(domain):
            console.print(
                f"[error]{tag} Не удалось записать deploy-hook "
                f"{ACME_HOOKS_DEPLOY_DIR / ACME_HYSTERIA2_HOOK_NAME}.[/error]"
            )
            return 1

        try:
            _save_state_meta(domain, info["cert"], state_path)
        except (StoreError, OSError) as exc:
            console.print(f"[error]{tag} Не удалось сохранить состояние: {exc}[/error]")
            return 1

    console.print(
        f"[info]{tag} Продление — штатный certbot.timer; подмена сертификата "
        "Hysteria2: `vds hysteria2 apply-cert --apply` (WP-2).[/info]"
    )
    return 0
