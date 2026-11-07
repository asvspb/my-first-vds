"""Рендер и применение sysctl-тюнинга gateway (CENSORSHIP-ROADMAP, фаза 2).

Шаблон `systemd/sysctl/99-vds-gateway.conf.tpl` (BBR + fq, rmem_max/wmem_max
для QUIC) рендерится как есть и пишется в /etc/sysctl.d/99-vds-gateway.conf
(ADR-002), затем применяется `sysctl -p <file>`.

Идемпотентен: повторный вызов перезаписывает файл тем же содержимым и
повторно применяет. Откат при `hysteria2 remove` НЕ выполняется (ADR-002/OQ-2).
"""

from pathlib import Path

from src.core.logger import console
from src.core.shell import run_list
from src.core.units import SYSTEMD_DIR
from src.gateway.paths import SYSCTL_CONF_PATH

SYSCTL_TEMPLATE = "sysctl/99-vds-gateway.conf.tpl"


def render_sysctl() -> str:
    """Содержимое 99-vds-gateway.conf из шаблона (детерминировано)."""
    tpl = SYSTEMD_DIR / SYSCTL_TEMPLATE
    if not tpl.is_file():
        raise FileNotFoundError(f"Шаблон sysctl не найден: {tpl}")
    return tpl.read_text(encoding="utf-8")


def apply_sysctl(conf_path: Path = SYSCTL_CONF_PATH) -> bool:
    """Записать /etc/sysctl.d/99-vds-gateway.conf и применить (`sysctl -p`).

    Файл — публичная конфигурация ядра (0644), не секрет. True — успех,
    False — ошибка (значением).
    """
    try:
        rendered = render_sysctl()
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(rendered, encoding="utf-8")
        conf_path.chmod(0o644)
    except OSError as exc:
        console.print(f"[error][hysteria2] Не удалось записать {conf_path}: {exc}[/error]")
        return False

    result = run_list(["sysctl", "-p", str(conf_path)], timeout=15)
    if not result.ok:
        console.print(
            f"[error][hysteria2] sysctl -p {conf_path} не удался: "
            f"{result.stderr.strip()}[/error]"
        )
        return False
    console.print(f"[change]sysctl-тюнинг применён: {conf_path}[/change]")
    return True
