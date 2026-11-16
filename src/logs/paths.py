"""Единая точка путей и имён модуля log-forensics (SPEC-20261116-log-forensics,
ADR-012).

Пути и имена systemd-юнитов фиксируются здесь и только здесь; смена — только
через новый ADR. Все постоянные артефакты живут в /var/lib/vds (telemetry,
forensics) и /etc/vds-forensics (правила, HMAC-ключ); в git они не попадают
(см. .gitignore, ADR-012 «Красные флаги»).

INSTALL_DIR-осознанность — по конвенции gateway/paths.py: репозиторий
определяется от расположения модуля, корень установки — из окружения
(INSTALL_DIR: /opt/my-vds или /opt/ztnet).
"""
import os
from pathlib import Path

# Корень установки (AGENTS.md §5.9): /opt/my-vds или /opt/ztnet из окружения.
INSTALL_DIR = Path(os.environ.get("INSTALL_DIR", "/opt/my-vds"))

# Репозиторий проекта (для systemd-шаблонов core.units.SYSTEMD_DIR не нужен,
# но модульная версия/контекст рендера — отсюда).
REPO_DIR = Path(__file__).resolve().parents[2]

# --- Телеметрия (сэмплы 5-мин, NDJSON, TTL 7 дней) -------------------------
TELEMETRY_DIR = Path("/var/lib/vds/telemetry")

# --- Форензика (baseline, бандлы, отчёты, captures) -------------------------
FORENSICS_DIR = Path("/var/lib/vds/forensics")
CAPTURES_DIR = FORENSICS_DIR / "captures"
BUNDLES_DIR = FORENSICS_DIR / "bundles"
REPORTS_DIR = FORENSICS_DIR / "reports"

# --- Конфиги/секреты модуля (0600, вне git) --------------------------------
RULES_FILE = Path("/etc/vds-forensics/rules.json")
HMAC_KEY_FILE = Path("/etc/vds-forensics/hmac.key")

# --- Снапшот probe-watch (read-only потребление — M1 SPEC) ------------------
# Вердикты — source of truth probe-watch; collect/logs ТОЛЬКО читают снапшот
# и считают дельту in-process чистой compute_delta (НЕ вызывая watch).
SNAPSHOT_FILE = Path("/var/lib/vds/probe-watch.json")

# --- nft-таблица монитора (владелец — gateway/probing; только потребляем) ---
NFT_TABLE = "vds_probe"

# --- Блокировки мутирующих операций модуля (core.lock.FileLock) ------------
LOCK_FILE = "/var/run/vds-logs.lock"
CAPTURE_LOCK_FILE = "/var/run/vds-logs-capture.lock"

# --- systemd-юниты (шаблоны systemd/*.tpl, установка core.units) -----------
SAMPLE_UNIT = "vds-logs-sample.service"
SAMPLE_TIMER = "vds-logs-sample.timer"
DAILY_UNIT = "vds-logs-daily.service"
DAILY_TIMER = "vds-logs-daily.timer"

SAMPLE_SERVICE_TEMPLATE = "vds-logs-sample.service.tpl"
SAMPLE_TIMER_TEMPLATE = "vds-logs-sample.timer.tpl"
DAILY_SERVICE_TEMPLATE = "vds-logs-daily.service.tpl"
DAILY_TIMER_TEMPLATE = "vds-logs-daily.timer.tpl"

# Undo-журнал install (паттерн ufw-модуля: remove снимает ровно то,
# что install поставил).
INSTALL_STATE_FILE = FORENSICS_DIR / "install-state.json"

# --- Лимиты (SPEC §5.4/§6.3/§11, OQ-3) --------------------------------------
SAMPLE_TTL_DAYS = 7           # ротация telemetry
REPORT_TTL_DAYS = 90
CAPTURE_TTL_DAYS = 7          # bounded-pcap metadata-only
DISK_CAP_PCT = 90             # disk_pct выше — сэмплер отказывается писать
MAX_JOURNAL_LINES = 200_000   # строк/источник (collect bundle)
SAMPLE_WINDOW_MINUTES = 5     # каденция сэмплера

# Пороги T-08 (SPEC §7.5, ревью G2: <209/>214 давали 100% FP на PQ-Kyber).
PCAP_CH_MIN_LEN = 180         # нормальный ClientHello 517–1300 Б


def samples_path_for(day=None) -> Path:
    """NDJSON-файл сэмплов за день: samples-YYYYMMDD.ndjson (ADR-012 §артефакты)."""
    from datetime import date

    d = day or date.today()
    return TELEMETRY_DIR / f"samples-{d.strftime('%Y%m%d')}.ndjson"
