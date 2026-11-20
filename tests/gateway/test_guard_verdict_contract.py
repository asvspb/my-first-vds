"""Контракт schema_hash между клиентом (ubuntuInstaller) и сервером (DECISION Q1/D-17).

Источник правды — клиент. Сервер вендорит только lock-файл хэшей
(``docs/contracts/guard-schema-hashes.json``), тела схем не копируются:
копии гарантировали бы тихий дрейф, а сеть в тестах запрещена (AGENTS §6).

Три проверки:
1. Структура lock-файла: 7 контрактов, формат ``sha256:<64 hex>``, источник.
2. Вывод ``vds gateway probe-watch watch --json`` покрывает поля, которые
   клиент читает в ``guard.server_verdict/1`` (``stage`` — опциональное поле,
   его отсутствие не должно ломать).
3. Если задан ``VPN_MANAGER_REPO`` — сверка вендорированных хэшей с живыми
   схемами соседнего чекаута 1-в-1 (офлайн, через subprocess; без переменной — skip).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPO_ROOT / "docs" / "contracts" / "guard-schema-hashes.json"

EXPECTED_IDS = {
    "guard.config/1",
    "guard.coverage/1",
    "guard.event/1",
    "guard.finding/1",
    "guard.incident/1",
    "guard.server_verdict/1",
    "guard.status/1",
}

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def load_lock() -> dict:
    with LOCK_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_lock_file_structure() -> None:
    lock = load_lock()
    assert lock["contract"] == "vpn-guard-schema-hashes/1"
    assert lock["source_repo"] == "ubuntuInstaller"
    assert lock["source_path"] == "scripts/vpn-manager/vpnm/guard/schemas"
    assert re.fullmatch(r"[0-9a-f]{40}", lock["source_commit"]), lock["source_commit"]
    hashes = lock["hashes"]
    assert set(hashes) == EXPECTED_IDS, sorted(set(hashes) ^ EXPECTED_IDS)
    for schema_id, value in hashes.items():
        assert SHA256_RE.match(value), f"{schema_id}: {value}"


def _watch_payload() -> dict:
    """JSON-контракт probe-watch (без nft/root: собираем отчёт напрямую)."""
    from src.gateway.probing import (  # локальный импорт — CLI не тянет тяжёлое
        Delta,
        ThreatState,
        Verdict,
        WatchReport,
    )

    report = WatchReport(
        now="2026-11-20T00:00:00",
        window="1h",
        delta=Delta(
            syn_bare=0,
            syn_valid=0,
            udp_443=0,
            bare_no_payload=0,
            ratio_no_payload=None,
            unique_probers=0,
        ),
        verdict=Verdict(name="quiet", reasons=[]),
        threshold=100,
        per_element_counters=True,
        geo_source="ru-cidrs",
        threat=ThreatState(level="quiet", reason="", since="", updated=""),
        lockdown={"active": False, "ttl_until": ""},
    )
    return report.to_json()


def test_probe_watch_json_covers_client_contract() -> None:
    payload = _watch_payload()

    # Поля, которые клиентский `vpn guard sync` переносит в guard.server_verdict/1.
    assert isinstance(payload["window"], str)
    assert isinstance(payload["verdict"], str)
    assert isinstance(payload["reasons"], list)
    assert all(isinstance(r, str) for r in payload["reasons"])
    assert payload["threat_level"] in {"quiet", "elevated", "high", None}
    assert payload["threat_reason"] is None or isinstance(payload["threat_reason"], str)

    lockdown = payload["lockdown"]
    assert isinstance(lockdown, dict)
    assert isinstance(lockdown["active"], bool)
    assert isinstance(lockdown["ttl_until"], str)

    # `stage` — опциональное расширение клиентской схемы: отсутствие допустимо,
    # а появление не должно требовать правок серверной стороны.
    assert "stage" not in payload or isinstance(payload["stage"], str)


def test_hashes_match_neighbour_checkout() -> None:
    """Сверка с живым клиентом (офлайн). Без VPN_MANAGER_REPO — skip."""
    repo = os.environ.get("VPN_MANAGER_REPO")
    if not repo:
        pytest.skip("VPN_MANAGER_REPO не задан — сверка с клиентом пропущена")
    client_root = Path(repo) / "scripts" / "vpn-manager"
    if not client_root.is_dir():
        pytest.fail(f"VPN_MANAGER_REPO={repo}: нет {client_root}")

    proc = subprocess.run(
        [sys.executable, "-c",
         "import json; from vpnm.guard import schema; "
         "print(json.dumps(schema.schema_hashes(), sort_keys=True))"],
        cwd=str(client_root),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    live = json.loads(proc.stdout)
    vendored = load_lock()["hashes"]
    assert live == vendored, {
        "только_клиент": {k: v for k, v in live.items() if vendored.get(k) != v},
        "только_сервер": {k: v for k, v in vendored.items() if live.get(k) != v},
    }
