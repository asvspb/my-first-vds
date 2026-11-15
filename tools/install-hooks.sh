#!/usr/bin/env bash
# install-hooks.sh — установка dev-хуков docsync (SPEC-20261116-doc-sync, WP-4).
#
# Идемпотентно: повторный запуск безопасен (просто переустанавливает config).
# Откат: git config --unset core.hooksPath
# Хуки: .githooks/commit-msg (sync-проверка индекса) и .githooks/pre-push
# (audit диапазона origin/main..HEAD). Режим warn/block — поле "mode" в
# docs/doc-sync.json; переход в block — только правкой реестра (коммит).
set -euo pipefail

toplevel="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "error: запустите из git-репозитория vds" >&2
    exit 1
}
cd "$toplevel"

# core.hooksPath доступен с git 2.9
gv="$(git version | awk '{print $3}')"
maj="${gv%%.*}"
rest="${gv#*.}"
min="${rest%%.*}"
if [ "$maj" -lt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -lt 9 ]; }; then
    echo "error: требуется git >= 2.9 (core.hooksPath), найдено: $gv" >&2
    echo "откат не требуется: конфиг не менялся" >&2
    exit 1
fi

for hook in .githooks/commit-msg .githooks/pre-push; do
    if [ ! -f "$hook" ]; then
        echo "error: $hook не найден в репозитории" >&2
        exit 1
    fi
    chmod +x "$hook"
done

prev="$(git config --get core.hooksPath || true)"
git config core.hooksPath .githooks

if [ "$prev" = ".githooks" ]; then
    echo "[docsync] hooks уже установлены (core.hooksPath=.githooks) — повтор идемпотентен"
elif [ -n "$prev" ]; then
    echo "[docsync] core.hooksPath: '$prev' -> '.githooks' (перезаписан)"
else
    echo "[docsync] hooks установлены: core.hooksPath=.githooks"
fi
echo "[docsync] проверка: python3 tools/docsync.py check --staged"
echo "[docsync] откат:   git config --unset core.hooksPath"
