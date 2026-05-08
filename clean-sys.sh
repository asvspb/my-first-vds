#!/usr/bin/env bash
# Version: 1.0
set -euo pipefail

# ============================================================================
# clean-sys.sh — Системная очистка Ubuntu-сервера
# Аналог desktop-версии, адаптированный для серверного окружения.
# Без GUI, snap, flatpak, браузеров.
# Основной фокус: apt, Docker, journalctl, логи, /tmp, старые ядра, pip/npm.
# ============================================================================

# Определяем реальный HOME пользователя (даже при запуске через sudo/root)
_real_home() {
  if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
    eval echo "~${SUDO_USER}"
  elif [ -n "${SUDO_USER:-}" ]; then
    eval echo "~${SUDO_USER}"
  else
    echo "$HOME"
  fi
}
HOME="$(_real_home)"
export HOME

# ──────────────────────────────────────────────
# Конфигурация (можно переопределить через env)
# ──────────────────────────────────────────────
LOG_PREFIX="[sys-clean]"
DRY_RUN="${DRY_RUN:-0}"

# --- APT ---
APT_CLEAN="${APT_CLEAN:-1}"
APT_AUTOCLEAN="${APT_AUTOCLEAN:-1}"
APT_AUTOREMOVE="${APT_AUTOREMOVE:-1}"
APT_PURGE_ORPHANS="${APT_PURGE_ORPHANS:-1}"          # deborphan / aptitude purge ~o

# --- Старые ядра ---
CLEAN_OLD_KERNELS="${CLEAN_OLD_KERNELS:-1}"           # удалить неиспользуемые ядра (кроме текущего)

# --- Journalctl ---
JOURNALCTL_VACUUM="${JOURNALCTL_VACUUM:-1}"
JOURNALCTL_VACUUM_SIZE="${JOURNALCTL_VACUUM_SIZE:-200M}"

# --- Логи ---
CLEAN_OLD_LOG_GZ="${CLEAN_OLD_LOG_GZ:-1}"             # удалить *.gz в /var/log старше N дней
LOG_GZ_RETENTION_DAYS="${LOG_GZ_RETENTION_DAYS:-7}"
CLEAN_VAR_LOG_OLD="${CLEAN_VAR_LOG_OLD:-1}"           # удалить файлы /var/log/*.log старше N дней (кроме active logs)
VAR_LOG_RETENTION_DAYS="${VAR_LOG_RETENTION_DAYS:-30}"
CLEAN_ROTATED_LOGS="${CLEAN_ROTATED_LOGS:-1}"         # удалить старые rotated логи (*.1, *.old, log.X.gz)

# --- Fail2ban ---
CLEAN_FAIL2BAN_LOGS="${CLEAN_FAIL2BAN_LOGS:-1}"       # очистить persistent bans / логи fail2ban

# --- /tmp и /var/tmp ---
CLEAN_TMP="${CLEAN_TMP:-1}"
TMP_MAX_AGE_DAYS="${TMP_MAX_AGE_DAYS:-7}"
CLEAN_VARTMP="${CLEAN_VARTMP:-1}"
VARTMP_MAX_AGE_DAYS="${VARTMP_MAX_AGE_DAYS:-7}"

# --- Docker ---
DOCKER_PRUNE="${DOCKER_PRUNE:-1}"                     # total docker system prune (агрессивно)
DOCKER_PRUNE_VOLUMES="${DOCKER_PRUNE_VOLUMES:-0}"     # удалять volumes (осторожно!)
DOCKER_SAFE_PRUNE="${DOCKER_SAFE_PRUNE:-1}"           # щадящая чистка: контейнеры >48h, образы >7d, builder >7d
DOCKER_PRUNE_CONTAINERS_UNTIL="${DOCKER_PRUNE_CONTAINERS_UNTIL:-48h}"
DOCKER_PRUNE_IMAGES_UNTIL="${DOCKER_PRUNE_IMAGES_UNTIL:-168h}"    # 7 days
DOCKER_PRUNE_BUILDER_UNTIL="${DOCKER_PRUNE_BUILDER_UNTIL:-168h}"
DOCKER_DEEP_PRUNE="${DOCKER_DEEP_PRUNE:-0}"           # агрессивный prune с --volumes и фильтром
DOCKER_DEEP_PRUNE_UNTIL="${DOCKER_DEEP_PRUNE_UNTIL:-336h}"       # 14 days

DOCKER_CLEANUP_UNTAGGED="${DOCKER_CLEANUP_UNTAGGED:-1}"           # docker image prune -a (untagged/dangling)
DOCKER_REMOVE_DANGLING_VOLUMES="${DOCKER_REMOVE_DANGLING_VOLUMES:-0}"

# --- Docker Build Cache (BuildKit) ---
CLEAN_DOCKER_BUILDX="${CLEAN_DOCKER_BUILDX:-1}"      # docker buildx prune

# --- pip / npm / uv ---
PIP_PURGE="${PIP_PURGE:-1}"
NPM_CACHE_CLEAN="${NPM_CACHE_CLEAN:-0}"
CLEAN_NPM_CACHE_DIR="${CLEAN_NPM_CACHE_DIR:-0}"
UV_CLEAN="${UV_CLEAN:-0}"
POETRY_CACHE_CLEAN="${POETRY_CACHE_CLEAN:-0}"
YARN_CACHE_CLEAN="${YARN_CACHE_CLEAN:-0}"
CARGO_CACHE_CLEAN="${CARGO_CACHE_CLEAN:-0}"

# --- /var/cache ---
CLEAN_VAR_CACHE="${CLEAN_VAR_CACHE:-1}"               # /var/cache/apt/archives/*.deb (кроме partial/)
CLEAN_VAR_CACHE_OTHER="${CLEAN_VAR_CACHE_OTHER:-0}"   # /var/cache/* кроме apt (опа!)

# --- /var/crash ---
CLEAN_VAR_CRASH="${CLEAN_VAR_CRASH:-1}"

# --- /var/mail / /var/spool ---
CLEAN_VAR_MAIL="${CLEAN_VAR_MAIL:-1}"                  # очистить почту пользователей (если не используется)
CLEAN_VAR_SPOOL_LPD="${CLEAN_VAR_SPOOL_LPD:-0}"        # очистить spool принтера (обычно не нужно на сервере)

# --- /var/lib/dpkg/info ---
CLEAN_DPKG_INFO_EXTRAS="${CLEAN_DPKG_INFO_EXTRAS:-0}"  # удалить .list, .md5sums, .postinst и т.д. для удалённых пакетов

# --- /home/*/.cache (чужие пользователи) ---
CLEAN_OTHER_USERS_CACHE="${CLEAN_OTHER_USERS_CACHE:-0}" # по умолчанию отключено — может быть небезопасно

# --- SSH ---
CLEAN_SSH_KNOWN_HOSTS="${CLEAN_SSH_KNOWN_HOSTS:-0}"     # удалить невалидные/старые записи из known_hosts

# --- Systemd ---
CLEAN_SYSTEMD_JOURNAL_DUPLICATES="${CLEAN_SYSTEMD_JOURNAL_DUPLICATES:-0}"  # journalctl --rotate --vacuum-time (доп.)

# --- MySQL/MariaDB ---
MYSQL_LOG_CLEAN="${MYSQL_LOG_CLEAN:-0}"                 # очистить логи MySQL (slow.log, error.log старше N дней)
MYSQL_LOG_DAYS="${MYSQL_LOG_DAYS:-30}"

# --- PostgreSQL ---
PG_LOG_CLEAN="${PG_LOG_CLEAN:-0}"

# --- Nginx/Apache ---
NGINX_LOG_CLEAN="${NGINX_LOG_CLEAN:-0}"
NGINX_LOG_DIR="${NGINX_LOG_DIR:-/var/log/nginx}"
NGINX_LOG_DAYS="${NGINX_LOG_DAYS:-30}"
APACHE_LOG_CLEAN="${APACHE_LOG_CLEAN:-0}"
APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
APACHE_LOG_DAYS="${APACHE_LOG_DAYS:-30}"

# --- Redis ---
REDIS_LOG_CLEAN="${REDIS_LOG_CLEAN:-0}"

# --- Docker volumes orphaned ---
DOCKER_ORPHAN_VOLUMES="${DOCKER_ORPHAN_VOLUMES:-0}"    # docker volume ls -qf dangling=true

# --- Docker networks ---
DOCKER_NETWORK_CLEAN="${DOCKER_NETWORK_CLEAN:-0}"      # docker network prune

# --- Дополнительно ---
REMOVE_OLD_CONTAINER_IMAGES="${REMOVE_OLD_CONTAINER_IMAGES:-0}"  # удалить образы старше 30 дней (кроме используемых)
CLEAN_SNAP="${CLEAN_SNAP:-0}"                            # если вдруг snap установлен на сервере
FLATPAK_UNUSED="${FLATPAK_UNUSED:-0}"                    # flatpak — редкость на сервере
CLEAN_TIMESHIFT="${CLEAN_TIMESHIFT:-0}"                   # timeshift — почти никогда на сервере
EMPTY_TRASH="${EMPTY_TRASH:-1}"                           # очистить корзину
ALLOW_RM="${ALLOW_RM:-0}"                                 # если нет gio — принудительно rm вместо пропуска

# ════════════════════════════════════════════
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ════════════════════════════════════════════

log() { printf '%s %s %s\n' "$(date '+%F %T')" "$LOG_PREFIX" "$*"; }
size_of() { du -sh "$1" 2>/dev/null | awk '{print $1}'; }

human() { numfmt --to=iec --suffix=B 2>/dev/null; }
free_bytes() { df -B1 --output=avail / 2>/dev/null | tail -1 | tr -d ' '; }

# Лок-файл
LOCKFILE="/tmp/.sys-clean.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
  log "Уже запущено — выхожу"
  exit 0
fi

trash_or_rm() {
  local p="$1"
  [ -e "$p" ] || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: удалил бы: $p"
    return 0
  fi
  if command -v gio >/dev/null 2>&1; then
    gio trash "$p" || log "warn: не удалось переместить в корзину: $p"
  else
    if [ "$ALLOW_RM" = "1" ]; then
      rm -rf -- "$p" || true
    else
      log "skip: нет gio (корзина), ALLOW_RM!=1, пропускаю $p"
    fi
  fi
}

empty_trash() {
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: очистил бы корзину"
    return 0
  fi
  if command -v gio >/dev/null 2>&1; then
    gio trash --empty || true
  else
    log "skip: нет gio для очистки корзины"
  fi
}

# Проверка на sudo (не root)
check_sudo() {
  if ! sudo -n true 2>/dev/null; then
    log "skip: требуется sudo (без пароля) для этой операции"
    return 1
  fi
  return 0
}

# ════════════════════════════════════════════
# МОДУЛИ ОЧИСТКИ
# ════════════════════════════════════════════

# --- 1. APT ---
apt_maintenance() {
  [ "$APT_CLEAN" = "1" ] || [ "$APT_AUTOCLEAN" = "1" ] || [ "$APT_AUTOREMOVE" = "1" ] || [ "$APT_PURGE_ORPHANS" = "1" ] || return 0
  check_sudo || return 0

  if [ "$DRY_RUN" = "1" ]; then
    [ "$APT_CLEAN" = "1" ] && log "DRY-RUN: sudo apt clean"
    [ "$APT_AUTOCLEAN" = "1" ] && log "DRY-RUN: sudo apt autoclean"
    [ "$APT_AUTOREMOVE" = "1" ] && log "DRY-RUN: sudo apt autoremove --purge -y"
    [ "$APT_PURGE_ORPHANS" = "1" ] && log "DRY-RUN: sudo apt purge \$(deborphan | tr '\\n' ' ') 2>/dev/null"
  else
    [ "$APT_CLEAN" = "1" ] && { log "apt clean"; sudo apt clean || true; }
    [ "$APT_AUTOCLEAN" = "1" ] && { log "apt autoclean"; sudo apt autoclean || true; }
    [ "$APT_AUTOREMOVE" = "1" ] && { log "apt autoremove --purge"; sudo apt autoremove --purge -y || true; }
    if [ "$APT_PURGE_ORPHANS" = "1" ]; then
      if command -v deborphan >/dev/null 2>&1; then
        local orphans
        orphans=$(deborphan 2>/dev/null | tr '\n' ' ' || true)
        [ -n "$orphans" ] && { log "deborphan: purge $orphans"; sudo apt purge -y $orphans || true; } \
                          || log "deborphan: сирот не найдено"
      else
        log "skip: deborphan не установлен (apt install deborphan для этой функции)"
        # Альтернатива: aptitude purge ~o
        if command -v aptitude >/dev/null 2>&1; then
          log "aptitude: purge ~o (orphaned)"
          sudo aptitude purge ~o -y || true
        fi
      fi
    fi
  fi
}

# --- 2. Старые ядра ---
clean_old_kernels() {
  [ "$CLEAN_OLD_KERNELS" = "1" ] || return 0
  check_sudo || return 0

  local current_kernel
  current_kernel=$(uname -r | sed 's/-[a-z]*$//')
  log "Текущее ядро: $current_kernel"

  # Для Ubuntu — через apt
  # Получаем список установленных образов ядер
  local installed_kernels
  installed_kernels=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | sort -V || true)
  [ -z "$installed_kernels" ] && { log "Ядра не найдены (странно)"; return 0; }

  local removed=0
  for pkg in $installed_kernels; do
    # Пропускаем мета-пакеты
    case "$pkg" in
      linux-image-generic|linux-image-extra-virtual|linux-image-virtual|linux-image-aws|linux-image-azure|linux-image-gcp) continue ;;
    esac
    # Проверяем, совпадает ли версия с текущим ядром
    local ver
    ver=$(echo "$pkg" | sed 's/^linux-image-//; s/-generic$//; s/-extra$//; s/-virtual$//; s/-aws$//; s/-azure$//; s/-gcp$//; s/-lowlatency$//; s/-kvm$//; s/-oem$//')
    if [ "$ver" != "$current_kernel" ] && echo "$installed_kernels" | grep -q "$pkg"; then
      if [ "$DRY_RUN" = "1" ]; then
        log "DRY-RUN: sudo apt purge -y $pkg"
      else
        log "Удаление старого ядра: $pkg"
        sudo apt purge -y "$pkg" || log "warn: не удалось удалить $pkg"
        removed=1
      fi
    fi
  done

  if [ "$removed" = "1" ] && [ "$DRY_RUN" != "1" ]; then
    # Запускаем autoremove после удаления ядер
    sudo apt autoremove --purge -y || true
    sudo apt clean || true
  fi
  [ "$removed" = "0" ] && log "Старых ядер не найдено"
}

# --- 3. Journalctl ---
vacuum_journal() {
  [ "$JOURNALCTL_VACUUM" = "1" ] || return 0
  check_sudo || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: sudo journalctl --vacuum-size=$JOURNALCTL_VACUUM_SIZE"
  else
    log "journalctl vacuum до $JOURNALCTL_VACUUM_SIZE"
    sudo journalctl --vacuum-size="$JOURNALCTL_VACUUM_SIZE" || log "warn: journalctl vacuum не удался"
  fi
}

# --- 4. Старые .gz логи в /var/log ---
clean_old_log_gz() {
  [ "$CLEAN_OLD_LOG_GZ" = "1" ] || return 0
  check_sudo || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: sudo find /var/log -type f -name '*.gz' -mtime +$LOG_GZ_RETENTION_DAYS -delete"
  else
    log "Удаление *.gz логов старше $LOG_GZ_RETENTION_DAYS дней"
    sudo find /var/log -type f -name '*.gz' -mtime +"$LOG_GZ_RETENTION_DAYS" -delete || true
  fi
}

# --- 5. Старые .log файлы в /var/log ---
clean_var_log_old() {
  [ "$CLEAN_VAR_LOG_OLD" = "1" ] || return 0
  check_sudo || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: sudo find /var/log -maxdepth 1 -type f -name '*.log' -mtime +$VAR_LOG_RETENTION_DAYS -delete"
  else
    log "Удаление *.log в /var/log старше $VAR_LOG_RETENTION_DAYS дней"
    sudo find /var/log -maxdepth 1 -type f -name '*.log' -mtime +"$VAR_LOG_RETENTION_DAYS" -delete || true
  fi
}

# --- 6. Ротированные логи (*.1, *.old, *.log.X.gz) ---
clean_rotated_logs() {
  [ "$CLEAN_ROTATED_LOGS" = "1" ] || return 0
  check_sudo || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: поиск ротированных логов (mtime +30) в /var/log"
  else
    log "Удаление старых ротированных логов в /var/log"
    # *.1, *.old, *.2.gz, *.3.gz и т.д.
    sudo find /var/log -type f \( -name '*.1' -o -name '*.old' -o -name '*.2.gz' -o -name '*.3.gz' -o -name '*.4.gz' -o -name '*.5.gz' -o -name '*.6.gz' -o -name '*.7.gz' \) -mtime +30 -delete 2>/dev/null || true
    sudo find /var/log -type f -regextype posix-extended -regex '.*\.[0-9]+$' -mtime +30 -delete 2>/dev/null || true
  fi
}

# --- 7. Fail2ban ---
clean_fail2ban_logs() {
  [ "$CLEAN_FAIL2BAN_LOGS" = "1" ] || return 0
  check_sudo || return 0

  # Очистка persistent bans (файлы бан-базы fail2ban)
  local f2b_db="/var/lib/fail2ban/fail2ban.sqlite3"
  [ -f "$f2b_db" ] || { log "skip: нет fail2ban БД"; return 0; }

  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: очистка persistent bans из fail2ban (age > 30 дней)"
  else
    log "Очистка fail2ban bans старше 30 дней"
    # Очищаем записи старше 30 дней
    sudo sqlite3 "$f2b_db" "DELETE FROM bips WHERE updated < strftime('%s', 'now', '-30 days');" 2>/dev/null || log "warn: не удалось очистить fail2ban bans"
    sudo sqlite3 "$f2b_db" "VACUUM;" 2>/dev/null || true
  fi

  # Очистка логов fail2ban
  local f2b_log="/var/log/fail2ban.log"
  [ -f "$f2b_log" ] || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: truncate $f2b_log"
  else
    log "Truncate $f2b_log"
    sudo truncate -s 0 "$f2b_log" || log "warn: не удалось truncate fail2ban.log"
  fi
}

# --- 8. /tmp и /var/tmp ---
cleanup_tmp_path() {
  local path="$1" days="$2"
  if [ "$DRY_RUN" = "1" ]; then
    if check_sudo 2>/dev/null; then
      log "DRY-RUN: sudo find $path -xdev -type f -mtime +$days -delete"
    else
      log "DRY-RUN: find $path -xdev -type f -user $(id -u) -mtime +$days -delete"
    fi
    return 0
  fi
  if check_sudo 2>/dev/null; then
    sudo find "$path" -xdev -type f -mtime +"$days" -delete 2>/dev/null || true
    sudo find "$path" -xdev -type d -empty -delete 2>/dev/null || true
  else
    find "$path" -xdev -type f -user "$(id -u)" -mtime +"$days" -delete 2>/dev/null || true
    find "$path" -xdev -type d -user "$(id -u)" -empty -delete 2>/dev/null || true
  fi
}

clean_tmp_all()   { [ "$CLEAN_TMP" = "1" ] && { log "Очистка /tmp (старше $TMP_MAX_AGE_DAYS дней)"; cleanup_tmp_path "/tmp" "$TMP_MAX_AGE_DAYS"; } }
clean_vartmp_all(){ [ "$CLEAN_VARTMP" = "1" ] && { log "Очистка /var/tmp (старше $VARTMP_MAX_AGE_DAYS дней)"; cleanup_tmp_path "/var/tmp" "$VARTMP_MAX_AGE_DAYS"; } }

# --- 9. Docker ---
docker_prune_safe() {
  [ "$DOCKER_SAFE_PRUNE" = "1" ] || return 0
  command -v docker >/dev/null 2>&1 || { log "skip: docker не найден (safe prune)"; return 0; }

  local cont_until="$DOCKER_PRUNE_CONTAINERS_UNTIL"
  local img_until="$DOCKER_PRUNE_IMAGES_UNTIL"
  local builder_until="$DOCKER_PRUNE_BUILDER_UNTIL"

  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: docker container prune -f --filter until=${cont_until}"
    log "DRY-RUN: docker image prune -f"
    log "DRY-RUN: docker builder prune -af --filter until=${builder_until}"
  else
    log "Docker safe prune (containers >$cont_until, images >$img_until, builder >$builder_until)"
    docker container prune -f --filter "until=${cont_until}" 2>/dev/null || log "warn: container prune"
    docker image prune -f 2>/dev/null || log "warn: image prune"
    docker builder prune -af --filter "until=${builder_until}" 2>/dev/null || log "warn: builder prune"
  fi

  if [ "$DOCKER_DEEP_PRUNE" = "1" ]; then
    local deep_until="$DOCKER_DEEP_PRUNE_UNTIL"
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: docker system prune -af --volumes --filter until=${deep_until}"
    else
      log "Docker deep prune (--volumes, until=${deep_until})"
      docker system prune -af --volumes --filter "until=${deep_until}" 2>/dev/null || log "warn: deep prune"
    fi
  fi

  # Untagged images
  if [ "$DOCKER_CLEANUP_UNTAGGED" = "1" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: docker image prune -af"
    else
      log "Docker: удаление untagged/dangling образов"
      docker image prune -af 2>/dev/null || true
    fi
  fi

  [ "$DOCKER_NETWORK_CLEAN" = "1" ] && { [ "$DRY_RUN" = "1" ] && log "DRY-RUN: docker network prune -f" || docker network prune -f 2>/dev/null || true; }
}

docker_prune() {
  [ "$DOCKER_PRUNE" = "1" ] || return 0
  command -v docker >/dev/null 2>&1 || { log "skip: docker не найден"; return 0; }

  local vols=""
  [ "$DOCKER_PRUNE_VOLUMES" = "1" ] && vols=" --volumes"
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: docker system prune -af${vols}"
  else
    log "Docker system prune -af${vols}"
    docker system prune -af${vols} 2>/dev/null || log "warn: docker system prune"
  fi
}

docker_orphan_volumes() {
  [ "$DOCKER_ORPHAN_VOLUMES" = "1" ] || return 0
  command -v docker >/dev/null 2>&1 || { log "skip: docker не найден"; return 0; }
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: docker volume ls -qf dangling=true | xargs -r docker volume rm"
  else
    log "Docker: удаление orphan volumes (dangling)"
    docker volume ls -qf dangling=true 2>/dev/null | xargs -r docker volume rm 2>/dev/null || log "warn: volume rm"
  fi
}

docker_prune_buildx() {
  [ "$CLEAN_DOCKER_BUILDX" = "1" ] || return 0
  command -v docker >/dev/null 2>&1 || { log "skip: docker не найден"; return 0; }
  if ! docker buildx version >/dev/null 2>&1; then
    log "skip: buildx не доступен"
    return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: docker buildx prune -af"
  else
    log "Docker buildx prune"
    docker buildx prune -af 2>/dev/null || log "warn: buildx prune"
  fi
}

# --- 10. pip cache ---
clean_pip() {
  [ "$PIP_PURGE" = "1" ] || return 0
  if command -v pip3 >/dev/null 2>&1; then
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: pip3 cache purge"
    else
      log "pip3 cache purge"
      pip3 cache purge 2>/dev/null || true
    fi
  elif command -v pip >/dev/null 2>&1; then
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: pip cache purge"
    else
      log "pip cache purge"
      pip cache purge 2>/dev/null || true
    fi
  else
    log "skip: pip не найден"
  fi
}

# --- 11. npm / yarn / uv / poetry / cargo ---
clean_npm() {
  if command -v npm >/dev/null 2>&1; then
    if [ "$NPM_CACHE_CLEAN" = "1" ]; then
      if [ "$DRY_RUN" = "1" ]; then
        log "DRY-RUN: npm cache clean --force"
      else
        log "npm cache clean --force"
        npm cache clean --force 2>/dev/null || true
      fi
    fi
    if [ "$CLEAN_NPM_CACHE_DIR" = "1" ]; then
      local dir="$HOME/.npm/_cacache"
      [ -d "$dir" ] || return 0
      if [ "$DRY_RUN" = "1" ]; then
        log "DRY-RUN: rm -rf $dir"
      else
        log "Удаление npm cacache: $dir"
        rm -rf "$dir" 2>/dev/null || true
      fi
    fi
  else
    [ "$NPM_CACHE_CLEAN" = "1" ] && log "skip: npm не найден"
  fi
}

clean_yarn() {
  [ "$YARN_CACHE_CLEAN" = "1" ] || return 0
  command -v yarn >/dev/null 2>&1 || { log "skip: yarn не найден"; return 0; }
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: yarn cache clean"
  else
    log "yarn cache clean"
    yarn cache clean 2>/dev/null || true
  fi
}

clean_uv() {
  [ "$UV_CLEAN" = "1" ] || return 0
  command -v uv >/dev/null 2>&1 || { log "skip: uv не найден"; return 0; }
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: uv cache clean"
  else
    log "uv cache clean"
    uv cache clean 2>/dev/null || true
  fi
}

clean_poetry() {
  [ "$POETRY_CACHE_CLEAN" = "1" ] || return 0
  local dir="$HOME/.cache/pypoetry"
  [ -d "$dir" ] || { log "skip: нет Poetry cache"; return 0; }
  local sz
  sz=$(size_of "$dir")
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: удалил бы Poetry cache ($sz): $dir"
  else
    log "Очистка Poetry cache ($sz)"
    rm -rf "$dir" 2>/dev/null || true
  fi
}

clean_cargo() {
  [ "$CARGO_CACHE_CLEAN" = "1" ] || return 0
  command -v cargo >/dev/null 2>&1 || { log "skip: cargo не найден"; return 0; }
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: cargo install cargo-cache && cargo cache -a 2>/dev/null || cargo clean"
  else
    log "Очистка cargo registry"
    # Если есть cargo-cache — используем его
    if cargo cache 2>/dev/null --help >/dev/null 2>&1; then
      cargo cache -a 2>/dev/null || true
    else
      # Просто чистим target/ в HOME проектах — опасно, чистим только registry
      rm -rf "$HOME/.cargo/registry/cache"/* 2>/dev/null || true
    fi
  fi
}

# --- 12. /var/cache ---
clean_var_cache() {
  [ "$CLEAN_VAR_CACHE" = "1" ] || return 0
  check_sudo || return 0

  # apt archives (.deb пакеты) — самые тяжёлые
  if [ -d /var/cache/apt/archives ]; then
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: sudo find /var/cache/apt/archives -type f -name '*.deb' ! -path '*/partial/*' -delete"
    else
      log "Очистка /var/cache/apt/archives/*.deb"
      sudo find /var/cache/apt/archives -type f -name '*.deb' ! -path '*/partial/*' -delete 2>/dev/null || true
    fi
  fi

  if [ "$CLEAN_VAR_CACHE_OTHER" = "1" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: sudo find /var/cache -mindepth 1 -maxdepth 1 ! -name apt -exec rm -rf {} +"
    else
      log "Очистка /var/cache (кроме apt)"
      sudo find /var/cache -mindepth 1 -maxdepth 1 ! -name apt -exec rm -rf {} + 2>/dev/null || true
    fi
  fi
}

# --- 13. /var/crash ---
clean_var_crash() {
  [ "$CLEAN_VAR_CRASH" = "1" ] || return 0
  check_sudo || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: sudo rm -f /var/crash/*"
  else
    log "Очистка /var/crash"
    sudo rm -f /var/crash/* 2>/dev/null || true
  fi
}

# --- 14. /var/mail ---
clean_var_mail() {
  [ "$CLEAN_VAR_MAIL" = "1" ] || return 0
  check_sudo || return 0

  # Очистить почту в /var/mail для пользователей
  local mdir="/var/mail"
  [ -d "$mdir" ] || return 0
  local found=0
  for f in "$mdir"/*; do
    [ -f "$f" ] || continue
    local sz
    sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
    [ "$sz" -gt 0 ] || continue
    found=1
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: очистил бы $f ($(numfmt --to=iec "$sz" 2>/dev/null || echo "$sz B"))"
    else
      log "Очистка $f"
      sudo truncate -s 0 "$f" 2>/dev/null || sudo rm -f "$f" && sudo touch "$f" 2>/dev/null || true
    fi
  done
  [ "$found" = "0" ] && log "skip: /var/mail пуст"
}

# --- 15. Nginx, Apache, MySQL, PostgreSQL, Redis логи ---
clean_web_logs() {
  if [ "$NGINX_LOG_CLEAN" = "1" ]; then
    check_sudo || return 0
    [ -d "$NGINX_LOG_DIR" ] || { log "skip: нет $NGINX_LOG_DIR"; }
    if [ -d "$NGINX_LOG_DIR" ] && [ "$DRY_RUN" != "1" ]; then
      log "Очистка nginx логов (старше $NGINX_LOG_DAYS дней)"
      sudo find "$NGINX_LOG_DIR" -type f -name '*.log' -mtime +"$NGINX_LOG_DAYS" -delete 2>/dev/null || true
      sudo find "$NGINX_LOG_DIR" -type f -name '*.gz' -delete 2>/dev/null || true
    fi
  fi

  if [ "$APACHE_LOG_CLEAN" = "1" ]; then
    check_sudo || return 0
    [ -d "$APACHE_LOG_DIR" ] || { log "skip: нет $APACHE_LOG_DIR"; }
    if [ -d "$APACHE_LOG_DIR" ] && [ "$DRY_RUN" != "1" ]; then
      log "Очистка apache логов (старше $APACHE_LOG_DAYS дней)"
      sudo find "$APACHE_LOG_DIR" -type f -name '*.log' -mtime +"$APACHE_LOG_DAYS" -delete 2>/dev/null || true
      sudo find "$APACHE_LOG_DIR" -type f -name '*.gz' -delete 2>/dev/null || true
    fi
  fi
}

clean_mysql_logs() {
  [ "$MYSQL_LOG_CLEAN" = "1" ] || return 0
  check_sudo || return 0
  # MySQL логи обычно в /var/log/mysql/
  local mysql_log_dir="/var/log/mysql"
  [ -d "$mysql_log_dir" ] || { log "skip: нет $mysql_log_dir"; return 0; }
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: sudo find $mysql_log_dir -type f -mtime +$MYSQL_LOG_DAYS -delete"
  else
    log "Очистка MySQL логов (старше $MYSQL_LOG_DAYS дней)"
    sudo find "$mysql_log_dir" -type f -mtime +"$MYSQL_LOG_DAYS" -delete 2>/dev/null || true
  fi
}

# --- 16. Snap (опционально, на сервере редко) ---
clean_snap() {
  [ "$CLEAN_SNAP" = "1" ] || return 0
  command -v snap >/dev/null 2>&1 || { log "skip: snap не найден"; return 0; }
  check_sudo || return 0

  # Удалить отключённые ревизии
  if [ "$DRY_RUN" = "1" ]; then
    snap list --all 2>/dev/null | awk '/disabled/{print "DRY-RUN: snap remove", $1, "--revision=" $3}' || true
  else
    log "Snap: удаление отключённых ревизий"
    snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' | while read -r pkg rev; do
      [ -n "$pkg" ] && [ -n "$rev" ] || continue
      log "  snap remove $pkg --revision=$rev"
      sudo snap remove "$pkg" --revision="$rev" 2>/dev/null || true
    done
  fi

  # Установить retain
  log "Snap: установка refresh.retain=2"
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: sudo snap set system refresh.retain=2"
  else
    sudo snap set system refresh.retain=2 2>/dev/null || log "warn: snap set retain"
  fi

  # Очистка /var/cache/snapd
  [ "$(id -u)" -eq 0 ] || [ "$DRY_RUN" = "1" ] && log "DRY-RUN: sudo rm -rf /var/cache/snapd/*"
  if [ "$DRY_RUN" != "1" ]; then
    sudo rm -rf /var/cache/snapd/* 2>/dev/null || log "warn: clean snapd cache"
  fi
}

# --- 17. Flatpak ---
flatpak_unused() {
  [ "$FLATPAK_UNUSED" = "1" ] || return 0
  command -v flatpak >/dev/null 2>&1 || { log "skip: flatpak не найден"; return 0; }
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN: flatpak uninstall --unused -y"
  else
    log "Flatpak: удаление неиспользуемых runtime"
    flatpak uninstall --unused -y 2>/dev/null || true
  fi
}

# --- 18. Дополнительные мелкие кэши пользователя ---
clean_user_caches() {
  # Дополнительные кэши в ~/.cache
  local cache_dirs=(
    "$HOME/.cache/pip"
    "$HOME/.cache/node-gyp"
    "$HOME/.cache/yarn"
    "$HOME/.cache/vscode-ripgrep"
    "$HOME/.cache/ms-playwright-go"
    "$HOME/.cache/puppeteer"
    "$HOME/.cache/uv"
    "$HOME/.cache/pypoetry"
    "$HOME/.cache/cargo"
  )
  for d in "${cache_dirs[@]}"; do
    [ -d "$d" ] || continue
    local sz
    sz=$(size_of "$d")
    if [ "$DRY_RUN" = "1" ]; then
      log "DRY-RUN: rm -rf $d ($sz)"
    else
      log "Очистка: $d ($sz)"
      rm -rf "$d" 2>/dev/null || true
    fi
  done
}

# --- 19. Сводка по диску ---
show_disk_summary() {
  log "=== СВОДКА ПО ДИСКУ ==="
  echo ""
  echo "--- ИСПОЛЬЗОВАНИЕ ДИСКА (/) ---"
  df -h / 2>/dev/null || true
  echo ""

  echo "--- ТОП-15 КАТАЛОГОВ В /var ---"
  sudo du -sh /var/* 2>/dev/null | sort -rh | head -15 || true
  echo ""

  echo "--- ТОП-10 КАТАЛОГОВ В $HOME (скрытые) ---"
  du -sh "$HOME"/.* 2>/dev/null | sort -rh | head -10 || true
  echo ""

  echo "--- ТОП-10 КАТАЛОГОВ В $HOME (обычные) ---"
  du -sh "$HOME"/* 2>/dev/null | sort -rh | head -10 || true
  echo ""

  echo "--- ТОП-5 КАТАЛОГОВ В /var/log ---"
  sudo du -sh /var/log/* 2>/dev/null | sort -rh | head -5 || true
  echo ""

  echo "--- ТОП-5 ОБРАЗОВ DOCKER ---"
  if command -v docker >/dev/null 2>&1; then
    docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" 2>/dev/null | sort -k2 -rh | head -5 || true
  fi
  echo ""

  echo "--- ТОП-5 КОНТЕЙНЕРОВ DOCKER ---"
  if command -v docker >/dev/null 2>&1; then
    docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Size}}\t{{.CreatedAt}}" 2>/dev/null | head -5 || true
  fi
  echo ""

  echo "--- JOURNALD ---"
  journalctl --disk-usage 2>/dev/null || true
  echo ""

  echo "--- SNAP (если установлен) ---"
  if command -v snap >/dev/null 2>&1; then
    snap list 2>/dev/null || true
  fi
  echo ""

  echo "--- PIP КЭШ ---"
  du -sh "$HOME/.cache/pip" 2>/dev/null || echo "нет кэша"
  echo ""

  echo "--- NPM КЭШ ---"
  du -sh "$HOME/.npm" 2>/dev/null || echo "нет кэша"
  echo ""
}

# ════════════════════════════════════════════
# ГЛАВНЫЙ ЦИКЛ
# ════════════════════════════════════════════

log "=== НАЧАЛО ОЧИСТКИ ==="
BEFORE_FREE=$(free_bytes)
log "Свободно ДО: $(printf "%s" "$BEFORE_FREE" | human)"
log "DRY_RUN=$DRY_RUN"

# --- APT ---
apt_maintenance

# --- Ядра ---
clean_old_kernels

# --- Journal ---
vacuum_journal

# --- Логи ---
clean_old_log_gz
clean_var_log_old
clean_rotated_logs
clean_fail2ban_logs
clean_mysql_logs
clean_web_logs

# --- /tmp, /var/tmp ---
clean_tmp_all
clean_vartmp_all

# --- Docker ---
docker_prune_safe
docker_prune_buildx
docker_orphan_volumes
docker_prune

# --- pip, npm, yarn, uv, poetry, cargo ---
clean_pip
clean_npm
clean_yarn
clean_uv
clean_poetry
clean_cargo

# --- /var/cache, /var/crash, /var/mail ---
clean_var_cache
clean_var_crash
clean_var_mail

# --- Snap / Flatpak (опционально, редко на сервере) ---
clean_snap
flatpak_unused

# --- Пользовательские кэши ---
clean_user_caches

# --- Корзина ---
[ "$EMPTY_TRASH" = "1" ] && empty_trash

# ════════════════════════════════════════════
# ИТОГИ
# ════════════════════════════════════════════

AFTER_FREE=$(free_bytes)
DELTA=$(( AFTER_FREE - BEFORE_FREE ))
log "Свободно ПОСЛЕ: $(printf "%s" "$AFTER_FREE" | human) (Δ=$(printf "%s" "$DELTA" | human))"

show_disk_summary

log "=== ГОТОВО ==="