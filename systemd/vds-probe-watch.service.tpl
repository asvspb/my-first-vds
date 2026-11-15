[Unit]
Description=VDS Probe Watch (active probing monitor, nft counters + journal, И33 v1)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
# Персистентность после ребута: счётчики в ядре не живут — если таблицы нет,
# применяем файл-источник первым тиком (таблица поднимется сама).
ExecStartPre=/bin/sh -c 'nft list table inet vds_probe >/dev/null 2>&1 || nft -f {nft_file}'
# Отсутствие таблицы после ExecStartPre = exit 1 (юнит failed — сигнал, не шум).
# --record: только таймер перезаписывает снапшот (ручной watch read-only).
ExecStart={python} -m src.main gateway probe-watch watch --since 1h --record
StandardOutput=journal
StandardError=journal
IOSchedulingClass=idle
CPUWeight=1
