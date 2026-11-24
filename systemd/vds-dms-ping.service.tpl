[Unit]
Description=VDS DMS ping (dead-man-switch gate, quiet-exit P37)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
# Секрет НЕ в Environment: процесс читает /etc/vds/dms.env (0600) сам.
ExecStart={python} -m src.main dms ping --config /etc/vds/dms.env
StandardOutput=journal
StandardError=journal
Nice=10
IOSchedulingClass=idle
CPUWeight=10
MemoryMax=64M
TimeoutStartSec=60
NoNewPrivileges=yes
# ip link / ping-проба носителя: netlink (CAP_NET_ADMIN) + raw socket (CAP_NET_RAW)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ReadWritePaths=/var/run
ProtectHome=yes
PrivateTmp=yes
# ВАЖНО: исходящий HTTPS (urllib, Healthchecks) — AF_INET ОБЯЗАТЕЛЕН.
# DMS, в отличие от alert-watch, ходит в интернет; zero-AF_INET-инвариант
# (vpn-guard I-2) относится только к демонам guard, не к этому oneshot.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
