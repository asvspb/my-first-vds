[Unit]
Description=VDS Alert Watch (threat / relay pulse / heartbeat notifications, exit node)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
# Секреты НЕ в Environment: процесс читает /etc/vds/alert.env (0600) сам.
ExecStart={python} -m src.main alert watch --config /etc/vds/alert.env
StandardOutput=journal
StandardError=journal
Nice=10
IOSchedulingClass=idle
CPUWeight=10
MemoryMax=96M
TimeoutStartSec=60
NoNewPrivileges=yes
# awg show — netlink (CAP_NET_ADMIN), ping — raw socket (CAP_NET_RAW)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ReadWritePaths=/var/lib/vds /var/run
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
