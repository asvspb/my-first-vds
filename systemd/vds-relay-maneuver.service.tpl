[Unit]
Description=VDS Relay Maneuver (relay→exit leg port failover tick, ADR-015/P25)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
# Тик всегда exit 0: guard/ManeuverError/StoreError/занятый лок перехвачены
# в run_tick (oneshot не должен уходить в failed). Секретов в командной
# строке и Environment нет — state манёвра 0600 читается процессом сам.
ExecStart={python} -m src.main relay maneuver tick --apply
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vds-relay-maneuver
Nice=5
TimeoutStartSec=60
NoNewPrivileges=yes
# awg show/set — netlink (CAP_NET_ADMIN), ping -I — raw socket (CAP_NET_RAW)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
# persist_endpoint и бэкап awg1.conf.bak-pre-maneuver лежат в /etc/amnezia —
# без этого пути ProtectSystem=strict даёт EROFS; state манёвра — /var/lib/vds,
# лок — /var/run.
ReadWritePaths=/var/lib/vds /var/run /etc/amnezia
ProtectHome=yes
PrivateTmp=yes
# awg — netlink, ping — AF_INET/AF_INET6, лок — AF_UNIX
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
