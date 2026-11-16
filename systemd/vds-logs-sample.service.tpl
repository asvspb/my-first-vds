[Unit]
Description=VDS Logs Telemetry Sampler (5-min forensic sample, SPEC-20261116-log-forensics)
After=network.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
ExecStart={python} -m src.main logs sample --apply
StandardOutput=journal
StandardError=journal
# SPEC §6.2 (ревью G2): ресурсные пределы сэмплера
Nice=10
IOSchedulingClass=idle
CPUWeight=10
MemoryMax=64M
TimeoutStartSec=120
NoNewPrivileges=yes
# root-чтение nft/journal/proc; запись только в /var/lib/vds + runtime-lock
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYSLOG CAP_DAC_READ_SEARCH
ProtectSystem=strict
ReadWritePaths=/var/lib/vds /var/run
ProtectHome=yes
PrivateTmp=yes
