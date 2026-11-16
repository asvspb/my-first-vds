[Unit]
Description=VDS Logs Daily Analyze (rules T-01..T-17 + report, SPEC-20261116-log-forensics)
After=network.target

[Service]
Type=oneshot
Environment=INSTALL_DIR={install_dir}
WorkingDirectory={repo_dir}
ExecStart={python} -m src.main logs report --apply
StandardOutput=journal
StandardError=journal
# SPEC §6.2 (ревью G2): daily-анализ тяжелее сэмплера
Nice=10
IOSchedulingClass=idle
CPUWeight=20
MemoryMax=192M
TimeoutStartSec=600
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYSLOG CAP_DAC_READ_SEARCH
ProtectSystem=strict
ReadWritePaths=/var/lib/vds /var/run
ProtectHome=yes
PrivateTmp=yes
