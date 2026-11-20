[Unit]
Description=VDS relay exit-leg port pool (nft REDIRECT 51900-51911 + UFW P_base, ADR-015/P24)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Правила nat/prerouting и UFW не переживают ребут — oneshot восстанавливает
# их идемпотентным apply-скриптом (nft -f + ufw allow). Артефакт
# перегенерируется командой `vds relay exit-leg install`, руками не правится.
ExecStart={script_path}

NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
