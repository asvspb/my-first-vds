[Unit]
Description=VDS Hysteria2 port hopping (iptables REDIRECT chain, ADR-008)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={hop_script}
RemainAfterExit=yes

# Правила nat/PREROUTING не переживают ребут — юнит восстанавливает цепочку
# VDS_HY2_HOP идемпотентным apply-скриптом (ADR-008; артефакт перегенерируется
# командой `vds hysteria2 add-hop-ports`, руками на сервере не правится).
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
