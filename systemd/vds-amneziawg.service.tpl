[Unit]
Description=VDS AmneziaWG gateway (obfuscated WireGuard)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# amneziawg-tools (PPA ppa:amnezia/ppa, ADR-005): awg-quick читает obfuscation
# (Jc/Jmin/Jmax, S1/S2, H1-H4) из .conf; интерфейс awg0 (kernel-модуль amneziawg).
ExecStart=/usr/bin/awg-quick up {config_path}
# P14: awg-quick down по имени интерфейса ищет конфиг в дефолтном каталоге
# /etc/amnezia/amneziawg/<iface>.conf; наш конфиг лежит в AWG_CONFIG_PATH
# (/etc/amnezia/awg0.conf) → down обязан идти по пути конфига.
ExecStop=/usr/bin/awg-quick down {config_path}

# Конфиг содержит приватный ключ сервера (0600) — читается только awg-quick'ом.
NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
