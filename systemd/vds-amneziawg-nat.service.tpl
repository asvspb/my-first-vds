[Unit]
Description=VDS AmneziaWG NAT (MASQUERADE {subnet} -> {wan_if}, персистентно при ребуте)
Documentation=https://github.com/asvspb/my-first-vds
After=network-online.target vds-amneziawg.service
Wants=network-online.target

[Service]
Type=oneshot
# Идемпотентно: -C (есть?) → нет → -A. Не зависит от ufw (before.rules
# грузится только активным ufw — на части серверов ufw inactive).
ExecStart=/bin/sh -c 'iptables -t nat -C POSTROUTING -s {subnet} -o {wan_if} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} -o {wan_if} -j MASQUERADE'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
