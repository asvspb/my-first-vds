[Unit]
Description=VDS RU-relay NAT (MASQUERADE {client_subnet} -> {exit_iface}/{wan_if}, ADR-007)
Documentation=https://github.com/asvspb/my-first-vds
After=network-online.target vds-relay-exit.service
Wants=network-online.target

[Service]
Type=oneshot
# Идемпотентно: -C (есть?) -> нет -> -A; две цели: awg1 (к asv1) и eth0
# (RU-direct). Не зависит от ufw before.rules (на релее ufw может быть
# активен — правило дублируется в before.rules через runbook при наличии).
# ADR-016: второй носитель (wg-ws0) — та же точка MASQUERADE, не nft
# (nft-таблица vds_relay перегенерируется cidr-таймером и правило бы потерялось).
# Пустые p2p_* (по умолчанию) — правило не ставится.
ExecStart=/bin/sh -c 'iptables -t nat -C POSTROUTING -s {client_subnet} -o {exit_iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {client_subnet} -o {exit_iface} -j MASQUERADE; iptables -t nat -C POSTROUTING -s {client_subnet} -o {wan_if} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {client_subnet} -o {wan_if} -j MASQUERADE; if [ -n "{p2p_iface}" ]; then iptables -t nat -C POSTROUTING -s {p2p_subnet} -o {p2p_iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {p2p_subnet} -o {p2p_iface} -j MASQUERADE; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
