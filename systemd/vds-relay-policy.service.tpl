[Unit]
Description=VDS RU-relay policy-routing (nft vds_relay + fwmark {mark} -> table {table}, ADR-007)
Documentation=https://github.com/asvspb/my-first-vds
After=network-online.target vds-relay-exit.service vds-relay-cidr.service
Wants=network-online.target

[Service]
Type=oneshot
# Идемпотентно: nft -f флушит свою таблицу декларацией; ip rule/route
# добавляются при отсутствии. Default в table {table} — dev {exit_iface}.
ExecStart=/bin/sh -c 'nft -f {nft_file}; ip rule show | grep -q "fwmark {mark} lookup {table}" || ip rule add fwmark {mark} table {table}; ip route replace default dev {exit_iface} table {table}'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
