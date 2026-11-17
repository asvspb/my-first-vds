[Unit]
Description=VDS RU-relay policy-routing (nft vds_relay + fwmark {mark} -> table {table}, ADR-007)
Documentation=https://github.com/asvspb/my-first-vds
After=network-online.target vds-relay-exit.service vds-relay-cidr.service
Wants=network-online.target
# Маршрут `default dev awg1 table 100` привязан к интерфейсу: при
# restart/down vds-relay-exit ядро его удаляет, и зависящая от fwmark
# политика молча деградирует в прямой выход (живой случай LandVPS
# 2026-11-17). PartOf перезапускает политику вместе с exit-ногой.
PartOf=vds-relay-exit.service

[Service]
Type=oneshot
# Идемпотентно: nft -f флушит свою таблицу декларацией; ip rule/route
# добавляются при отсутствии. Default в table {table} — dev {exit_iface}.
ExecStart=/bin/sh -c 'nft -f {nft_file}; ip rule show | grep -q "fwmark {mark} lookup {table}" || ip rule add fwmark {mark} table {table}; ip route replace default dev {exit_iface} table {table}'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
