[Unit]
Description=VDS RU-relay policy-routing (nft vds_relay + fwmark {mark} -> table {table}, ADR-007)
Documentation=https://github.com/asvspb/my-first-vds
After=network-online.target vds-relay-exit.service vds-relay-cidr.service
# ADR-016 I-2a: мягкий порядок (After, НЕ Requires) — юнит носителя №2 может
# отсутствовать (wg-ws0 не установлен), это не ошибка старта policy.
After=vds-awg-wg-ws0.service
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
# ADR-016 AC-S4: после базовой настройки — table 100 -> активный носитель из
# p2p-carriers.json (дефолт awg1; отсутствие/битость state совместимы).
# Скрипт всегда exit 0 и сам проверяет `ip link show` — юнит не падает, если
# носитель №2 не поднялся. Ведущий дефис = игнорировать отсутствие скрипта.
ExecStartPost=-/etc/vds-relay/carrier-default-iface.sh {exit_iface}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
