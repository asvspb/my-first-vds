# Managed by VDS Orchestrator (vds hysteria2 install) — не удаляется при
# `vds hysteria2 remove` (ADR-002/OQ-2: тюнинг безвреден и полезен остальным
# сервисам). Источник: CENSORSHIP-ROADMAP, фаза 2.
#
# BBR для TCP-транспортов gateway (Xray) + fq-qdisc, требуемый BBR.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# UDP-буферы для QUIC (Hysteria2): апстрим-рекомендация 16 МБ — без этого
# скорость на линиях с большим BDP ограничена буферами ядра.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
