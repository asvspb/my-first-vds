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

# Учёт байтов в conntrack-таблице: с 1 в /proc/net/nf_conntrack появляются
# поля bytes_orig/bytes_reply, по которым probe-watch верифицирует UDP-сессии
# (Hysteria2 443/udp) — без acct остаётся фолбэк только на [ASSURED]
# (SPEC-20261116-surface-hardening §1.2, HF-1). Ubuntu 24.04 default = 0.
net.netfilter.nf_conntrack_acct = 1
