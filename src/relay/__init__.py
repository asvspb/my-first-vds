"""RU-relay (ADR-007, SPEC-20261114-ru-relay): входной релей на российском VDS.

AWG-сервер UDP 443 (awg0, 10.10.0.0/24) + Xray Reality TCP 443 RU-SNI +
awg1-нога до asv1 + policy-routing (RU-CIDR → eth0, прочее → awg1 через
fwmark/table 100) + UFW + еженедельный таймер обновления RU-CIDR.
"""
