"""XrayAdapter — реализация ProtocolAdapter для Xray VLESS Reality.

Тонкая обёртка: делегирует в install/clients/status/remove. CLI работает с
адаптером полиморфно (core/protocol.py); dry-run/apply для remove — на уровне
CLI, adapter.remove() по умолчанию печатает dry-run-план.
"""

from src.core.netcheck import public_ip
from src.core.protocol import ProtocolAdapter
from src.xray import clients as clients_mod
from src.xray import install as install_mod
from src.xray import remove as remove_mod
from src.xray import status as status_mod


class XrayAdapter(ProtocolAdapter):
    """Адаптер Xray VLESS Reality (TCP 443)."""

    name = "xray"
    default_port = 443
    transport = "tcp"

    def install(self, opts: dict) -> int:
        """opts: {sni?: str, port?: int} -> install.run_install."""
        return install_mod.run_install(
            sni=opts.get("sni", "www.google.com"),
            port=int(opts.get("port", self.default_port)),
        )

    def add_client(self, name: str) -> dict:
        return clients_mod.add_client(name)

    def remove_client(self, name: str) -> int:
        return clients_mod.remove_client(name)

    def status(self) -> dict:
        return status_mod.collect_status()

    def render_share_links(self, profile: dict) -> list[str]:
        """Ссылка для профиля клиента (из store или результата add_client).

        profile: {name, uuid, sni, extra: {public_key, short_id}, port?};
        host берётся из profile['host'], иначе public_ip(), иначе плейсхолдер.
        """
        extra = profile.get("extra") or {}
        host = profile.get("host") or public_ip() or "SERVER_IP"
        link = clients_mod.render_share_link(
            host=host,
            client_uuid=profile["uuid"],
            sni=profile.get("sni") or "www.google.com",
            public_key=extra.get("public_key", ""),
            short_id=extra.get("short_id", ""),
            name=profile["name"],
            port=int(profile.get("port", self.default_port)),
        )
        return [link]

    def remove(self) -> int:
        """Dry-run-план удаления (apply — на уровне CLI, SPEC §3)."""
        return remove_mod.run_remove(apply=False)
