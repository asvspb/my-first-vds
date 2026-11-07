"""HysteriaAdapter — реализация ProtocolAdapter для Hysteria2 (QUIC, UDP 443).

Тонкая обёртка: делегирует в install/clients/status/remove. CLI работает с
адаптером полиморфно (core/protocol.py); dry-run/apply для remove — на уровне
CLI, adapter.remove() по умолчанию печатает dry-run-план.
"""

from src.core.netcheck import public_ip
from src.core.protocol import ProtocolAdapter
from src.hysteria2 import clients as clients_mod
from src.hysteria2 import install as install_mod
from src.hysteria2 import remove as remove_mod
from src.hysteria2 import status as status_mod


class HysteriaAdapter(ProtocolAdapter):
    """Адаптер Hysteria2 (QUIC, self-signed без домена)."""

    name = "hysteria2"
    default_port = 443
    transport = "udp"

    def install(self, opts: dict) -> int:
        """opts: {port?: int} -> install.run_install."""
        return install_mod.run_install(port=int(opts.get("port", self.default_port)))

    def add_client(self, name: str) -> dict:
        return clients_mod.add_client(name)

    def remove_client(self, name: str) -> int:
        return clients_mod.remove_client(name)

    def status(self) -> dict:
        return status_mod.collect_status()

    def render_share_links(self, profile: dict) -> list[str]:
        """Ссылка для профиля клиента (из store или результата add_client).

        profile: {name, password, sni (IP сервера), port?}; host берётся из
        profile['host'], иначе sni, иначе public_ip(), иначе плейсхолдер.
        """
        host = (
            profile.get("host")
            or profile.get("sni")
            or public_ip()
            or "SERVER_IP"
        )
        link = clients_mod.render_share_link(
            host=host,
            password=profile["password"],
            name=profile["name"],
            port=int(profile.get("port", self.default_port)),
        )
        return [link]

    def remove(self) -> int:
        """Dry-run-план удаления (apply — на уровне CLI, SPEC §3)."""
        return remove_mod.run_remove(apply=False)
