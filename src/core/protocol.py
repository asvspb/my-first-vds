"""ProtocolAdapter ABC — единый контракт протоколов gateway (roadmap §4.0).

Каждый транспорт (Xray VLESS Reality, Hysteria2, ...) реализует этот интерфейс;
CLI-слой работает с адаптером полиморфно. Методы возвращают int-коды (0 —
успех) или dict-профили; исключения наружу не пробрасываются за исключением
`StoreError` на уровне store (см. SPEC §3).
"""

from abc import ABC, abstractmethod


class ProtocolAdapter(ABC):
    """Базовый интерфейс адаптера VPN-протокола.

    Атрибуты класса:
        name: человекочитаемое имя протокола (используется в store/CLI).
        default_port: порт по умолчанию (443 для MVP-транспортов).
        transport: "tcp" | "udp" — для netcheck.port_free.
    """

    name: str
    default_port: int
    transport: str  # "tcp" | "udp"

    @abstractmethod
    def install(self, opts: dict) -> int:
        """Установить протокол (конфиг, юнит, включение). 0 — успех."""
        ...

    @abstractmethod
    def add_client(self, name: str) -> dict:
        """Добавить клиента, вернуть его профиль (dict) для store."""
        ...

    @abstractmethod
    def remove_client(self, name: str) -> int:
        """Удалить клиента по имени. 0 — успех."""
        ...

    @abstractmethod
    def status(self) -> dict:
        """Текущее состояние протокола (юнит, порт, клиенты) как dict."""
        ...

    @abstractmethod
    def render_share_links(self, profile: dict) -> list[str]:
        """Ссылки подключения для профиля клиента (без приватных ключей)."""
        ...

    @abstractmethod
    def remove(self) -> int:
        """Полное удаление протокола (dry-run/apply — на уровне CLI). 0 — успех."""
        ...
