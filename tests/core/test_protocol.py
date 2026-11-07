"""Unit tests for src/core/protocol.py — ProtocolAdapter contract (FR-0.7).

No root, no network, no docker.
"""

import inspect

import pytest

from src.core.protocol import ProtocolAdapter


class _StubAdapter(ProtocolAdapter):
    """Минимальная реализация контракта для проверки интерфейса."""

    name = "stub"
    default_port = 443
    transport = "tcp"

    def install(self, opts: dict) -> int:
        return 0

    def add_client(self, name: str) -> dict:
        return {"name": name, "uuid": "test-uuid"}

    def remove_client(self, name: str) -> int:
        return 0

    def status(self) -> dict:
        return {"active": True, "clients": 1}

    def render_share_links(self, profile: dict) -> list:
        return [f"stub://{profile['name']}"]

    def remove(self) -> int:
        return 0


class TestContract:
    def test_incomplete_subclass_cannot_instantiate(self) -> None:
        class Incomplete(ProtocolAdapter):
            name = "x"
            default_port = 1
            transport = "tcp"

            def install(self, opts: dict) -> int:
                return 0

        with pytest.raises(TypeError):
            Incomplete()

    def test_abstract_methods_present(self) -> None:
        expected = {
            "install",
            "add_client",
            "remove_client",
            "status",
            "render_share_links",
            "remove",
        }
        assert expected == ProtocolAdapter.__abstractmethods__

    def test_stub_adapter_instantiates_and_calls(self) -> None:
        adapter = _StubAdapter()
        assert adapter.name == "stub"
        assert adapter.default_port == 443
        assert adapter.transport == "tcp"
        assert adapter.install({}) == 0
        profile = adapter.add_client("alice")
        assert profile["name"] == "alice"
        assert adapter.render_share_links(profile) == ["stub://alice"]
        assert adapter.remove_client("alice") == 0
        assert adapter.status() == {"active": True, "clients": 1}
        assert adapter.remove() == 0

    def test_all_methods_have_annotations(self) -> None:
        for method_name in ProtocolAdapter.__abstractmethods__:
            func = getattr(ProtocolAdapter, method_name)
            signature = inspect.signature(func)
            for param_name in ("opts", "name", "profile"):
                if param_name in signature.parameters:
                    assert signature.parameters[param_name].annotation is not inspect.Parameter.empty, (
                        f"{method_name}.{param_name} lacks annotation"
                    )
            assert signature.return_annotation is not inspect.Signature.empty, (
                f"{method_name} lacks return annotation"
            )

    def test_class_attributes_annotated(self) -> None:
        hints = ProtocolAdapter.__annotations__
        assert {"name", "default_port", "transport"} <= set(hints)
