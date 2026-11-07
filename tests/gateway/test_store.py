"""Unit-тесты gateway/store: roundtrip, права, битый JSON, дубликаты, удаление."""
import pytest

from src.gateway.store import (
    ClientProfile,
    GatewayState,
    StoreError,
    add_client,
    load_state,
    remove_client,
    save_state,
)


def make_profile(
    name: str = "alice", protocol: str = "xray", port: int = 443, uuid: str = "uuid-1"
) -> ClientProfile:
    return ClientProfile(name=name, protocol=protocol, port=port, uuid=uuid)


def test_roundtrip(tmp_path):
    state = GatewayState(domain="example.com")
    state = add_client(state, make_profile())
    path = tmp_path / "state.json"
    assert save_state(state, str(path)) is True
    loaded = load_state(str(path))
    assert loaded == state
    assert loaded.clients[0].name == "alice"
    assert loaded.version == 1


def test_save_state_permissions_0600(tmp_path):
    path = tmp_path / "state.json"
    save_state(GatewayState(), str(path))
    mode = (path.stat().st_mode & 0o777)
    assert mode == 0o600
    # повторный save не меняет права и не оставляет tmp-файлов
    save_state(GatewayState(domain="d"), str(path))
    assert (path.stat().st_mode & 0o777) == 0o600
    assert list(tmp_path.glob("*.tmp")) == []


def test_load_missing_file_returns_empty_state(tmp_path):
    state = load_state(str(tmp_path / "missing.json"))
    assert state == GatewayState()
    assert state.clients == []


def test_broken_json_raises_readable_store_error(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(StoreError) as exc_info:
        load_state(str(path))
    msg = str(exc_info.value)
    assert str(path) in msg
    assert "JSON" in msg


def test_duplicate_name_rejected_without_overwrite(tmp_path):
    state = GatewayState()
    state = add_client(state, make_profile(name="alice", uuid="uuid-a"))
    with pytest.raises(StoreError, match="alice"):
        add_client(state, make_profile(name="alice", uuid="uuid-b"))
    # исходное состояние не перезаписано: один клиент со старым uuid
    assert len(state.clients) == 1
    assert state.clients[0].uuid == "uuid-a"


def test_remove_existing_client(tmp_path):
    state = GatewayState()
    state = add_client(state, make_profile(name="alice"))
    state = add_client(state, make_profile(name="bob"))
    new_state = remove_client(state, "alice")
    assert [c.name for c in new_state.clients] == ["bob"]
    # чистая функция: исходное состояние не изменилось
    assert [c.name for c in state.clients] == ["alice", "bob"]


def test_remove_missing_client_raises(tmp_path):
    state = GatewayState()
    with pytest.raises(StoreError, match="ghost"):
        remove_client(state, "ghost")


def test_unknown_version_rejected(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"version": 99, "clients": []}', encoding="utf-8")
    with pytest.raises(StoreError, match="версия"):
        load_state(str(path))
