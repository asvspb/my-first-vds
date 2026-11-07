"""Unit tests for src/core/secrets.py (FR-0.5). tmp_path only, no root."""

import os
import stat
import uuid
from pathlib import Path

import pytest

from src.core.secrets import gen_password, gen_uuid, write_secret_atomic


class TestGenerators:
    def test_two_uuids_differ(self) -> None:
        assert gen_uuid() != gen_uuid()

    def test_uuid_is_valid_uuid4(self) -> None:
        parsed = uuid.UUID(gen_uuid())
        assert parsed.version == 4

    def test_two_passwords_differ(self) -> None:
        assert gen_password() != gen_password()

    def test_password_default_length(self) -> None:
        assert len(gen_password()) == 24

    def test_password_custom_length(self) -> None:
        assert len(gen_password(32)) == 32

    def test_password_alphanumeric_only(self) -> None:
        pwd = gen_password(200)
        assert pwd.isalnum()


class TestWriteSecretAtomic:
    def test_creates_file_with_0600_and_content(self, tmp_path: Path) -> None:
        path = tmp_path / "secret.txt"
        assert write_secret_atomic(str(path), "hunter2") is True
        assert path.read_text() == "hunter2"
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600

    def test_custom_mode(self, tmp_path: Path) -> None:
        path = tmp_path / "key.pem"
        assert write_secret_atomic(str(path), "data", mode=0o640) is True
        assert stat.S_IMODE(path.stat().st_mode) == 0o640

    def test_overwrites_existing_file_atomically(self, tmp_path: Path) -> None:
        path = tmp_path / "secret.txt"
        path.write_text("old")
        assert write_secret_atomic(str(path), "new-value") is True
        assert path.read_text() == "new-value"
        leftovers = [p for p in tmp_path.iterdir() if p.name != "secret.txt"]
        assert leftovers == []  # tmp-файл не остался

    def test_failure_leaves_no_partial_file(self, tmp_path: Path) -> None:
        # каталог не существует — запись невозможна
        path = tmp_path / "missing-dir" / "secret.txt"
        assert write_secret_atomic(str(path), "x") is False
        assert not path.exists()
        assert not (tmp_path / "missing-dir").exists() or list(
            (tmp_path / "missing-dir").iterdir()
        ) == []

    def test_failure_on_unwritable_dir(self, tmp_path: Path) -> None:
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        ro_dir.chmod(0o500)
        if os.access(ro_dir, os.W_OK):  # например, под root — пропускаем
            pytest.skip("running with write access to 0500 dir")
        path = ro_dir / "secret.txt"
        assert write_secret_atomic(str(path), "x") is False
        assert not path.exists()
        assert list(ro_dir.iterdir()) == []  # частичного файла нет
