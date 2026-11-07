"""Unit tests for src/core/shell.py: load_env and docker_exec.

No root, no network, no docker: subprocess is mocked via run_list.
"""

from pathlib import Path

import pytest

from src.core.shell import ShellResult, docker_exec, load_env


def _ok(stdout: str = "") -> ShellResult:
    return ShellResult(stdout=stdout, stderr="", returncode=0)


class TestLoadEnv:
    def test_parses_simple_key_values(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env"
        env_file.write_text("PUBLIC_IP=1.2.3.4\nMAIN_IFACE=eth0\n")
        assert load_env(str(env_file)) == {"PUBLIC_IP": "1.2.3.4", "MAIN_IFACE": "eth0"}

    def test_missing_file_returns_empty_dict(self, tmp_path: Path) -> None:
        assert load_env(str(tmp_path / "nope.env")) == {}

    def test_comments_blank_and_invalid_lines_skipped(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env"
        env_file.write_text(
            "# full-line comment\n"
            "\n"
            "   # indented comment\n"
            "NO_EQUALS_SIGN\n"
            "KEY=value\n"
        )
        assert load_env(str(env_file)) == {"KEY": "value"}

    def test_whitespace_stripped(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env"
        env_file.write_text("  KEY  =  value  \n")
        assert load_env(str(env_file)) == {"KEY": "value"}

    def test_double_quoted_value_unquoted(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env"
        env_file.write_text('KEY="hello world"\n')
        assert load_env(str(env_file)) == {"KEY": "hello world"}

    def test_single_quoted_value_unquoted(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env"
        env_file.write_text("KEY='hello world'\n")
        assert load_env(str(env_file)) == {"KEY": "hello world"}

    def test_unmatched_quotes_kept_verbatim(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env"
        env_file.write_text('KEY="unmatched\n')
        assert load_env(str(env_file)) == {"KEY": '"unmatched'}

    def test_empty_value(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env"
        env_file.write_text("EMPTY=\n")
        assert load_env(str(env_file)) == {"EMPTY": ""}


class TestDockerExec:
    def test_list_passed_through_as_is(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_run_list(args: list[str], check: bool = False, timeout: int | None = None) -> ShellResult:
            captured["args"] = args
            captured["timeout"] = timeout
            return _ok("ONLINE")

        monkeypatch.setattr("src.core.shell.run_list", fake_run_list)
        result = docker_exec("ztnet_zerotier", ["zerotier-cli", "-j", "listnetworks"], timeout=5)

        assert result.ok
        assert result.output == "ONLINE"
        assert captured["args"] == [
            "docker", "exec", "ztnet_zerotier", "zerotier-cli", "-j", "listnetworks",
        ]
        assert captured["timeout"] == 5

    def test_string_parsed_with_shlex(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_run_list(args: list[str], check: bool = False, timeout: int | None = None) -> ShellResult:
            captured["args"] = args
            return _ok()

        monkeypatch.setattr("src.core.shell.run_list", fake_run_list)
        docker_exec("ztnet_zerotier", "zerotier-cli info")

        assert captured["args"] == ["docker", "exec", "ztnet_zerotier", "zerotier-cli", "info"]

    def test_string_with_quoted_argument_stays_single_arg(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        def fake_run_list(args: list[str], check: bool = False, timeout: int | None = None) -> ShellResult:
            captured["args"] = args
            return _ok()

        monkeypatch.setattr("src.core.shell.run_list", fake_run_list)
        docker_exec("ztnet_zerotier", 'cat "/var/lib/my dir/file with spaces"')

        assert captured["args"] == [
            "docker", "exec", "ztnet_zerotier",
            "cat", "/var/lib/my dir/file with spaces",
        ]

    def test_default_timeout_is_10(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_run_list(args: list[str], check: bool = False, timeout: int | None = None) -> ShellResult:
            captured["timeout"] = timeout
            return _ok()

        monkeypatch.setattr("src.core.shell.run_list", fake_run_list)
        docker_exec("ztnet_zerotier", ["true"])

        assert captured["timeout"] == 10
