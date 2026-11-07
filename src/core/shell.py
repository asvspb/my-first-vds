import os
import shlex
import shutil
import subprocess
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class ShellResult:
    stdout: str
    stderr: str
    returncode: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return self.stdout.strip()


def run(
    command: str,
    check: bool = False,
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
    cwd: Optional[str] = None,
) -> ShellResult:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, command, result.stdout, result.stderr
            )
        return ShellResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return ShellResult(stdout="", stderr="timeout", returncode=-1)
    except Exception as e:
        return ShellResult(stdout="", stderr=str(e), returncode=-1)


def run_list(
    args: list[str],
    check: bool = False,
    timeout: Optional[int] = None,
) -> ShellResult:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, args, result.stdout, result.stderr
            )
        return ShellResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return ShellResult(stdout="", stderr="timeout", returncode=-1)
    except Exception as e:
        return ShellResult(stdout="", stderr=str(e), returncode=-1)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def load_env(path: str) -> dict[str, str]:
    """Parse a KEY=VALUE env file into a dict.

    Skips blank lines and full-line comments; lines without '=' are ignored.
    Surrounding matching quotes (single or double) are stripped from values.
    Returns an empty dict if the file does not exist.
    """
    env: dict[str, str] = {}
    if not os.path.isfile(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            if key:
                env[key] = val
    return env


def docker_exec(container: str, command: str | list[str], timeout: int = 10) -> ShellResult:
    """Run a command inside a docker container.

    `command` as a list is passed through as-is; as a string it is parsed
    with shlex.split so quoted arguments survive intact.
    """
    args = shlex.split(command) if isinstance(command, str) else list(command)
    return run_list(["docker", "exec", container] + args, timeout=timeout)


def docker_inspect(container: str, format_str: str) -> str:
    result = run_list(
        ["docker", "inspect", "--format", format_str, container],
        timeout=5,
    )
    return result.output if result.ok else ""


def systemctl(action: str, service: str, check: bool = False) -> ShellResult:
    return run_list(["systemctl", action, service], check=check, timeout=10)
