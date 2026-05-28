import platform
import subprocess
from typing import Optional

import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.progress_bar import ProgressBar

from src.core.shell import run

console = Console()


def get_public_ip() -> str:
    result = run("curl -s --connect-timeout 2 --max-time 4 ifconfig.me 2>/dev/null")
    return result.output if result.ok else "N/A"


def get_docker_status() -> tuple[int, int]:
    running = run("docker ps -q 2>/dev/null | wc -l")
    total = run("docker ps -aq 2>/dev/null | wc -l")
    r = int(running.output) if running.ok and running.output.isdigit() else 0
    t = int(total.output) if total.ok and total.output.isdigit() else 0
    return r, t


def make_bar(percent: float, width: int = 20) -> Text:
    filled = int(percent * width / 100)
    empty = width - filled
    text = Text()
    if percent >= 90:
        color = "red"
    elif percent >= 70:
        color = "yellow"
    else:
        color = "green"
    text.append("#" * filled, style=color)
    text.append("." * empty, style="dim")
    return text


def show_dashboard() -> None:
    hostname = platform.node()
    kernel = platform.release()
    arch = platform.machine()

    try:
        with open("/etc/os-release") as f:
            os_info = {}
            for line in f:
                if "=" in line:
                    k, _, v = line.strip().partition("=")
                    os_info[k] = v.strip('"')
        os_name = os_info.get("PRETTY_NAME", "")
    except FileNotFoundError:
        os_name = ""

    cpu_model = ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_model = line.split(":")[1].strip()
                    break
    except FileNotFoundError:
        pass

    cpu_cores = psutil.cpu_count()
    load_avg = psutil.getloadavg()
    cpu_percent = psutil.cpu_percent(interval=1)

    uptime_result = run("uptime -p 2>/dev/null | sed 's/up //'")
    uptime_str = uptime_result.output if uptime_result.ok else ""

    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()

    public_ip = get_public_ip()
    local_ip = ""
    hostname_i = run("hostname -I 2>/dev/null")
    if hostname_i.ok:
        local_ip = hostname_i.output.split()[0] if hostname_i.output else ""

    docker_running, docker_total = get_docker_status()

    console.print()
    console.print(Panel.fit(
        f"[bold]{hostname}[/bold]  [dim]{os_name} | {kernel} ({arch})[/dim]",
        border_style="cyan",
    ))

    console.print(f"  [dim]CPU:[/dim] {cpu_model[:40]} {cpu_cores}cores | "
                  f"[dim]Load:[/dim] {load_avg[0]:.2f} {load_avg[1]:.2f} {load_avg[2]:.2f} | "
                  f"[dim]Uptime:[/dim] {uptime_str}")

    console.print()

    cpu_bar = make_bar(cpu_percent)
    ram_percent = ram.percent
    ram_bar = make_bar(ram_percent)
    ram_used_mb = ram.used // (1024 * 1024)
    ram_total_mb = ram.total // (1024 * 1024)

    console.print(f"  [dim]CPU:[/dim] {cpu_percent:5.1f}% {cpu_bar}")
    console.print(f"  [dim]RAM:[/dim] {ram_used_mb}M/{ram_total_mb}M {ram_bar}")

    if swap.total > 0:
        swap_percent = swap.percent
        swap_bar = make_bar(swap_percent)
        swap_used_mb = swap.used // (1024 * 1024)
        swap_total_mb = swap.total // (1024 * 1024)
        console.print(f"  [dim]SWP:[/dim] {swap_used_mb}M/{swap_total_mb}M {swap_bar}")

    console.print()
    console.print("  [bold cyan]─── Disk ───────────────────────────────────────────────[/bold cyan]")

    disk_result = run("df -h --type=ext4 --type=xfs --type=btrfs --type=zfs 2>/dev/null")
    if disk_result.ok:
        for line in disk_result.output.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6 and not parts[0].startswith("tmpfs"):
                mount = parts[5]
                used = parts[2]
                avail = parts[3]
                use_pct = parts[4]
                size = parts[1]
                console.print(f"  {mount:<14} {used:>5} {avail:>5} {use_pct:>5} {size}")

    console.print()
    console.print("  [bold cyan]─── Network & Docker ───────────────────────────────────[/bold cyan]")
    console.print(f"  [dim]Pub IP:[/dim] {public_ip:<15} [dim]Loc IP:[/dim] {local_ip}")
    console.print(f"  [dim]Docker:[/dim] {docker_running}/{docker_total} containers running")
    console.print()
