import json
import logging
import os
import subprocess
from typing import Optional

from src.core.shell import run, docker_exec, docker_inspect, systemctl, command_exists
from src.core.lock import FileLock
from src.core.logger import console
from src.zerotier.api import ZeroTierAPI
from src.zerotier.nat import load_env, get_main_iface

logger = logging.getLogger(__name__)

INSTALL_DIR = os.environ.get("INSTALL_DIR", "/opt/ztnet")
ENV_FILE = os.path.join(INSTALL_DIR, ".env.info")
LOCK_FILE = "/var/run/ztnet-diagnose.lock"
CONTAINER = "ztnet_zerotier"


def zt_is_docker() -> bool:
    result = run("docker ps --format '{{.Names}}' 2>/dev/null")
    return CONTAINER in result.output if result.ok else False


def zt_exec_cmd(command: str) -> str:
    if zt_is_docker():
        result = docker_exec(CONTAINER, command)
    else:
        result = run(f"zerotier-cli {command}")
    return result.output if result.ok else ""


def get_authtoken() -> str:
    if zt_is_docker():
        result = docker_exec(CONTAINER, "cat /var/lib/zerotier-one/authtoken.secret")
    else:
        result = run("cat /var/lib/zerotier-one/authtoken.secret 2>/dev/null")
    return result.output.replace(" ", "").replace("\n", "") if result.ok else ""


def get_zt_addr() -> str:
    info = zt_exec_cmd("info")
    parts = info.split()
    return parts[2] if len(parts) >= 3 else ""


def run_diagnose(fix: bool = False, auto_yes: bool = False) -> int:
    lock = FileLock(LOCK_FILE)
    if not lock.acquire():
        console.print("[error]Другой экземпляр диагностики уже запущен[/error]")
        return 1

    try:
        critical = 0
        warnings = 0

        console.print("\n[info]═══ ZeroTier + ZTNET — Диагностика ═══[/info]\n")

        api = ZeroTierAPI()
        env = load_env()

        # 1. Конфликт порта 9993
        console.print("[bold][1/8] Конфликт порта 9993[/bold]")
        sys_zt_active = systemctl("is-active", "zerotier-one").ok
        if sys_zt_active:
            console.print("[error][XX] Системный zerotier-one АКТИВЕН[/error]")
            critical += 1
            if fix:
                systemctl("stop", "zerotier-one")
                systemctl("disable", "zerotier-one")
                systemctl("mask", "zerotier-one")
                run("pkill -9 -x zerotier-one 2>/dev/null")
                console.print("[success]Системный zerotier-one остановлен и замаскирован[/success]")
        else:
            console.print("[success][OK] Системный zerotier-one не активен[/success]")

        # 2. Docker контейнеры
        console.print("\n[bold][2/8] Docker-контейнеры ZTNET[/bold]")
        for svc in ["ztnet", "ztnet_postgres", "ztnet_zerotier"]:
            status = docker_inspect(svc, "{{.State.Status}}")
            health = docker_inspect(svc, "{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}")
            restarts = docker_inspect(svc, "{{.RestartCount}}")

            if status == "running":
                if health == "healthy":
                    console.print(f"[success][OK] {svc}: running (healthy, restarts: {restarts})[/success]")
                else:
                    console.print(f"[warning][!!] {svc}: running (health: {health})[/warning]")
                    warnings += 1
            elif status == "missing" or not status:
                console.print(f"[error][XX] {svc}: КОНТЕЙНЕР НЕ НАЙДЕН[/error]")
                critical += 1
            else:
                console.print(f"[error][XX] {svc}: {status} (health: {health})[/error]")
                critical += 1

        # 3. ZeroTier демон
        console.print("\n[bold][3/8] ZeroTier демон[/bold]")
        zt_info = zt_exec_cmd("info")
        if not zt_info:
            console.print("[error][XX] ZeroTier демон не отвечает[/error]")
            critical += 1
        else:
            zt_status = ""
            for word in zt_info.split():
                if word in ("ONLINE", "OFFLINE", "TUNNELED", "DEGRADED"):
                    zt_status = word
                    break
            if zt_status == "ONLINE":
                console.print(f"[success][OK] Статус: {zt_status}[/success]")
            elif zt_status == "TUNNELED":
                console.print(f"[warning][!!] Статус: TUNNELED — UDP заблокирован[/warning]")
                warnings += 1
            else:
                console.print(f"[warning][!!] Статус: {zt_status}[/warning]")
                warnings += 1

        # 4. TUN/TAP
        console.print("\n[bold][4/8] TUN/TAP устройство[/bold]")
        if zt_is_docker():
            tun_check = docker_exec(CONTAINER, "ls -la /dev/net/tun")
            if tun_check.ok:
                console.print("[success][OK] /dev/net/tun доступен в контейнере[/success]")
            else:
                console.print("[error][XX] /dev/net/tun НЕ доступен в контейнере[/error]")
                critical += 1

        host_tun = os.path.exists("/dev/net/tun")
        if host_tun:
            console.print("[success][OK] /dev/net/tun существует на хосте[/success]")
        else:
            console.print("[warning][!!] /dev/net/tun не найден на хосте[/warning]")
            warnings += 1

        # 5. Сети
        console.print("\n[bold][5/8] Сети и маршруты[/bold]")
        networks_json = zt_exec_cmd("-j listnetworks")
        if networks_json:
            try:
                nets = json.loads(networks_json)
                for n in nets:
                    status = n.get("status", "?")
                    nwid = n.get("id", "?")
                    name = n.get("name", "?")
                    ips = ", ".join(n.get("assignedAddresses", [])) or "no IP"
                    if status == "OK":
                        console.print(f"[success][OK] {nwid} ({name}): {status} ip={ips}[/success]")
                    elif status == "NOT_FOUND":
                        console.print(f"[error][XX] {nwid} ({name}): {status}[/error]")
                        critical += 1
                    else:
                        console.print(f"[warning][!!] {nwid} ({name}): {status}[/warning]")
                        warnings += 1
            except json.JSONDecodeError:
                console.print("[warning][!!] Не удалось распарсить список сетей[/warning]")
                warnings += 1
        else:
            console.print("[warning][!!] Нет подключённых сетей[/warning]")
            warnings += 1

        # 6. NAT / IP Forwarding
        console.print("\n[bold][6/8] NAT / IP Forwarding[/bold]")
        ip_fwd = run("sysctl -n net.ipv4.ip_forward 2>/dev/null").output
        if ip_fwd == "1":
            console.print("[success][OK] IP forwarding: включён[/success]")
        else:
            console.print("[error][XX] IP forwarding: ВЫКЛЮЧЕН[/error]")
            critical += 1
            if fix:
                run("sysctl -w net.ipv4.ip_forward=1")
                run("echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-zt-forward.conf")
                console.print("[success]IP forwarding включён[/success]")

        main_iface = env.get("MAIN_IFACE") or get_main_iface()
        all_subnets = env.get("ZT_SUBNETS") or env.get("ZT_SUBNET", "10.121.15.0/24")
        for sub in all_subnets.split(","):
            sub = sub.strip()
            if not sub:
                continue
            nat_check = run(f"iptables -t nat -L POSTROUTING -n 2>/dev/null | grep '{sub}'")
            if nat_check.ok and nat_check.output:
                console.print(f"[success][OK] NAT для {sub}: настроен[/success]")
            else:
                console.print(f"[error][XX] NAT для {sub}: ОТСУТСТВУЕТ[/error]")
                critical += 1

        # 7. UFW
        console.print("\n[bold][7/8] UFW Firewall[/bold]")
        if command_exists("ufw"):
            ufw_status = run("ufw status 2>/dev/null").output
            if "active" in ufw_status:
                if "9993" in ufw_status:
                    console.print("[success][OK] UFW: порт 9993 открыт[/success]")
                else:
                    console.print("[error][XX] UFW активен, но порт 9993 НЕ открыт[/error]")
                    critical += 1
                    if fix:
                        run("ufw allow 9993/udp")
                        run("ufw allow 9993/tcp")
                        console.print("[success]Порт 9993 открыт в UFW[/success]")
            else:
                console.print("[warning][!!] UFW не активен[/warning]")
                warnings += 1
        else:
            console.print("[warning][!!] UFW не установлен[/warning]")

        # 8. Персистентность
        console.print("\n[bold][8/8] Персистентность[/bold]")
        if os.path.isfile("/etc/iptables/rules.v4"):
            console.print("[success][OK] /etc/iptables/rules.v4 существует[/success]")
        else:
            console.print("[error][XX] /etc/iptables/rules.v4 НЕ найден[/error]")
            critical += 1
            if fix:
                run("mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4")

        if os.path.isfile("/etc/sysctl.d/99-zt-forward.conf"):
            console.print("[success][OK] sysctl ip_forward сохранён[/success]")
        else:
            console.print("[error][XX] sysctl ip_forward НЕ сохранён[/error]")
            critical += 1
            if fix:
                run("echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-zt-forward.conf")

        # Итог
        console.print("\n[info]═══ Итог ═══[/info]")
        if critical == 0 and warnings == 0:
            console.print("[success]Всё в порядке — проблем не обнаружено[/success]")
        elif critical == 0:
            console.print(f"[warning]Предупреждений: {warnings} — рекомендуется устранить[/warning]")
        else:
            console.print(f"[error]Критических: {critical}, предупреждений: {warnings}[/error]")

        return 0 if critical == 0 else 1
    finally:
        lock.release()
