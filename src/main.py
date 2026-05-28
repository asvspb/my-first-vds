#!/usr/bin/env python3
import typer
from typing import Optional

from src.core.logger import setup_logger

setup_logger("src")

app = typer.Typer(
    name="vds",
    help="VDS Management & ZeroTier Orchestrator",
    add_completion=False,
)

zerotier_app = typer.Typer(help="ZeroTier VPN management")
wireguard_app = typer.Typer(help="WireGuard VPN management")
app.add_typer(zerotier_app, name="zerotier")
app.add_typer(wireguard_app, name="wireguard")


@app.command()
def sysinfo():
    """Показать статус сервера (CPU, RAM, Docker, Disk)"""
    from src.sysinfo.dashboard import show_dashboard
    show_dashboard()


@app.command()
def cleanup(
    dry_run: bool = typer.Option(False, "--dry-run", help="Показать что будет удалено без удаления"),
    aggressive: bool = typer.Option(False, "--aggressive", help="Агрессивная очистка Docker"),
):
    """Системная очистка сервера (apt, Docker, логи, /tmp)"""
    from src.system.cleanup import run_cleanup
    raise typer.Exit(run_cleanup(dry_run=dry_run, safe_docker=not aggressive))


@zerotier_app.command("install")
def zt_install(
    port: int = typer.Option(3000, "--port", help="Порт ZTNET Panel"),
):
    """Установить ZeroTier + ZTNET Panel + Internet Gateway"""
    from src.zerotier.install import run_install
    raise typer.Exit(run_install(ztnet_port=port))


@zerotier_app.command("status")
def zt_status():
    """Показать статус ZeroTier (сети, пиры, NAT)"""
    from src.zerotier.diagnose import run_diagnose
    raise typer.Exit(run_diagnose(fix=False))


@zerotier_app.command("diagnose")
def zt_diagnose(
    fix: bool = typer.Option(False, "--fix", help="Интерактивное исправление проблем"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Автоисправление без подтверждения"),
):
    """Диагностика ZeroTier + ZTNET с возможностью исправления"""
    from src.zerotier.diagnose import run_diagnose
    raise typer.Exit(run_diagnose(fix=fix, auto_yes=yes))


@zerotier_app.command("reconcile")
def zt_reconcile(
    apply: bool = typer.Option(False, "--apply", help="Применить изменения (по умолчанию dry-run)"),
    init: bool = typer.Option(False, "--init", help="Сгенерировать topology.json из текущего состояния"),
    validate: bool = typer.Option(False, "--validate", help="Проверить корректность topology.json"),
):
    """Синхронизировать состояние ZeroTier с topology.json"""
    from src.zerotier.reconcile import run_reconcile
    raise typer.Exit(run_reconcile(apply=apply, init=init, validate=validate))


@zerotier_app.command("watchdog")
def zt_watchdog():
    """Фоновый мониторинг и восстановление ZeroTier"""
    from src.zerotier.watchdog import run_watchdog
    raise typer.Exit(run_watchdog())


@zerotier_app.command("nat")
def zt_nat():
    """Восстановить NAT правила для всех ZeroTier сетей"""
    from src.zerotier.nat import setup_nat_all
    raise typer.Exit(setup_nat_all())


@zerotier_app.command("cleanup")
def zt_cleanup():
    """Полное удаление ZeroTier + ZTNET"""
    from src.zerotier.cleanup import run_cleanup
    raise typer.Exit(run_cleanup())


@wireguard_app.command("install")
def wg_install(
    port: int = typer.Option(51820, "--port", help="Порт WireGuard"),
    client: str = typer.Option("client", "--client", help="Имя первого клиента"),
    dns: str = typer.Option("8.8.8.8, 8.8.4.4", "--dns", help="DNS сервер для клиента"),
):
    """Установить WireGuard VPN сервер"""
    from src.wireguard.install import run_install
    raise typer.Exit(run_install(port=port, client_name=client, dns=dns))


@wireguard_app.command("add-client")
def wg_add_client(
    name: str = typer.Option("client", "--name", help="Имя нового клиента"),
):
    """Добавить нового клиента WireGuard"""
    from src.wireguard.install import add_client
    raise typer.Exit(add_client(client_name=name))


@wireguard_app.command("remove")
def wg_remove():
    """Удалить WireGuard"""
    from src.wireguard.install import remove
    raise typer.Exit(remove())


if __name__ == "__main__":
    app()
