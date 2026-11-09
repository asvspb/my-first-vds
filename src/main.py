#!/usr/bin/env python3
import typer
from typing import Optional

from src.core.logger import setup_logger

setup_logger("src")

app = typer.Typer(
    name="vds",
    help="VDS Management & ZeroTier Orchestrator",
    add_completion=False,
    invoke_without_command=True,
)

zerotier_app = typer.Typer(help="ZeroTier VPN management")
wireguard_app = typer.Typer(help="WireGuard VPN management")
coturn_app = typer.Typer(help="Coturn TURN server management")
gateway_app = typer.Typer(help="Gateway state management")
xray_app = typer.Typer(help="Xray VLESS Reality gateway (TCP 443)")
hysteria2_app = typer.Typer(help="Hysteria2 QUIC gateway (UDP 443)")
acme_app = typer.Typer(help="ACME / Let's Encrypt certificates (certbot, HTTP-01)")
app.add_typer(zerotier_app, name="zerotier")
app.add_typer(wireguard_app, name="wireguard")
app.add_typer(coturn_app, name="coturn")
app.add_typer(gateway_app, name="gateway")
app.add_typer(xray_app, name="xray")
app.add_typer(hysteria2_app, name="hysteria2")
app.add_typer(acme_app, name="acme")

@app.callback(invoke_without_command=True)
def main_menu(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    import questionary
    from rich.console import Console
    console = Console()
    
    while True:
        console.clear()
        console.print("[bold cyan]═══ VDS Management Menu ═══[/bold cyan]\n")
        
        choice = questionary.select(
            "Что вы хотите сделать?",
            choices=[
                questionary.Choice("Системный статус (Dashboard)", "sysinfo"),
                questionary.Choice("Управление ZeroTier", "zerotier"),
                questionary.Choice("Управление WireGuard", "wireguard"),
                questionary.Choice("Управление Coturn (TURN)", "coturn"),
                questionary.Choice("Управление Xray (VLESS Reality)", "xray"),
                questionary.Choice("Управление Hysteria2 (QUIC, UDP 443)", "hysteria2"),
                questionary.Choice("Базовая настройка сервера (Setup)", "server_setup"),
                questionary.Choice("Очистка системы (Cleanup)", "cleanup"),
                questionary.Choice("Выход", "exit"),
            ]
        ).ask()
        
        if choice == "sysinfo":
            sysinfo()
            questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
        elif choice == "server_setup":
            try:
                server_setup()
            except typer.Exit:
                pass
            questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
        elif choice == "cleanup":
            try:
                cleanup(dry_run=False, aggressive=False)
            except typer.Exit:
                pass
            questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
        elif choice == "wireguard":
            wg_choice = questionary.select(
                "Меню WireGuard:",
                choices=[
                    questionary.Choice("Установка сервера (install)", "install"),
                    questionary.Choice("Добавить клиента (add-client)", "add_client"),
                    questionary.Choice("Удалить WireGuard (remove)", "remove"),
                    questionary.Choice("Назад", "back"),
                ]
            ).ask()
            
            if wg_choice == "install":
                try:
                    wg_install(port=51820, client="client", dns="8.8.8.8, 8.8.4.4")
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif wg_choice == "add_client":
                name = questionary.text("Имя нового клиента:", default="client2").ask()
                if name:
                    try:
                        wg_add_client(name=name)
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif wg_choice == "remove":
                if questionary.confirm("Удалить WireGuard?").ask():
                    try:
                        wg_remove()
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()

        elif choice == "coturn":
            ct_choice = questionary.select(
                "Меню Coturn:",
                choices=[
                    questionary.Choice("Установка TURN-сервера (install)", "install"),
                    questionary.Choice("Статус и конфигурация (status)", "status"),
                    questionary.Choice("Удалить Coturn (remove)", "remove"),
                    questionary.Choice("Назад", "back"),
                ]
            ).ask()

            if ct_choice == "install":
                user = questionary.text("Логин для TURN:", default="admin").ask() or "admin"
                pwd = questionary.text("Пароль (пусто = автогенерация):", default="").ask()
                try:
                    coturn_install(username=user, password=pwd)
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif ct_choice == "status":
                try:
                    coturn_status()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif ct_choice == "remove":
                if questionary.confirm("Удалить Coturn?").ask():
                    try:
                        coturn_remove()
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()

        elif choice == "xray":
            xray_choice = questionary.select(
                "Меню Xray:",
                choices=[
                    questionary.Choice("Установка (install)", "install"),
                    questionary.Choice("Добавить клиента (add-client)", "add_client"),
                    questionary.Choice("Статус (status)", "status"),
                    questionary.Choice("Удалить Xray (remove)", "remove"),
                    questionary.Choice("Назад", "back"),
                ]
            ).ask()

            if xray_choice == "install":
                sni = questionary.text("SNI для Reality:", default="www.google.com").ask()
                try:
                    xray_install(sni=sni or "www.google.com")
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif xray_choice == "add_client":
                name = questionary.text("Имя нового клиента:").ask()
                if name:
                    try:
                        xray_add_client(name=name)
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif xray_choice == "status":
                try:
                    xray_status()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif xray_choice == "remove":
                if questionary.confirm("Удалить Xray полностью?").ask():
                    try:
                        xray_remove(apply=True)
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()

        elif choice == "hysteria2":
            hy_choice = questionary.select(
                "Меню Hysteria2:",
                choices=[
                    questionary.Choice("Установка (install)", "install"),
                    questionary.Choice("Добавить клиента (add-client)", "add_client"),
                    questionary.Choice("Статус (status)", "status"),
                    questionary.Choice("Удалить Hysteria2 (remove)", "remove"),
                    questionary.Choice("Назад", "back"),
                ]
            ).ask()

            if hy_choice == "install":
                try:
                    hysteria2_install()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif hy_choice == "add_client":
                name = questionary.text("Имя нового клиента:").ask()
                if name:
                    try:
                        hysteria2_add_client(name=name)
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif hy_choice == "status":
                try:
                    hysteria2_status()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif hy_choice == "remove":
                if questionary.confirm("Удалить Hysteria2 полностью?").ask():
                    try:
                        hysteria2_remove(apply=True)
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()

        elif choice == "zerotier":
            zt_choice = questionary.select(
                "Меню ZeroTier:",
                choices=[
                    questionary.Choice("Диагностика (status/diagnose)", "diagnose"),
                    questionary.Choice("Синхронизация сетей (reconcile)", "reconcile"),
                    questionary.Choice("Подключить новую сеть (add-network)", "add_network"),
                    questionary.Choice("Восстановление NAT (nat)", "nat"),
                    questionary.Choice("Запуск Watchdog (watchdog)", "watchdog"),
                    questionary.Choice("Установка (install)", "install"),
                    questionary.Choice("Полное удаление (cleanup)", "cleanup"),
                    questionary.Choice("Назад", "back"),
                ]
            ).ask()
            
            if zt_choice == "diagnose":
                try:
                    zt_diagnose(fix=False, yes=False)
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif zt_choice == "reconcile":
                import os
                if not os.path.exists("/opt/ztnet/topology.json"):
                    if questionary.confirm("Файл topology.json не найден. Сгенерировать его сейчас?").ask():
                        try:
                            zt_reconcile(apply=False, init=True, validate=False)
                        except typer.Exit:
                            pass
                    else:
                        questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
                        continue
                
                rec_action = questionary.select(
                    "Действие Reconcile:",
                    choices=[
                        questionary.Choice("Проверка (Dry Run)", "dry"),
                        questionary.Choice("Применить изменения (Apply)", "apply"),
                        questionary.Choice("Обновить файл из текущего состояния (Init)", "init"),
                    ]
                ).ask()
                
                try:
                    if rec_action == "dry":
                        zt_reconcile(apply=False, init=False, validate=False)
                    elif rec_action == "apply":
                        zt_reconcile(apply=True, init=False, validate=False)
                    elif rec_action == "init":
                        if questionary.confirm("ВНИМАНИЕ: Это перезапишет topology.json. Продолжить?").ask():
                            zt_reconcile(apply=False, init=True, validate=False)
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif zt_choice == "add_network":
                try:
                    zt_add_network()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif zt_choice == "nat":
                try:
                    zt_nat()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif zt_choice == "watchdog":
                try:
                    zt_watchdog()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif zt_choice == "install":
                try:
                    zt_install(port=3000)
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif zt_choice == "cleanup":
                if questionary.confirm("Удалить ZeroTier?").ask():
                    try:
                        zt_cleanup()
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
        elif choice == "exit" or choice is None:
            break


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


@app.command()
def server_setup():
    """Базовая первичная настройка сервера (Python)"""
    from src.system.setup import run_setup
    raise typer.Exit(run_setup())


@gateway_app.command("status")
def gateway_status():
    """Показать состояние gateway (файл state.json, клиенты, протоколы)"""
    from src.core.logger import console
    from src.gateway.paths import STATE_PATH
    from src.gateway.store import StoreError, load_state

    console.print(f"[info][gateway][/info] Файл состояния: {STATE_PATH}")
    try:
        state = load_state()
    except StoreError as exc:
        console.print(f"[error][gateway] {exc}[/error]")
        raise typer.Exit(1)

    if not state.clients and not state.protocols:
        console.print("[warning][gateway] Состояние пусто: протоколы не установлены.[/warning]")
        return

    console.print(
        f"[info] Версия:[/info] {state.version}  "
        f"[info]Домен:[/info] {state.domain or '—'}"
    )
    for client in state.clients:
        console.print(
            f"  [change]-[/change] {client.name} ({client.protocol}, port {client.port})"
        )
    for proto, meta in state.protocols.items():
        installed = meta.get("installed", False)
        console.print(
            f"  [info]*[/info] {proto}: "
            f"{'[success]installed[/success]' if installed else '[warning]not installed[/warning]'}"
        )


@xray_app.command("install")
def xray_install(
    sni: str = typer.Option("www.google.com", "--sni", help="SNI для Reality (dest/serverNames)"),
):
    """Установить Xray VLESS Reality (TCP 443)"""
    from src.xray.install import run_install
    raise typer.Exit(run_install(sni=sni))


@xray_app.command("add-client")
def xray_add_client(
    name: str = typer.Argument(..., help="Имя нового клиента"),
    transport: str = typer.Option(
        "reality", "--transport", help="reality (по умолчанию) или xhttp"
    ),
):
    """Добавить клиента и показать share-link (Reality или XHTTP)"""
    from src.core.logger import console
    from src.gateway.store import StoreError
    from src.xray.clients import XrayError, add_client

    try:
        result = add_client(name, transport=transport)
    except (StoreError, XrayError) as exc:
        console.print(f"[error][xray] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(0 if result else 1)


@xray_app.command("status")
def xray_status():
    """Статус Xray: юнит, валидность конфига, порт, ошибки journal"""
    from src.xray.status import run_status
    raise typer.Exit(run_status())


@xray_app.command("remove")
def xray_remove(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Удалить Xray (юнит, конфиг, бинарь+geodata, клиенты из store)"""
    from src.xray.remove import run_remove
    raise typer.Exit(run_remove(apply=apply))


@xray_app.command("add-transport")
def xray_add_transport(
    transport: str = typer.Argument(..., help="Транспорт: xhttp"),
    domain: str = typer.Option(..., "--domain", help="Домен с LE-сертификатом (`vds acme issue`)"),
    mode: str = typer.Option(
        "fallback",
        "--mode",
        help="fallback: SNI-разделение за Reality на 443; port: публичный 8443",
    ),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
    yes: bool = typer.Option(False, "--yes", help="Без интерактивного подтверждения"),
):
    """Добавить XHTTP-транспорт к живому Xray (ADR-003, SPEC WP-3)"""
    from src.xray.install import run_add_transport_xhttp
    raise typer.Exit(
        run_add_transport_xhttp(transport, domain, mode=mode, apply=apply, yes=yes)
    )


@xray_app.command("remove-transport")
def xray_remove_transport(
    transport: str = typer.Argument(..., help="Транспорт: xhttp"),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
    yes: bool = typer.Option(False, "--yes", help="Без интерактивного подтверждения"),
):
    """Снять XHTTP-транспорт (fallbacks + инблэнд + XHTTP-клиенты, ADR-003)"""
    from src.core.logger import console
    from src.xray.remove import remove_transport_xhttp

    if transport != "xhttp":
        console.print(
            f"[error][xray] Неизвестный транспорт {transport!r} "
            "(поддерживается: xhttp).[/error]"
        )
        raise typer.Exit(1)
    raise typer.Exit(remove_transport_xhttp(apply=apply, yes=yes))


@xray_app.command("use-domain")
def xray_use_domain(
    domain: str = typer.Option(
        ..., "--domain", help="Домен, A-запись которого резолвится в публичный IP сервера"
    ),
):
    """Адрес Reality share-links = домен (state.domain); dest/serverNames не меняются (SPEC WP-4)"""
    from src.core.logger import console
    from src.gateway.store import StoreError
    from src.xray.clients import XrayError, use_domain

    try:
        use_domain(domain)
    except (StoreError, XrayError) as exc:
        console.print(f"[error][xray] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(0)


@hysteria2_app.command("install")
def hysteria2_install(
    port: int = typer.Option(443, "--port", help="UDP-порт QUIC"),
):
    """Установить Hysteria2 (QUIC, UDP 443, self-signed без домена)"""
    from src.hysteria2.install import run_install
    raise typer.Exit(run_install(port=port))


@hysteria2_app.command("add-client")
def hysteria2_add_client(
    name: str = typer.Argument(..., help="Имя нового клиента"),
):
    """Добавить клиента и показать share-link Hysteria2"""
    from src.core.logger import console
    from src.gateway.store import StoreError
    from src.hysteria2.clients import Hysteria2Error, add_client

    try:
        result = add_client(name)
    except (StoreError, Hysteria2Error) as exc:
        console.print(f"[error][hysteria2] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(0 if result else 1)


@hysteria2_app.command("status")
def hysteria2_status():
    """Статус Hysteria2: юнит, UDP-порт, сертификат, ошибки journal"""
    from src.hysteria2.status import run_status
    raise typer.Exit(run_status())


@hysteria2_app.command("apply-cert")
def hysteria2_apply_cert(
    apply: bool = typer.Option(False, "--apply", help="Применить LE-сертификат (по умолчанию dry-run)"),
    restore: bool = typer.Option(False, "--restore", help="Откат к self-signed из бэкапа .bak-pre-le"),
):
    """Подменить self-signed сертификат Hysteria2 на LE (dry-run по умолчанию)"""
    from src.acme.apply_cert import run_apply
    raise typer.Exit(run_apply(apply=apply, restore=restore))


@hysteria2_app.command("remove")
def hysteria2_remove(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Удалить Hysteria2 (юнит, конфиг, сертификаты, бинарь, клиенты из store)"""
    from src.hysteria2.remove import run_remove
    raise typer.Exit(run_remove(apply=apply))


@acme_app.command("issue")
def acme_issue(
    domain: str = typer.Option(..., "--domain", help="Домен, резолвящийся в публичный IP сервера"),
    email: str = typer.Option(..., "--email", help="Email для аккаунта Let's Encrypt"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Показать план без изменений"),
):
    """Выпустить LE-сертификат на домен (HTTP-01, порт 80) + deploy-hook"""
    from src.acme.install import run_issue
    raise typer.Exit(run_issue(domain=domain, email=email, dry_run=dry_run))


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


@zerotier_app.command("add-network")
def zt_add_network():
    """Добавление новой сети к существующей установке ZTNET"""
    from src.zerotier.add_network import run_add_network
    raise typer.Exit(run_add_network())


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


@coturn_app.command("install")
def coturn_install(
    username: str = typer.Option("admin", "--user", "-u", help="Логин для TURN"),
    password: str = typer.Option("", "--password", "-p", help="Пароль (пусто = автогенерация)"),
    realm: str = typer.Option("private-cinema.local", "--realm", help="Realm"),
    port: int = typer.Option(3478, "--port", help="Порт TURN"),
):
    """Установить Coturn TURN сервер"""
    from src.coturn.install import run_install
    raise typer.Exit(run_install(username=username, password=password, realm=realm, port=port))


@coturn_app.command("status")
def coturn_status():
    """Показать статус и конфигурацию Coturn"""
    from src.coturn.install import run_status
    raise typer.Exit(run_status())


@coturn_app.command("remove")
def coturn_remove():
    """Удалить Coturn"""
    from src.coturn.install import run_remove
    raise typer.Exit(run_remove())


if __name__ == "__main__":
    app()
