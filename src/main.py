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
amneziawg_app = typer.Typer(help="AmneziaWG gateway (obfuscated WireGuard, UDP 51825)")
acme_app = typer.Typer(help="ACME / Let's Encrypt certificates (certbot, HTTP-01)")
relay_app = typer.Typer(
    help="RU-relay (ADR-007): AWG udp/443 + Reality tcp/443 + policy-routing до asv1; "
    "exit-leg — выделенная нога awg2 на exit-узле (ADR-015, P24)"
)
relay_exit_leg_app = typer.Typer(
    help=(
        "Exit-узел (ADR-015, P24): выделенная нога awg2 (10.11.0.0/30) + пул "
        "51900-51911/udp только с IP релея; dry-run по умолчанию"
    ),
    no_args_is_help=True,
)
relay_maneuver_app = typer.Typer(
    help=(
        "Локальный манёвр ноги relay→exit (ADR-015, P25): runtime awg set, "
        "liveness, anti-ping-pong; dry-run по умолчанию"
    ),
    no_args_is_help=True,
)
relay_wstunnel_app = typer.Typer(
    help=(
        "Носитель №2 p2p (ADR-016): wstunnel WSS/TLS + WG; вендоринг бинарника "
        "с пиннингом версии/SHA256, env-файлы секретов, юниты"
    ),
    no_args_is_help=True,
)
relay_app.add_typer(relay_exit_leg_app, name="exit-leg")
relay_app.add_typer(relay_maneuver_app, name="maneuver")
relay_carrier_app = typer.Typer(
    help=(
        "Селектор носителей p2p (ADR-016, WP-P2P-3): table 100 -> awg1|wg-ws0, "
        "state primary/fallback/exhausted; lock общий с манёвром P25"
    ),
    no_args_is_help=True,
)
relay_app.add_typer(relay_exit_leg_app, name="exit-leg")
relay_app.add_typer(relay_maneuver_app, name="maneuver")
relay_app.add_typer(relay_wstunnel_app, name="wstunnel")
relay_app.add_typer(relay_carrier_app, name="carrier")
probe_watch_app = typer.Typer(
    help="Монитор активного зондирования tcp/443 (И33 v1: nft counters + journal)"
)
probe_rucidr_app = typer.Typer(
    help="RU-CIDR-агрегат для exit-серверов без релея (SPEC-20261116-probe-response §3)"
)
system_app = typer.Typer(help="Системные утилиты: очистка, первичная настройка, файрвол UFW")
ufw_app = typer.Typer(
    help="UFW hardening (SPEC-20261116): dry-run по умолчанию, --apply для изменений"
)
logs_app = typer.Typer(
    help=(
        "Log-forensics (SPEC-20261116-log-forensics, ADR-012): телеметрия 5 мин, "
        "правила T-01..T-17, baseline, bounded pcap; dry-run по умолчанию"
    )
)
logs_capture_app = typer.Typer(
    help="Bounded pcap-захват tcp/443 (metadata-only, TTL 7 дней, §8.1)"
)
logs_app.add_typer(logs_capture_app, name="capture")
alert_app = typer.Typer(
    help=(
        "Сторож угрозы на exit-узле (SPEC-20261117-alert-watch): threat/пульс "
        "плеча/лок 443 → Telegram/SMTP. Только уведомления; dry-run по умолчанию"
    )
)
dms_app = typer.Typer(
    help=(
        "DMS — dead-man-switch пинг Healthchecks (SPEC-20261124-quiet-exit §5, "
        "P37): исходящий HTTPS с gate на живых ногах, /fail при мёртвой ноге. "
        "dry-run по умолчанию"
    )
)
app.add_typer(zerotier_app, name="zerotier")
app.add_typer(wireguard_app, name="wireguard")
app.add_typer(coturn_app, name="coturn")
app.add_typer(gateway_app, name="gateway")
app.add_typer(xray_app, name="xray")
app.add_typer(hysteria2_app, name="hysteria2")
app.add_typer(amneziawg_app, name="amneziawg")
app.add_typer(acme_app, name="acme")
app.add_typer(relay_app, name="relay")
app.add_typer(system_app, name="system")
system_app.add_typer(ufw_app, name="ufw")
gateway_app.add_typer(probe_watch_app, name="probe-watch")
probe_watch_app.add_typer(probe_rucidr_app, name="ru-cidr")
app.add_typer(logs_app, name="logs")
app.add_typer(alert_app, name="alert")
app.add_typer(dms_app, name="dms")

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
                questionary.Choice("Управление AmneziaWG (UDP 51825)", "amneziawg"),
                questionary.Choice("Управление RU-relay (ADR-007)", "relay"),
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

        elif choice == "amneziawg":
            awg_choice = questionary.select(
                "Меню AmneziaWG:",
                choices=[
                    questionary.Choice("Установка (install)", "install"),
                    # add-client / status / remove — WP-3/WP-4 (SPEC §7)
                    questionary.Choice("Назад", "back"),
                ]
            ).ask()

            if awg_choice == "install":
                try:
                    amneziawg_install()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()

        elif choice == "relay":
            relay_choice = questionary.select(
                "Меню RU-relay:",
                choices=[
                    questionary.Choice("Развёртывание релея (init, dry-run по умолчанию)", "init"),
                    questionary.Choice("Статус (status)", "status"),
                    questionary.Choice("Добавить клиента (add-client)", "add_client"),
                    questionary.Choice("Удалить клиента (remove-client)", "remove_client"),
                    questionary.Choice("Назад", "back"),
                ]
            ).ask()

            if relay_choice == "init":
                exit_ip = questionary.text("Exit-сервер (asv1 IPv4):", default="103.45.247.172").ask() or ""
                domain = questionary.text("Домен релея:", default="relay.asvpersonal.ru").ask() or ""
                sni = questionary.text("SNI Reality (RU-сайт same-DC):").ask() or ""
                try:
                    relay_init(exit_ip=exit_ip, domain=domain, sni=sni)
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif relay_choice == "status":
                try:
                    relay_status()
                except typer.Exit:
                    pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif relay_choice == "add_client":
                name = questionary.text("Имя клиента:", default="phone").ask()
                if name:
                    try:
                        relay_add_client(name=name)
                    except typer.Exit:
                        pass
                questionary.press_any_key_to_continue("Нажмите любую клавишу для возврата...").ask()
            elif relay_choice == "remove_client":
                name = questionary.text("Имя клиента для удаления:", default="phone").ask()
                if name:
                    try:
                        relay_remove_client(name=name, apply=questionary.confirm("Применить удаление (--apply)?", default=False).ask() or False)
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


@gateway_app.command("blockcheck")
def gateway_blockcheck(
    timeout: float = typer.Option(30.0, "--timeout", help="Таймаут внешних проб (сек)"),
    json_output: bool = typer.Option(
        False, "--json", help="Machine-readable вывод (experimental)"
    ),
):
    """Диагностика «блок нашего IP» vs «глобальная деградация» vs «локальная
    проблема»: локальная проба + внешний check-host.net + контрольный хост.
    Offline/сбой API -> вердикт unknown, exit 0 (не ошибка)."""
    import json as _json

    from src.core.logger import console
    from src.core.netcheck import run_blockcheck

    verdict, evidence = run_blockcheck(timeout=timeout)
    if json_output:
        print(_json.dumps({"verdict": verdict, "evidence": evidence}, ensure_ascii=False))
        raise typer.Exit(0)

    tag = {
        "ok": "success",
        "ip_block_likely": "error",
        "ru_segment_block_likely": "warning",
        "global_degradation": "warning",
        "local_problem": "error",
        "unknown": "info",
    }[verdict]
    console.print(f"[{tag}][blockcheck] Вердикт: {verdict}[/{tag}]")

    target = evidence.get("target") or {}
    control = evidence.get("control") or {}
    console.print("[info][blockcheck] Evidences:[/info]")
    console.print(
        f"  - local tcp {evidence.get('public_ip') or '?'}:443: "
        f"{evidence.get('local_tcp_ok')} (vds-xray active: {evidence.get('unit_active')})"
    )
    if target:
        console.print(
            f"  - target (наш IP): RU ok {target.get('ru_ok')}/{target.get('ru_total')}, "
            f"мир ok {target.get('world_ok')}/{target.get('world_total')}"
        )
    else:
        console.print("  - target (наш IP): внешняя проба недоступна")
    if control:
        console.print(
            f"  - control ({'93.184.216.34'}): RU ok {control.get('ru_ok')}/{control.get('ru_total')}, "
            f"мир ok {control.get('world_ok')}/{control.get('world_total')}"
        )
    else:
        console.print("  - control: внешняя проба недоступна")

    advice = {
        "ok": "IP-блок маловероятен; недоступность у клиента — блок "
        "сегмента клиента, не наш IP (CDN-канал должен жить).",
        "ip_block_likely": "Вероятен TSPU-блок нашего IP: используйте "
        "CDN-канал/фронт или ротацию IP.",
        "ru_segment_block_likely": "Блок на RU-сегменте: direct-каналы под "
        "вопросом, CDN должен жить.",
        "global_degradation": "Внешний сервис/мир деградировал — не "
        "различимо с блоком; повторите позже.",
        "local_problem": "Сервис жив извне, локально нет: проверьте юнит/"
        "порт (`vds xray status`).",
        "unknown": "Недостаточно данных (API недоступен/offline); вердикт "
        "не вынесен.",
    }[verdict]
    console.print(f"[info][blockcheck] Рекомендация:[/info] {advice}")
    raise typer.Exit(0)


@gateway_app.command("healthcheck")
def gateway_healthcheck(
    restart: bool = typer.Option(
        True,
        "--restart/--no-restart",
        help="Рестартовать упавшие юниты (rate-limit: 3/час на юнит)",
    ),
    install_timer: bool = typer.Option(
        False,
        "--install-timer",
        help="Установить и запустить systemd-таймер vds-gateway-health.timer "
        "(healthcheck каждые 5 мин; root)",
    ),
    unit_mode: bool = typer.Option(
        False,
        "--unit",
        help="Режим из systemd-таймера: exit 0 всегда, кроме нечитаемого "
        "state.json (в ручном режиме exit 1 при error-находке)",
    ),
):
    """Проверка здоровья gateway: юниты, порты (по state), срок сертификата
    (<14 дн. warning, <7 error). Read-only, кроме рестарта упавшего юнита."""
    from src.core.logger import console
    from src.gateway.health import install_health_timer, run_healthcheck

    if install_timer:
        import os

        if os.geteuid() != 0:
            console.print(
                "[error][gateway] Установка таймера требует root (sudo).[/error]"
            )
            raise typer.Exit(1)
        if not install_health_timer():
            raise typer.Exit(1)
        return

    raise typer.Exit(run_healthcheck(restart=restart, unit_mode=unit_mode))


@gateway_app.command("init")
def gateway_init(
    protocols: str = typer.Option(
        "reality,hysteria2",
        "--protocols",
        help="CSV из reality,hysteria2,obfs,hop,xhttp,cdn,awg",
    ),
    domain: str = typer.Option(None, "--domain", help="Домен для ACME/CDN/ссылок"),
    email: str = typer.Option(None, "--email", help="Email Let's Encrypt (не сохраняется)"),
    sni: str = typer.Option("www.google.com", "--sni", help="SNI для Reality (dest/serverNames)"),
    hop_range: str = typer.Option(
        "20000-20500", "--hop-range", help="Диапазон port hopping при hop"
    ),
    cdn_domain: str = typer.Option(
        None, "--cdn-domain", help="Origin-домен CDN (по умолчанию = --domain)"
    ),
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
    demo_clients: bool = typer.Option(
        False, "--demo-clients", help="Создать phone/mob/laptop и напечатать ссылки"
    ),
    require_domain: bool = typer.Option(
        False,
        "--require-domain",
        help="Строгий режим: DNS не подтверждён → exit 1 вместо skip с warning",
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="Профиль развёртывания: quiet-exit (SPEC-20261124) — relay-only exit",
    ),
    relay_ip: Optional[str] = typer.Option(
        None, "--relay-ip",
        help="quiet-exit: IPv4 релея — allowlist 51900/udp + 9443/tcp (обязателен)",
    ),
    relay_pubkey: Optional[str] = typer.Option(
        None, "--relay-pubkey",
        help="quiet-exit: публичный ключ awg1 релея (без него exit-leg/wstunnel — pending)",
    ),
    ws_domain: Optional[str] = typer.Option(
        None, "--ws-domain", help="quiet-exit: домен сертификата wstunnel (ws.<domain>)"
    ),
    ws_prefix_file: Optional[str] = typer.Option(
        None, "--ws-prefix-file",
        help="quiet-exit: prefix-файл релея для wstunnel server (/etc/vds/wstunnel-client.env)",
    ),
):
    """Идемпотентное развёртывание gateway с нуля (SPEC-20261114):
    reality + hysteria2 (+obfs/hop/xhttp/cdn/awg) + healthcheck-таймер.
    Dry-run по умолчанию: план + проверки портов/DNS без мутаций.

    Профиль quiet-exit (SPEC-20261124): awg0 OOB-1 + UFW allowlist релея +
    ACME-окно 80/tcp + нога релея/wstunnel (pending без --relay-pubkey);
    прямые транспорты с --profile quiet-exit — fail-fast exit 2."""
    from src.gateway.init import run_init

    raise typer.Exit(
        run_init(
            protocols=protocols,
            domain=domain,
            email=email,
            sni=sni,
            hop_range=hop_range,
            cdn_domain=cdn_domain,
            apply=apply,
            demo_clients=demo_clients,
            require_domain=require_domain,
            profile=profile,
            relay_ip=relay_ip,
            relay_pubkey=relay_pubkey,
            ws_domain=ws_domain,
            ws_prefix_file=ws_prefix_file,
        )
    )


@gateway_app.command("links")
def gateway_links(
    protocol: str = typer.Option(
        None, "--protocol", help="Фильтр: xray | hysteria2 | amneziawg (по умолчанию все)"
    ),
    include_obfs: bool = typer.Option(
        False,
        "--include-obfs",
        help="Добавить obfs-ссылку hysteria2-клиентов (`<name>@obfs`, порт obfs-инстанса)",
    ),
):
    """Share-links всех клиентов из state (для `vpn profile pull` по ssh)"""
    from src.core.logger import console
    from src.gateway.links import render_all_links
    from src.gateway.store import StoreError

    try:
        links = render_all_links(protocol=protocol, include_obfs=include_obfs)
    except (StoreError, ValueError) as exc:
        console.print(f"[error][gateway] {exc}[/error]")
        raise typer.Exit(1)

    if not links:
        console.print("[warning][gateway] Состояние пусто: клиентов нет.[/warning]")
        return

    # Машиночитаемый вывод для `vpn profile pull`: каждая запись `name: link`
    # — ровно одна физическая строка. rich (console.print) переносит строки
    # по ширине терминала и ломает парсер на клиенте — поэтому print().
    for name, proto, link in links:
        print(f"{name}: {link}")


@probe_watch_app.callback(invoke_without_command=True)
def probe_watch_callback(
    ctx: typer.Context,
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Карта покрытия сигналов на этом сервере (что активно, что слепо)",
    ),
):
    """Монитор активного зондирования tcp/443 (И33 v1 + SPEC-20261116-probe-response):
    dry-run по умолчанию, read-only watch, RU-классификация по relay-CIDR,
    threat-level quiet/elevated/high и (opt-in) авто-лок 443."""
    from src.core.logger import console

    if ctx.invoked_subcommand is not None:
        return
    from src.gateway.probing import cmd_explain

    if explain:
        raise typer.Exit(cmd_explain())
    ctx.get_help()


@probe_rucidr_app.command("install")
def probe_rucidr_install(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
):
    """Поставить RU-CIDR-агрегат + еженедельный таймер vds-probe-rucidr (root).

    Включает вердикт RU-PROBE-SUSPECT на exit-серверах без релея НЕМЕДЛЕННО:
    агрегат ipdeny → /etc/vds-relay/ru-cidrs.txt (тот же путь, что ждёт relay).
    Идемпотентно; сбой сети не портит прежний агрегат.

    Примеры:
      sudo vds gateway probe-watch ru-cidr install          # dry-run, план
      sudo vds gateway probe-watch ru-cidr install --apply  # агрегат + таймер
    """
    import os

    from src.core.logger import console
    from src.gateway.probing_rucidr import cmd_ru_cidr_install

    if apply and os.geteuid() != 0:
        console.print("[error][probe-ru] install требует root (sudo).[/error]")
        raise typer.Exit(1)
    raise typer.Exit(cmd_ru_cidr_install(apply=apply))


@probe_rucidr_app.command("update")
def probe_rucidr_update(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
):
    """Разово обновить RU-CIDR-агрегат из ipdeny (root; зовётся и таймером).

    Примеры:
      sudo vds gateway probe-watch ru-cidr update --apply   # обновить сейчас
    """
    import os

    from src.core.logger import console
    from src.gateway.probing_rucidr import cmd_ru_cidr_update

    if apply and os.geteuid() != 0:
        console.print("[error][probe-ru] update требует root (sudo).[/error]")
        raise typer.Exit(1)
    raise typer.Exit(cmd_ru_cidr_update(apply=apply))


@probe_watch_app.command("config")
def probe_watch_config(
    auto_lockdown: Optional[str] = typer.Option(
        None,
        "--auto-lockdown",
        help="on|off: авто-лок 443 при threat high из часового тика (default off, SPEC §10 OQ-1)",
    ),
    lockdown_allow: Optional[str] = typer.Option(
        None,
        "--lockdown-allow",
        help="IP[,IP…]: allow-list авто-лока (v4); пусто + только-443 профиль = fail-fast",
    ),
    lockdown_ttl: Optional[str] = typer.Option(
        None,
        "--lockdown-ttl",
        help="TTL авто-лока: Nh, 1h..168h (default 48h, SPEC §10 OQ-2)",
    ),
    apply: bool = typer.Option(False, "--apply", help="Записать конфиг (по умолчанию dry-run)"),
):
    """Конфиг связки auto-lockdown (SPEC-20261116-probe-response §4.2).

    Без параметров — показать текущий конфиг. При auto-lockdown on и
    threat high часовой тик вызывает lock-443 (reason auto:RU-SUSPECT);
    downgrade лок НЕ снимает (OQ-3), TTL страхует; elevated никогда не
    триггерит лок. Fail-fast: on + пустой allow при профиле без 51825/2053
    отклоняется (лок закрыл бы всё входящее).

    Примеры:
      sudo vds gateway probe-watch config                                     # показать
      sudo vds gateway probe-watch config --auto-lockdown on --lockdown-allow 203.0.113.10 --apply
      sudo vds gateway probe-watch config --auto-lockdown on --lockdown-ttl 24h --apply
      sudo vds gateway probe-watch config --auto-lockdown off --apply
    """
    from src.gateway.probing import cmd_config

    raise typer.Exit(
        cmd_config(
            auto_lockdown=auto_lockdown,
            lockdown_allow=lockdown_allow,
            lockdown_ttl=lockdown_ttl,
            apply=apply,
        )
    )


@probe_watch_app.command("install")
def probe_watch_install(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
):
    """Установить nft-таблицу vds_probe + таймер vds-probe-watch (root).

    Идемпотентно; счётчики при переустановке сбрасываются (см. --help plan)."""
    from src.core.logger import console
    from src.gateway.probing import cmd_install

    import os

    if apply and os.geteuid() != 0:
        console.print("[error][probe] install требует root (sudo).[/error]")
        raise typer.Exit(1)
    raise typer.Exit(cmd_install(apply=apply))


@probe_watch_app.command("watch")
def probe_watch_watch(
    since: str = typer.Option(
        "1h", "--since", help="Окно journal-сканирования: '1h' или Nh"
    ),
    threshold: int = typer.Option(
        50, "--threshold", help="Порог unique probers за окно для PROBE-BURST"
    ),
    json_out: bool = typer.Option(False, "--json", help="Машиночитаемый JSON-отчёт"),
    record: bool = typer.Option(
        False,
        "--record",
        help="Перезаписать снапшот текущими счётчиками (ТОЛЬКО для юнита "
        "таймера; ручной watch read-only, дельта считается от таймерного снапшота)",
    ),
):
    """Read-only отчёт: дельта счётчиков nft + journal-сигнатуры + вердикт
    (quiet / PROBE-BURST / RU-PROBE-SUSPECT). Без --record ничего не пишет."""
    import re as _re

    from src.core.logger import console
    from src.gateway.probing import cmd_watch

    match = _re.fullmatch(r"(\d+)\s*h", since.strip())
    if not match:
        console.print(f"[error][probe] --since: ожидался формат Nh (например 1h), получено {since!r}[/error]")
        raise typer.Exit(1)
    hours = int(match.group(1))
    if hours <= 0:
        console.print("[error][probe] --since: N должно быть > 0[/error]")
        raise typer.Exit(1)
    raise typer.Exit(
        cmd_watch(since_hours=hours, threshold=threshold, json_out=json_out, record=record)
    )


@probe_watch_app.command("explain")
def probe_watch_explain():
    """Честная карта покрытия: nft/counter/юниты/journal/RU-CIDR/IPv6 (non-goal)."""
    from src.gateway.probing import cmd_explain

    raise typer.Exit(cmd_explain())


@probe_watch_app.command("remove")
def probe_watch_remove(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
):
    """Демонтаж nft-таблицы vds_probe + юнитов (идемпотентно, root)."""
    from src.core.logger import console
    from src.gateway.probing import cmd_remove

    import os

    if apply and os.geteuid() != 0:
        console.print("[error][probe] remove требует root (sudo).[/error]")
        raise typer.Exit(1)
    raise typer.Exit(cmd_remove(apply=apply))


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
    regenerate_path: bool = typer.Option(
        False,
        "--regenerate-path",
        help="Перевыпустить случайный path XHTTP (ломает выданные ссылки: после --apply сразу `vpn profile pull`)",
    ),
    skip_domain_check: bool = typer.Option(
        False,
        "--skip-domain-check",
        help="Только для миграции после смены IP: не требовать DNS==IP (сертификат/SNI не меняются)",
    ),
):
    """Добавить XHTTP-транспорт к живому Xray (ADR-003, SPEC WP-3)"""
    from src.xray.install import run_add_transport_xhttp
    raise typer.Exit(
        run_add_transport_xhttp(
            transport, domain, mode=mode, apply=apply, yes=yes,
            regenerate_path=regenerate_path, skip_domain_check=skip_domain_check,
        )
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


@xray_app.command("add-cdn")
def xray_add_cdn(
    domain: str = typer.Option(
        ..., "--domain", help="CDN-домен с LE-сертификатом (`vds acme issue --domain <cdn-домен>`)"
    ),
    port: int = typer.Option(2053, "--port", help="Origin-порт инблэнда (CF HTTPS-порт)"),
    yes: bool = typer.Option(False, "--yes", help="Без интерактивного подтверждения"),
):
    """Добавить CDN-транспорт VLESS+WS+TLS за Cloudflare (SPEC WP-2, ADR-006)"""
    from src.core.logger import console
    from src.xray.cdn import add_cdn

    if not yes:
        import questionary

        if not questionary.confirm(
            f"Добавить CDN-инблэнд на {domain}:{port}? Будет перезапущен "
            "vds-xray (короткий downtime); Reality/XHTTP не изменяются.",
            default=False,
        ).ask():
            console.print("[info][xray-cdn] Операция отменена.[/info]")
            raise typer.Exit(1)
    raise typer.Exit(add_cdn(domain, port=port))


@xray_app.command("add-cdn-client")
def xray_add_cdn_client(
    name: str = typer.Argument(..., help="Имя нового CDN-клиента"),
    front: str = typer.Option(
        None, "--front", help="Фронт пула для host/sni ссылки (по умолчанию основной домен CDN)"
    ),
):
    """Добавить CDN-клиента и показать share-link (vless за Cloudflare)"""
    from src.core.logger import console
    from src.xray.cdn import CdnError, add_cdn_client

    try:
        result = add_cdn_client(name, front=front)
    except (StoreError, CdnError) as exc:
        console.print(f"[error][xray-cdn] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(0 if result else 1)


@xray_app.command("add-cdn-front")
def xray_add_cdn_front(
    domain: str = typer.Argument(..., help="Домен фронта с LE-сертификатом (`vds acme issue --domain <домен>`)"),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Добавить фронт в пул CDN (сертификат в CDN-инблэнд, SPEC WP-2)"""
    from src.xray.cdn import add_cdn_front
    raise typer.Exit(add_cdn_front(domain, apply=apply))


@xray_app.command("remove-cdn-front")
def xray_remove_cdn_front(
    domain: str = typer.Argument(..., help="Домен фронта"),
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Снять фронт из пула CDN (LE-сертификат certbot не удаляется)"""
    from src.xray.cdn import remove_cdn_front
    raise typer.Exit(remove_cdn_front(domain, apply=apply))


@xray_app.command("list-cdn-fronts")
def xray_list_cdn_fronts():
    """Фронты пула CDN: домен, LE-файлы, срок сертификата, DNS-чек"""
    from src.core.logger import console
    from src.xray.cdn import list_fronts

    fronts = list_fronts()
    if not fronts:
        console.print(
            "[warning][xray-cdn] CDN не установлен — пул фронтов пуст "
            "(`vds xray add-cdn --domain <домен>`).[/warning]"
        )
        raise typer.Exit(1)
    for front in fronts:
        label = "основной" if front["main"] else "фронт"
        days = front["cert_days_left"]
        days_info = str(days) if days is not None else "?"
        console.print(
            f"[info][xray-cdn] {front['domain']} ({label}):[/info] "
            f"LE={'есть' if front['cert_files_ok'] else 'нет'}, "
            f"осталось {days_info} дн., "
            f"DNS={'ок' if front['dns_ok'] else 'не подтверждён'}"
        )
    raise typer.Exit(0)


@xray_app.command("remove-cdn-client")
def xray_remove_cdn_client(
    name: str = typer.Argument(..., help="Имя CDN-клиента"),
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Удалить CDN-клиента (uuid из конфига + state; dry-run по умолчанию)"""
    from src.core.logger import console
    from src.gateway.store import StoreError
    from src.xray.cdn import CdnError, remove_cdn_client

    try:
        remove_cdn_client(name, apply=apply)
    except (StoreError, CdnError) as exc:
        console.print(f"[error][xray-cdn] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(0)


@xray_app.command("remove-cdn")
def xray_remove_cdn(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
    yes: bool = typer.Option(False, "--yes", help="Без интерактивного подтверждения"),
):
    """Снять CDN-транспорт (инблэнд ws, клиенты state, UFW; Reality/XHTTP не трогаются)"""
    from src.xray.cdn import remove_cdn
    raise typer.Exit(remove_cdn(apply=apply, yes=yes))


@hysteria2_app.command("install")
def hysteria2_install(
    port: int = typer.Option(443, "--port", help="UDP-порт QUIC"),
    masquerade_url: str = typer.Option(
        None,
        "--masquerade-url",
        help="Сайт-маскировка при зондировании (по умолчанию https://download.microsoft.com/)",
    ),
):
    """Установить Hysteria2 (QUIC, UDP 443, self-signed без домена)"""
    from src.hysteria2.install import run_install
    raise typer.Exit(run_install(port=port, masquerade_url=masquerade_url))


@hysteria2_app.command("add-hop-ports")
def hysteria2_add_hop_ports(
    port_range: str = typer.Argument(..., help="Диапазон UDP-портов, напр. 20000-20500 (<=1000 портов)"),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Port hopping: REDIRECT диапазона на udp/443 (цепочка VDS_HY2_HOP, ADR-008)"""
    from src.hysteria2.hop import add_hop_ports
    raise typer.Exit(add_hop_ports(port_range, apply=apply))


@hysteria2_app.command("remove-hop-ports")
def hysteria2_remove_hop_ports(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Снять port hopping (цепочка, UFW, юнит; живой udp/443 не трогается)"""
    from src.hysteria2.hop import remove_hop_ports
    raise typer.Exit(remove_hop_ports(apply=apply))


@hysteria2_app.command("add-obfs")
def hysteria2_add_obfs(
    port: int = typer.Option(51826, "--port", help="UDP-порт obfs-инстанса salamander"),
):
    """Запустить obfs-инстанс (salamander) параллельно с основным udp/443"""
    from src.hysteria2.obfs import add_obfs
    raise typer.Exit(add_obfs(port=port))


@hysteria2_app.command("remove-obfs")
def hysteria2_remove_obfs(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Снять obfs-инстанс (юнит, конфиг, state; основной udp/443 не трогается)"""
    from src.hysteria2.obfs import remove_obfs
    raise typer.Exit(remove_obfs(apply=apply))


@hysteria2_app.command("rotate-obfs")
def hysteria2_rotate_obfs():
    """Ротация obfs-пароля (тот же порт, рестарт; клиентам — ре-импорт ссылки)"""
    from src.hysteria2.obfs import rotate_obfs
    raise typer.Exit(rotate_obfs())


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


@hysteria2_app.command("set-cert-domain")
def hysteria2_set_cert_domain(
    domain: str = typer.Argument(
        None,
        help="Домен из развёрнутого сертификата (sni ссылок); без аргумента — очистить",
    ),
):
    """Зафиксировать домен LE-сертификата Hysteria2 (host/sni в ссылках, GR-10)"""
    from src.hysteria2.clients import set_cert_domain
    raise typer.Exit(set_cert_domain(domain))


@hysteria2_app.command("remove")
def hysteria2_remove(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Удалить Hysteria2 (юнит, конфиг, сертификаты, бинарь, клиенты из store)"""
    from src.hysteria2.remove import run_remove
    raise typer.Exit(run_remove(apply=apply))


@amneziawg_app.command("install")
def amneziawg_install(
    port: int = typer.Option(51825, "--port", help="UDP-порт AmneziaWG"),
):
    """Установить AmneziaWG (PPA ppa:amnezia/ppa, UDP 51825, obfuscated WireGuard)"""
    from src.amneziawg.install import run_install
    raise typer.Exit(run_install(port=port))


@amneziawg_app.command("add-client")
def amneziawg_add_client(
    name: str = typer.Argument(..., help="Имя нового клиента"),
    no_psk: bool = typer.Option(False, "--no-psk", help="Без preshared key"),
    keepalive: int = typer.Option(
        0, "--keepalive",
        help="PersistentKeepalive в конфиге клиента (И44: по умолчанию НЕ "
             "пишется — радиомолчание в простое, метроном 25с = DPI-маяк; "
             "для NAT-дырки рекомендовано простое 113)"),
):
    """Добавить клиента AmneziaWG: .conf (0600) для импорта в AmneziaVPN"""
    from src.amneziawg.clients import AWGClientError, add_client
    from src.core.logger import console
    from src.gateway.store import StoreError

    try:
        add_client(name, no_psk=no_psk, keepalive=keepalive or None)
    except (StoreError, AWGClientError) as exc:
        console.print(f"[error][amneziawg] {exc}[/error]")
        raise typer.Exit(1)


@amneziawg_app.command("remove-client")
def amneziawg_remove_client(
    name: str = typer.Argument(..., help="Имя клиента"),
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Удалить клиента AmneziaWG (dry-run по умолчанию, --apply применяет)"""
    from src.amneziawg.clients import AWGClientError, remove_client
    from src.core.logger import console
    from src.gateway.store import StoreError

    try:
        plan = remove_client(name, apply=apply)
    except (StoreError, AWGClientError) as exc:
        console.print(f"[error][amneziawg] {exc}[/error]")
        raise typer.Exit(1)
    if plan.get("dry_run"):
        console.print("[warning][amneziawg] Dry-run — план удаления (без --apply):[/warning]")
        for step in plan.get("plan", []):
            console.print(f"  - {step}")


@amneziawg_app.command("status")
def amneziawg_status():
    """Статус AmneziaWG: юнит, DKMS-версия, UDP-порт, peers (секреты маскированы)"""
    from src.amneziawg.status import run_status

    raise typer.Exit(run_status())


@amneziawg_app.command("remove")
def amneziawg_remove(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Удалить AmneziaWG (юнит, ufw, конфиги, клиенты из store; пакеты PPA — вручную)"""
    from src.amneziawg.remove import run_remove

    raise typer.Exit(run_remove(apply=apply))


_RELAY_INIT_EPILOG = (
    "Примеры:\n"
    "  sudo vds relay init --exit 103.45.247.172 --domain relay.asvpersonal.ru --sni www.rt.ru\n"
    "  sudo vds relay init --exit 103.45.247.172 --domain relay.asvpersonal.ru --sni www.rt.ru \\\n"
    "      --exit-conf /root/relay-awg1.conf --apply\n\n"
    "Dry-run по умолчанию: печатает план (preflight + шаги) без мутаций.\n"
    "Порядок подготовки: Фаза 0 — docs/DEPLOY-RU-RELAY.md (A-запись DNS-only,\n"
    "leg smoke-test); Фаза 2 — этот init (--apply) либо ранбук руками.\n"
    "Клиенты после установки: sudo vds relay add-client NAME."
)


@relay_app.command("init", epilog=_RELAY_INIT_EPILOG)
def relay_init(
    exit_ip: str = typer.Option(..., "--exit", help="Публичный IPv4 exit-сервера asv1 (нога awg1)"),
    domain: str = typer.Option(..., "--domain", help="Домен релея (A-запись DNS-only! CF-прокси не пропускает UDP)"),
    sni: str = typer.Option(..., "--sni", help="RU-сайт same-DC для Reality-фолбэка (SNI/dest)"),
    exit_conf: str = typer.Option(
        None, "--exit-conf", help="Путь к клиентскому .conf с asv1 (vds amneziawg add-client relay)"
    ),
    apply: bool = typer.Option(False, "--apply", help="Исполнить план (по умолчанию dry-run)"),
):
    """Идемпотентно развернуть RU-relay (ADR-007 v1): AWG udp/443 (10.10.0.0/24),
    Reality tcp/443 RU-SNI, awg1-нога до asv1, UFW, ip_forward, MASQUERADE,
    nft policy-routing (RU-CIDR → eth0, прочее → awg1), недельный CIDR-таймер.
    Dry-run по умолчанию; повторный запуск дотягивает, не ломает."""
    from src.relay.init import run_init

    raise typer.Exit(
        run_init(exit_ip=exit_ip, domain=domain, sni=sni, exit_conf=exit_conf, apply=apply)
    )


@relay_app.command("status")
def relay_status(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable вывод"),
):
    """Статус релея: юниты, интерфейсы awg0/awg1, живость ноги до asv1
    (handshake-возраст), nft/ip rule, RU-CIDR, слушание 443. Read-only.

    Пример: sudo vds relay status; sudo vds relay status --json"""
    from src.relay.status import run_status

    raise typer.Exit(run_status(json_output=json_output))


@relay_app.command("add-client")
def relay_add_client(
    name: str = typer.Argument(..., help="Имя клиента (напр. phone, laptop)"),
    no_psk: bool = typer.Option(False, "--no-psk", help="Без preshared key"),
    keepalive: int = typer.Option(
        0, "--keepalive",
        help="PersistentKeepalive клиента (И44: по умолчанию НЕ пишется — "
             "радиомолчание; для NAT-дырки простое 113)"),
    endpoint: str = typer.Option(
        "", "--endpoint",
        help="Явный endpoint клиента HOST[:PORT] (по умолчанию домен релея, "
             "при неразрешимом домене — IP сервера)"),
    dns: str = typer.Option(
        "", "--dns",
        help="DNS клиента: IP-литералы через запятую (по умолчанию "
             "1.1.1.1,1.0.0.1 — идут через exit, в обход ТСПУ)"),
    qr: bool = typer.Option(
        False, "--qr",
        help="Напечатать QR конфига в терминале (qrencode; без него — warning)"),
):
    """Добавить пира AWG-сервера релея: .conf 0600 с endpoint <relay-домен>:443,
    MTU 1280 (двойная инкапсуляция), AllowedIPs 0.0.0.0/0 (только IPv4: нога
    awg1 v4-only) и DNS = 1.1.1.1, 1.0.0.1. Секреты в stdout не выводятся.

    Пример: sudo vds relay add-client phone --keepalive 25 --qr
    Домен не резолвится (внутреннее имя хостера / нет A-записи) → warning и
    фолбэк на публичный IP сервера; переопределение — `--endpoint`.
    Конфиг копируется с сервера по ssh → импорт в AmneziaVPN
    (docs/DEPLOY-RU-RELAY.md §Клиенты)."""
    from src.core.logger import console
    from src.gateway.store import StoreError
    from src.relay.clients import RelayClientError, add_client

    try:
        add_client(
            name, no_psk=no_psk, keepalive=keepalive or None,
            endpoint_override=endpoint or None,
            dns=dns or None, qr=qr,
        )
    except (StoreError, RelayClientError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        raise typer.Exit(1)


@relay_app.command("remove-client")
def relay_remove_client(
    name: str = typer.Argument(..., help="Имя клиента (напр. phone, laptop)"),
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Удалить релейного AWG-клиента (P20): [Peer] из /etc/amnezia/awg0.conf,
    клиентский .conf, запись из state + ЖИВОЕ удаление пира `awg set … remove`
    (БЕЗ рестарта юнита — остальные пиры не теряют handshake, P24).
    Откат конфига при сбое; повторный remove идемпотентен.

    Пример: sudo vds relay remove-client smoke-asv2 --apply"""
    from src.amneziawg.clients import AWGClientError
    from src.core.logger import console
    from src.gateway.store import StoreError
    from src.relay.clients import RelayClientError, remove_client

    try:
        result = remove_client(name, apply=apply)
    except (AWGClientError, StoreError, RelayClientError) as exc:
        console.print(f"[error][relay] {exc}[/error]")
        raise typer.Exit(1)
    if result["dry_run"]:
        console.print("[info][relay] DRY-RUN план remove-client:[/info]")
        for step in result["plan"]:
            console.print(f"[info][relay]   - {step}[/info]")
        console.print("[info][relay] Запустите с --apply для исполнения.[/info]")


@relay_exit_leg_app.command("install")
def relay_exit_leg_install(
    relay_ip: str = typer.Option(
        ..., "--relay-ip", help="Публичный IPv4 RU-релея (единственный разрешённый saddr)"
    ),
    public_key: str = typer.Option(
        ..., "--public-key", help="Публичный ключ релея (awg1) — единственный пир awg2"
    ),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Exit-узел (ADR-015, P24): выделенная нога awg2 (10.11.0.0/30) + пул
    51900-51911/udp, доступный только с IP релея (nft REDIRECT на 51900, UFW —
    один порт), PersistentKeepalive 25. Клиентский awg0 (51825) не трогается.
    Идемпотентно: повторный --apply не перегенерирует ключи и не плодит правила.

    Пример: sudo vds relay exit-leg install --relay-ip 185.80.91.135 \\
        --public-key <awg1-pubkey-релея> --apply

    На релее команда отказывает: релей не получает прав на exit."""
    from src.relay.exit_leg import run_install

    raise typer.Exit(run_install(relay_ip=relay_ip, public_key=public_key, apply=apply))


@relay_exit_leg_app.command("remove")
def relay_exit_leg_remove(
    apply: bool = typer.Option(False, "--apply", help="Применить удаление (по умолчанию dry-run)"),
):
    """Снять exit-leg: юниты awg2/пула, nft-таблица vds_relay_leg, UFW-правило,
    конфиг awg2 (0600) и state.protocols['relay_leg']. Клиентский awg0 не тронут.

    Пример: sudo vds relay exit-leg remove --apply"""
    from src.relay.exit_leg import run_remove

    raise typer.Exit(run_remove(apply=apply))


@relay_wstunnel_app.command("install")
def relay_wstunnel_install(
    archive: str = typer.Option(
        ..., "--archive", help="Локальный .tar.gz релиза wstunnel (скачивается отдельно)"
    ),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Установить бинарник wstunnel из локального архива (ADR-016, WP-P2P-1).

    Сеть модуль не трогает: архив скачивает оператор, модуль проверяет **sha256
    до распаковки** (пиннинг `WSTUNNEL_VERSION`/`WSTUNNEL_SHA256`) и атомарно
    ставит `/usr/local/bin/wstunnel` (0755). Никаких `latest` и `curl | sh`.

    Пример: sudo vds relay wstunnel install --archive /tmp/wstunnel_11.1.0_linux_amd64.tar.gz --apply"""
    from pathlib import Path

    from src.relay.wstunnel import WstunnelError, run_install

    try:
        raise typer.Exit(run_install(archive=Path(archive), dry_run=not apply, apply=apply))
    except WstunnelError as exc:
        console.print(f"[error][wstunnel] {exc}[/error]")
        raise typer.Exit(1)


@relay_carrier_app.command("status")
def relay_carrier_status(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable вывод"),
):
    """Состояние селектора носителей (ADR-016, WP-P2P-3).

    Пример: vds relay carrier status --json"""
    from src.relay.carriers import run_status

    raise typer.Exit(run_status(json_output=json_output))


@relay_carrier_app.command("switch")
def relay_carrier_switch(
    to: str = typer.Option(..., "--to", help="Целевой носитель: awg | wstunnel"),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Ручное переключение table 100 (lock общий с манёвром P25 — AC-7).

    Пример: sudo vds relay carrier switch --to wstunnel --apply"""
    from src.relay.carriers import run_switch

    raise typer.Exit(run_switch(to=to, apply=apply))


@relay_wstunnel_app.command("init")
def relay_wstunnel_init(
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Релей, шаг 1: ключи `wg-ws0` + секрет path-prefix (ADR-016).

    Печатает ТОЛЬКО публичный ключ; приватный остаётся в
    `/etc/amnezia/wg-ws0.priv` (0600), prefix — в `/etc/vds/wstunnel-client.env`
    (0600, файл передаётся на exit).

    Пример: sudo vds relay wstunnel init --apply"""
    from src.relay.wstunnel import WstunnelError, run_init

    try:
        raise typer.Exit(run_init(dry_run=not apply, apply=apply))
    except WstunnelError as exc:
        console.print(f"[error][wstunnel] {exc}[/error]")
        raise typer.Exit(1)


@relay_wstunnel_app.command("server")
def relay_wstunnel_server(
    relay_ip: str = typer.Option(..., "--relay-ip", help="Публичный IPv4 релея"),
    relay_public_key: str = typer.Option(..., "--relay-public-key", help="Публичный ключ релея (wg-ws0)"),
    domain: str = typer.Option(..., "--domain", help="LE-домен: ws.<domain> (DNS only)"),
    prefix_file: str = typer.Option(..., "--prefix-file", help="env-файл prefix с релея (0600)"),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Exit-сторона носителя №2 (ADR-016): `wg-ws0` + wstunnel server (WSS 9443).

    Требует выпущенный LE на `--domain`. Печатает публичный ключ exit — его
    нужно передать на релей для `vds relay wstunnel client`.

    Пример: sudo vds relay wstunnel server --relay-ip <ip> \
        --relay-public-key <key> --domain ws.<domain> \
        --prefix-file /tmp/wstunnel-client.env --apply"""
    from pathlib import Path

    from src.relay.wstunnel import WstunnelError, run_exit_install

    try:
        raise typer.Exit(run_exit_install(
            relay_ip=relay_ip, relay_public_key=relay_public_key, domain=domain,
            prefix_file=Path(prefix_file), apply=apply,
        ))
    except WstunnelError as exc:
        console.print(f"[error][wstunnel] {exc}[/error]")
        raise typer.Exit(1)


@relay_wstunnel_app.command("client")
def relay_wstunnel_client(
    exit_public_key: str = typer.Option(..., "--exit-public-key", help="Публичный ключ exit (wg-ws0)"),
    domain: str = typer.Option(..., "--domain", help="LE-домен: ws.<domain>"),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Релей, шаг 2: конфиг `wg-ws0`, клиент wstunnel, NAT-ветка, юниты.

    `table 100` не переключается — это делает селектор (WP-P2P-3).

    Пример: sudo vds relay wstunnel client --exit-public-key <key> \
        --domain ws.<domain> --apply"""
    from src.relay.wstunnel import WstunnelError, run_relay_install

    try:
        raise typer.Exit(run_relay_install(
            exit_public_key=exit_public_key, domain=domain, apply=apply,
        ))
    except WstunnelError as exc:
        console.print(f"[error][wstunnel] {exc}[/error]")
        raise typer.Exit(1)


@relay_wstunnel_app.command("status")
def relay_wstunnel_status(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable вывод"),
):
    """Состояние вендоринга: пиннинг, установленная версия, env-файлы.

    Пример: vds relay wstunnel status --json"""
    import json as _json

    from src.relay.wstunnel import run_status

    status = run_status()
    if json_output:
        print(_json.dumps(status, ensure_ascii=False))
        raise typer.Exit(0)
    console.print(f"[info][wstunnel] пиннинг: v{status['pinned_version']}[/info]")
    console.print(f"[info][wstunnel] установлен: {status['installed_version'] or 'нет'}[/info]")
    console.print(f"[info][wstunnel] env-файлы: сервер={status['env_server']}, клиент={status['env_client']}[/info]")
    raise typer.Exit(0)


@relay_maneuver_app.command("status")
def relay_maneuver_status(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable вывод"),
):
    """Статус манёвра ноги: state-machine, текущий/предыдущий порт, cooldown,
    exhausted, failed_ports, runtime endpoint. Read-only, без секретов.

    Пример: sudo vds relay maneuver status --json"""
    from src.relay.maneuver import run_status

    raise typer.Exit(run_status(json_output=json_output))


@relay_maneuver_app.command("history")
def relay_maneuver_history(
    limit: int = typer.Option(10, "--limit", help="Сколько последних попыток показать"),
):
    """История попыток манёвра (ts, from→to, ok/rollback, liveness_ms).

    Пример: sudo vds relay maneuver history --limit 20"""
    from src.relay.maneuver import run_history

    raise typer.Exit(run_history(limit=limit))


@relay_maneuver_app.command("step")
def relay_maneuver_step(
    apply: bool = typer.Option(False, "--apply", help="Исполнить манёвр (по умолчанию dry-run)"),
    force: bool = typer.Option(
        False, "--force",
        help="Обойти ТОЛЬКО cooldown (guard роли/пула и лимит 3/час сохраняются)",
    ),
):
    """Один тик автомата: при мёртвом liveness и живом трафике — runtime-смена
    endpoint (`awg set awg1 listen-port 0 peer … endpoint …`), окно liveness 20 с,
    персист Endpoint только при успехе, откат на прежний порт по таймауту.
    awg-quick/рестарты юнитов не используются; exit-сторона не трогается.

    Пример: sudo vds relay maneuver step --apply"""
    from src.relay.maneuver import run_step

    raise typer.Exit(run_step(apply=apply, force=force))


@relay_maneuver_app.command("rollback")
def relay_maneuver_rollback(
    apply: bool = typer.Option(False, "--apply", help="Выполнить откат (по умолчанию dry-run)"),
):
    """Вернуть endpoint на предыдущий порт (previous_port). Идемпотентно:
    предыдущий == текущий → exit 0. Конфиг персистится только при liveness.

    Пример: sudo vds relay maneuver rollback --apply"""
    from src.relay.maneuver import run_rollback

    raise typer.Exit(run_rollback(apply=apply))


@relay_maneuver_app.command("tick")
def relay_maneuver_tick(
    apply: bool = typer.Option(
        False, "--apply", help="Исполнить тик (без флага — read-only сэмпл)"
    ),
):
    """Один тик таймера (ExecStart `vds-relay-maneuver.service`). ВСЕГДА exit 0:
    отказ guard/ManeuverError/StoreError/занятый лок перехватываются, в journal
    печатается одна строка `\\[relay-maneuver] state=… port=… liveness=… …`.
    `--apply` — реальный тик; без него state не пишется.

    Пример: sudo vds relay maneuver tick --apply"""
    from src.relay.maneuver import run_tick

    raise typer.Exit(run_tick(apply=apply))


@relay_maneuver_app.command("install")
def relay_maneuver_install(
    apply: bool = typer.Option(False, "--apply", help="Установить юниты (по умолчанию dry-run)"),
    enable_auto: bool = typer.Option(
        False, "--enable-auto",
        help="Включить и запустить таймер (по умолчанию auto=off: opt-in)",
    ),
    interval: str = typer.Option(
        "60s", "--interval", help="Период тика (>=15s; 60s → детекция 3/3 ≈180 с)"
    ),
):
    """Opt-in таймер манёвра: `vds-relay-maneuver.timer` + `.service` (ADR-015,
    SPEC-20261120 WP-M4). Guard роли/пула. auto=off по умолчанию: файлы
    ставятся, таймер не включён и не запущен; `--enable-auto` — enable+start.

    Пример: sudo vds relay maneuver install --apply --enable-auto --interval 60s"""
    from src.relay.maneuver import run_install

    raise typer.Exit(run_install(apply=apply, enable_auto=enable_auto, interval=interval))


@relay_maneuver_app.command("remove")
def relay_maneuver_remove(
    apply: bool = typer.Option(False, "--apply", help="Снять юниты (по умолчанию dry-run)"),
):
    """Снять `.timer` и `.service` (stop+disable+rm, идемпотентно). State
    `/var/lib/vds/relay-maneuver.json` сохраняется как история.

    Пример: sudo vds relay maneuver remove --apply"""
    from src.relay.maneuver import run_remove

    raise typer.Exit(run_remove(apply=apply))


@acme_app.command("issue")
def acme_issue(
    domain: str = typer.Option(..., "--domain", help="Домен, резолвящийся в публичный IP сервера"),
    email: str = typer.Option(..., "--email", help="Email для аккаунта Let's Encrypt"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Показать план без изменений"),
    window_80: bool = typer.Option(
        False, "--window-80",
        help="quiet-exit (SPEC-20261124 P1-5): 80/tcp открывается ДО certbot и закрывается в finally + renewal-hooks pre/open post/close",
    ),
):
    """Выпустить LE-сертификат на домен (HTTP-01, порт 80) + deploy-hook"""
    from src.acme.install import run_issue
    raise typer.Exit(run_issue(domain=domain, email=email, dry_run=dry_run, window_80=window_80))


@acme_app.command("check-80-window")
def acme_check_80_window():
    """Fail-safe чек окна ACME (P1-5): 80/tcp должен быть закрыт вне окна.
    [warning] + exit 1, если правило открыто без маркера /run/vds-acme-80-opened;
    stale-маркер без правила — подчищается. Read-only по ufw.

    Пример: sudo vds acme check-80-window"""
    from src.acme.window_hook import run_check_window
    raise typer.Exit(run_check_window())


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
    """Удалить WireGuard"""
    from src.coturn.install import run_remove
    raise typer.Exit(run_remove())


@ufw_app.command("harden")
def ufw_harden(
    profile: str = typer.Option(
        "gateway",
        "--profile",
        help="Профиль: gateway | relay | exit-cascade | quiet-exit (SPEC-20261124)",
    ),
    allow_from: Optional[str] = typer.Option(
        None, "--allow-from", help="IP релея для exit-cascade: 443 открывается только с него"
    ),
    apply: bool = typer.Option(False, "--apply", help="Применить план (по умолчанию dry-run)"),
    undo: bool = typer.Option(False, "--undo", help="Откатить применённые harden'ом правила (по журналу в state)"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Обход guard'а активного lock-443 (SPEC §9.C; событие пишется в журнал лока)",
    ),
    no_direct_awg: bool = typer.Option(
        False, "--no-direct-awg",
        help="quiet-exit: не открывать 51825/udp (P1-7; требует --yes-i-have-vnc)",
    ),
    yes_i_have_vnc: bool = typer.Option(
        False, "--yes-i-have-vnc",
        help="quiet-exit: подтверждение VNC-пути для --no-direct-awg (иначе abort)",
    ),
    close_public_ssh: bool = typer.Option(
        False, "--close-public-ssh",
        help="quiet-exit Фаза 2 (IQ-3): закрыть публичный SSH; preflight awg0+handshake oob-laptop ≤3 мин; деструктивно — только с --apply",
    ),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable вывод (v1: не реализован, plan печатается текстом)"),
):
    """Идемпотентный харднинг UFW (SPEC-20261116): deny in / allow out,
    ssh-лимит первым из allow-набора, сервисные порты из state.protocols
    (детекция существующих правил — relay init / amneziawg / hysteria2 hop
    не дублируются), forwarding для каскадных профилей, ufw enable строго
    последним. Docker/listeners-расхождения — [warning]. ICMP не трогаем.
    Guard: при активном lock-443 — отказ (SPEC §9.C), обход только --force.
    Откат: --undo --apply. Dry-run по умолчанию.

    quiet-exit (SPEC-20261124): слушатели 443/8443/2053 → ERROR «нарушение
    quiet-exit», план НЕ применяется; 80/tcp автоматически НЕ открывается
    (закрытие TECHDEBT P39); Фаза 1 держит публичный SSH limit (warning),
    Фаза 2: `--close-public-ssh --apply` после живого OOB-1.

    Примеры:
      sudo vds system ufw harden --profile gateway            # dry-run, план
      sudo vds system ufw harden --profile gateway --apply    # применить
      sudo vds system ufw harden --profile exit-cascade --allow-from 203.0.113.10 --apply
      sudo vds system ufw harden --profile relay --apply      # asv1/релей
      sudo vds system ufw harden --profile quiet-exit --apply # тихий exit (Фаза 1)
      sudo vds system ufw harden --close-public-ssh --apply   # Фаза 2 (после OOB-1!)
    """
    from src.system.ufw import HardeningOpts, UfwError, run_harden

    if json_output:
        from src.core.logger import console
        console.print("[warning][ufw] --json в v1 не реализован — план печатается текстом.[/warning]")
    if no_direct_awg and not yes_i_have_vnc:
        from src.core.logger import console
        console.print(
            "[error][ufw] --no-direct-awg закрывает OOB-1: подтверждение "
            "--yes-i-have-vnc обязательно (SPEC P1-7).[/error]"
        )
        raise typer.Exit(2)
    if close_public_ssh and (undo or profile != "quiet-exit"):
        from src.core.logger import console
        console.print(
            "[error][ufw] --close-public-ssh — отдельная операция Фазы 2; "
            "используйте `harden --profile quiet-exit --close-public-ssh [--apply]` "
            "без --undo.[/error]"
        )
        raise typer.Exit(2)
    if close_public_ssh:
        from src.system.ufw import UfwError as _UfwError, run_close_public_ssh

        try:
            code = run_close_public_ssh(apply=apply)
        except _UfwError as exc:
            from src.core.logger import console
            console.print(f"[error][ufw] {exc}[/error]")
            raise typer.Exit(1)
        raise typer.Exit(code)
    try:
        code = run_harden(
            profile, apply=apply, undo=undo,
            opts=HardeningOpts(
                allow_from=allow_from,
                no_direct_awg=no_direct_awg,
                yes_i_have_vnc=yes_i_have_vnc,
            ),
            force=force,
        )
    except UfwError as exc:
        from src.core.logger import console
        console.print(f"[error][ufw] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(code)


@ufw_app.command("ssh-port")
def ufw_ssh_port(
    to: Optional[int] = typer.Option(
        None, "--to", help="Новый ssh-порт (Фаза A: ufw limit + sshd-конфиг; 22 НЕ закрывается)"
    ),
    finalize: bool = typer.Option(
        False, "--finalize", help="Фаза B: удалить правила 22 (только после проверки входа на новый порт со второго терминала!)"
    ),
    apply: bool = typer.Option(False, "--apply", help="Применить (по умолчанию dry-run)"),
):
    """Двухфазный перенос ssh-порта (SPEC-20261116 §1.7). Фаза A добавляет
    ufw limit N + /etc/ssh/sshd_config.d/99-vds-port.conf + ssh.socket drop-in
    (Ubuntu 24.04) и ОСТАНАВЛИВАЕТСЯ: порт 22 остаётся открытым до подтверждения.
    Фаза B (--finalize) удаляет правила 22 — выполняйте только после успешного
    входа на порт N со ВТОРОГО терминала.

    Примеры:
      sudo vds system ufw ssh-port --to 49222            # dry-run
      sudo vds system ufw ssh-port --to 49222 --apply    # Фаза A
      sudo vds system ufw ssh-port --finalize --apply    # Фаза B (после проверки!)
    """
    from src.system.ufw import UfwError, run_ssh_port

    try:
        code = run_ssh_port(to, finalize, apply=apply)
    except UfwError as exc:
        from src.core.logger import console
        console.print(f"[error][ufw-ssh] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(code)


@ufw_app.command("status")
def ufw_status():
    """Сводка UFW-состояния: meta harden из state, live `ufw status`,
    pending-предупреждение незавершённого переноса ssh-порта. Read-only.

    Пример: sudo vds system ufw status"""
    from src.system.ufw import run_status

    raise typer.Exit(run_status())


@ufw_app.command("lock-443")
def ufw_lock443(
    allow_from: Optional[str] = typer.Option(
        None,
        "--allow-from",
        help="IP[,IP…]: кому оставить 443/tcp (только IPv4); пусто = 443 закрыт всем",
    ),
    ttl: str = typer.Option(
        "48h", "--ttl", help="TTL само-разблокировки: Nh в диапазоне 1h..168h (SPEC §10 OQ-2)"
    ),
    reason: str = typer.Option(
        "", "--reason", help="Причина лока (в журнал/статус; авто-тик пишет auto:RU-SUSPECT)"
    ),
    with_udp: bool = typer.Option(
        False,
        "--with-udp",
        help="Закрыть и 443/udp, и Hy2-hop-диапазон (по умолчанию НЕ трогаются — §9.B)",
    ),
    status: bool = typer.Option(
        False, "--status", help="Показать состояние лока + TTL (read-only)"
    ),
    unlock: bool = typer.Option(
        False, "--unlock", help="Досрочное снятие: восстановить широкие правила из журнала"
    ),
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
):
    """Изоляция 443 по вердиктам probe-watch (SPEC-20261116-probe-response §4.1).

    Удаляет широкие 443/tcp (в undo-журнал state["ufw_lockdown"]), добавляет
    allow from <IP> для 443. AWG 51825/udp, CDN 2053, ssh — НЕ трогаются
    (плейбук Фаза 3). Hy2-hop (asv1) остаётся открытым с warning (§9.B);
    полное молчание — явным --with-udp. TTL обязателен (default 48h):
    истечение снимает лок тиком probe-watch (§11), забытый лок невозможен.
    Повторный --apply идемпотентен: продлевает TTL, allow-from заменяется.
    Guard: harden при активном локе отказывает (обход --force, §9.C).

    Примеры:
      sudo vds system ufw lock-443                                          # dry-run: план
      sudo vds system ufw lock-443 --reason "RU-PROBE-SUSPECT" --apply     # лок (443 всем закрыт)
      sudo vds system ufw lock-443 --allow-from 203.0.113.10,203.0.113.11 --ttl 24h --apply
      sudo vds system ufw lock-443 --status                                # состояние + TTL
      sudo vds system ufw lock-443 --unlock --apply                        # досрочное снятие
    """
    from src.system.ufw import UfwError, run_lock443

    try:
        code = run_lock443(
            allow_from=allow_from,
            ttl=ttl,
            reason=reason,
            with_udp=with_udp,
            status=status,
            unlock=unlock,
            apply=apply,
        )
    except UfwError as exc:
        from src.core.logger import console
        console.print(f"[error][ufw] {exc}[/error]")
        raise typer.Exit(1)
    raise typer.Exit(code)


# ---------------------------------------------------------------------------
# logs (SPEC-20261116-log-forensics, ADR-012) — импорты ленивые внутри команд
# ---------------------------------------------------------------------------

def _require_root_logs(action: str) -> None:
    import os

    from src.core.logger import console

    if os.geteuid() != 0:
        console.print(f"[error][logs] {action} требует root (sudo).[/error]")
        raise typer.Exit(1)


@logs_app.command("status")
def logs_status():
    """Состояние модуля: каталоги, таймеры, последний сэмпл, disk_pct, capture.

    Примеры:
      vds logs status
    """
    from src.logs.install import cmd_status

    raise typer.Exit(cmd_status())


@logs_app.command("sample")
def logs_sample(
    apply: bool = typer.Option(False, "--apply", help="Записать сэмпл (по умолчанию dry-run)"),
):
    """Разово собрать 5-мин Event (nft/ss/nstat/awg/units/journal + probe-watch
    read-only дельта) и дописать в telemetry NDJSON (disk-cap 90%).

    Примеры:
      sudo vds logs sample          # dry-run: план источников
      sudo vds logs sample --apply  # записать сэмпл
    """
    if apply:
        _require_root_logs("sample --apply")
    from src.logs.collect import cmd_sample

    raise typer.Exit(cmd_sample(apply=apply))


@logs_app.command("analyze")
def logs_analyze(
    live: bool = typer.Option(False, "--live", help="Анализ по telemetry за --since"),
    since: str = typer.Option("24h", "--since", help="Окно анализа: Nh (max 168h)"),
    json_out: bool = typer.Option(False, "--json", help="Машиночитаемый JSON (§7.9)"),
):
    """Анализ телеметрии правилами T-01..T-17 (read-only, без root, без реакций
    R-9). Exit: 0 — ok, 1 — findings ≥ medium, 2 — ошибка.

    Примеры:
      vds logs analyze --live --since 24h
      vds logs analyze --live --since 2h --json
    """
    import re as _re

    from src.core.logger import console
    from src.logs.report import cmd_analyze

    match = _re.fullmatch(r"(\d+)\s*h", since.strip())
    if not match:
        console.print(f"[error][logs] --since: ожидался Nh, получено {since!r}[/error]")
        raise typer.Exit(2)
    hours = int(match.group(1))
    if hours <= 0 or hours > 168:
        console.print(f"[error][logs] --since: N в диапазоне 1..168, получено {hours}[/error]")
        raise typer.Exit(2)
    if not live:
        console.print("[info][logs] Укажите --live (анализ по телеметрии; bundle-режим — WP-3).[/info]")
        raise typer.Exit(2)
    raise typer.Exit(cmd_analyze(live=live, since_hours=hours, json_out=json_out))


@logs_app.command("report")
def logs_report(
    apply: bool = typer.Option(False, "--apply", help="Записать daily-отчёт (reports/, 0600)"),
    last: bool = typer.Option(False, "--last", help="Показать последний сохранённый отчёт"),
):
    """Daily-отчёт (вердикт + findings + coverage) — вызывает daily-таймер 04:15.

    Примеры:
      vds logs report --last          # последний отчёт
      sudo vds logs report --apply    # собрать и записать сейчас
    """
    if apply:
        _require_root_logs("report --apply")
    from src.logs.report import cmd_report

    raise typer.Exit(cmd_report(apply=apply, last=last))


@logs_capture_app.command("start")
def logs_capture_start(
    duration: int = typer.Option(1, "--duration", help="Часы захвата (default 1h, max 4h)"),
    max_mb: int = typer.Option(50, "--max-mb", help="Объём кольца MB (default 50; -C=max_mb//5, -W 5)"),
    apply: bool = typer.Option(False, "--apply", help="Запустить tcpdump (по умолчанию dry-run)"),
):
    """Bounded pcap-захват tcp/443 (§8.1): IPv4 BPF, -s 1600, -G 3600, -W 5,
    metadata-only, TTL 7 дней, путь /var/lib/vds/forensics/captures/.

    Примеры:
      sudo vds logs capture start --duration 1h --max-mb 50          # dry-run: BPF/лимиты
      sudo vds logs capture start --duration 1h --max-mb 50 --apply
    """
    _require_root_logs("capture start")
    from src.logs.capture import cmd_capture_start

    raise typer.Exit(cmd_capture_start(duration_h=duration, max_mb=max_mb, apply=apply))


@logs_capture_app.command("status")
def logs_capture_status():
    """Состояние захвата: pidfile+comm, файлы кольца, суммарный объём."""
    from src.logs.capture import cmd_capture_status

    raise typer.Exit(cmd_capture_status())


@logs_capture_app.command("stop")
def logs_capture_stop(
    apply: bool = typer.Option(False, "--apply", help="SIGTERM (по умолчанию dry-run)"),
):
    """Останов захвата: kill ТОЛЬКО PID из pidfile после comm==tcpdump
    (AGENTS §6: не по порту/имени)."""
    _require_root_logs("capture stop --apply")
    from src.logs.capture import cmd_capture_stop

    raise typer.Exit(cmd_capture_stop(apply=apply))


@logs_app.command("install")
def logs_install(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run; opt-in OQ-2)"),
):
    """Установить log-forensics (root): каталоги, hmac.key, rules.json,
    таймеры vds-logs-sample (5 мин) и vds-logs-daily (04:15). Идемпотентно;
    undo-журнал для remove.

    Примеры:
      sudo vds logs install          # dry-run: план
      sudo vds logs install --apply
    """
    _require_root_logs("install --apply")
    from src.logs.install import cmd_install

    raise typer.Exit(cmd_install(apply=apply))


@logs_app.command("remove")
def logs_remove(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
):
    """Демонтаж таймеров/юнитов по undo-журналу (артефакты сохраняются)."""
    _require_root_logs("remove --apply")
    from src.logs.install import cmd_remove

    raise typer.Exit(cmd_remove(apply=apply))


@alert_app.command("install")
def alert_install(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
    channel: Optional[str] = typer.Option(
        None, "--channel", help="tg,smtp — какие каналы включить (пусто = авто по парам ключей)"
    ),
    interval: str = typer.Option("2m", "--interval", help="Период тика таймера (2m)"),
    handshake_threshold: str = typer.Option(
        "300s", "--handshake-threshold", help="Порог возраста handshake для пульса плеча"
    ),
    heartbeat: str = typer.Option("24h", "--heartbeat", help="Период heartbeat (dead-man switch)"),
    force: bool = typer.Option(False, "--force", help="Перезаписать существующий alert.env"),
    allow_relay_node: bool = typer.Option(
        False,
        "--allow-relay-node",
        help="Разрешить установку на узле-рееле (делать не надо: секреты на релее не храним)",
    ),
):
    """Установить сторожа на exit-узле: юниты + /etc/vds/alert.env (0600).

    Dry-run по умолчанию. Секреты в юнит не попадают: процесс читает env сам.

    Примеры:
      sudo vds alert install                 # план: юниты, имена ключей, каналы
      sudo vds alert install --apply
      sudo vds alert install --channel smtp --apply
    """
    from src.alert.cli import cmd_install

    raise typer.Exit(
        cmd_install(
            apply=apply,
            channel=channel,
            interval=interval,
            handshake_threshold=handshake_threshold,
            heartbeat=heartbeat,
            force=force,
            allow_relay_node=allow_relay_node,
        )
    )


@alert_app.command("remove")
def alert_remove(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
    purge: bool = typer.Option(
        False, "--purge", help="Удалить также alert.env и alert-state.json"
    ),
):
    """Снять юниты сторожа (alert.env сохраняется; --purge удаляет и его)."""
    from src.alert.cli import cmd_remove

    raise typer.Exit(cmd_remove(apply=apply, purge=purge))


@alert_app.command("test")
def alert_test(
    channel: Optional[str] = typer.Option(
        None, "--channel", help="tg|smtp — проверить только этот канал (по умолчанию все активные)"
    ),
):
    """Отправить тестовое сообщение (root, читает /etc/vds/alert.env).

    Без записи state: повторные запуски не влияют на дедуп/лимиты.

    Примеры:
      sudo vds alert test
      sudo vds alert test --channel smtp
    """
    from src.alert.cli import cmd_test

    raise typer.Exit(cmd_test(channel=channel))


@alert_app.command("status")
def alert_status(
    json_out: bool = typer.Option(False, "--json", help="Машиночитаемый JSON (без секретов)"),
):
    """Состояние сторожа: каналы, юниты, что видно (coverage). Без root — урезанно."""
    from src.alert.cli import cmd_status

    raise typer.Exit(cmd_status(json_out=json_out))


@alert_app.command("watch")
def alert_watch(
    config: str = typer.Option(
        "/etc/vds/alert.env", "--config", help="Путь к конфигу (в юните — фиксированный)"
    ),
    no_send: bool = typer.Option(
        False, "--no-send", help="Dry-run тика: план без отправки и без записи state"
    ),
):
    """Служебная команда: один тик сторожа (его зовёт таймер).

    Ручная отладка — только с --no-send, иначе возможен дубль тревоги.
    """
    from src.alert.watch import run_tick

    raise typer.Exit(run_tick(config_path=config, no_send=no_send))


@dms_app.command("install")
def dms_install(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
    role: str = typer.Option("exit", "--role", help="Роль узла: exit|relay (gate различается)"),
    interval: str = typer.Option("5m", "--interval", help="Период тика таймера (5m)"),
    force: bool = typer.Option(False, "--force", help="Перезаписать существующий dms.env"),
):
    """Установить DMS-пинг: юниты + /etc/vds/dms.env (0600).

    Dry-run по умолчанию. Секрет (DMS_PING_URL) в юнит не попадает:
    процесс читает env сам; URL нигде не печатается.

    Примеры:
      sudo vds dms install --role exit --apply
      sudo vds dms install --role relay --apply
    """
    from src.dms.cli import cmd_install

    raise typer.Exit(cmd_install(apply=apply, role=role, interval=interval, force=force))


@dms_app.command("remove")
def dms_remove(
    apply: bool = typer.Option(False, "--apply", help="Исполнить (по умолчанию dry-run)"),
    purge: bool = typer.Option(False, "--purge", help="Удалить также dms.env"),
):
    """Снять юниты DMS (dms.env сохраняется; --purge удаляет и его)."""
    from src.dms.cli import cmd_remove

    raise typer.Exit(cmd_remove(apply=apply, purge=purge))


@dms_app.command("test")
def dms_test():
    """Один реальный пинг «руками» (gate + GET или GET /fail; root).

    Без записи state. URL не печатается — только теги DMS-SENT/DMS-FAILED.

    Примеры:
      sudo vds dms test
    """
    from src.dms.cli import cmd_test

    raise typer.Exit(cmd_test())


@dms_app.command("status")
def dms_status(
    json_out: bool = typer.Option(False, "--json", help="Машиночитаемый JSON (URL маской)"),
):
    """Состояние DMS: конфиг (URL маской), юниты. Без root — урезанно."""
    from src.dms.cli import cmd_status

    raise typer.Exit(cmd_status(json_out=json_out))


@dms_app.command("ping")
def dms_ping(
    config: str = typer.Option(
        "/etc/vds/dms.env", "--config", help="Путь к конфигу (в юните — фиксированный)"
    ),
):
    """Служебная команда: один тик DMS (его зовёт таймер). Exit-код всегда 0.

    Пинг только при живых ногах (gate); при мёртвой ноге — GET <URL>/fail.
    """
    from src.dms.gate import run_ping_locked

    raise typer.Exit(run_ping_locked(config_path=config))


if __name__ == "__main__":
    app()
