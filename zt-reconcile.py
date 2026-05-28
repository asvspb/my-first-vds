#!/usr/bin/env python3
"""
ZeroTier Desired-State Reconciler (Declarative Control Plane)

Reads topology.json (desired state) and reconciles actual ZT state.
Safe operations only — never deletes members, only authorizes and sets IPs.

Daemon-ready for systemd timer execution.

Usage:
    python3 zt-reconcile.py                    # dry-run (show diff)
    python3 zt-reconcile.py --apply             # apply changes
    python3 zt-reconcile.py --init              # generate topology.json from current state
    python3 zt-reconcile.py --validate          # validate topology.json schema

Exit codes:
    0 — success (or no changes needed)
    1 — error (API down, validation failed, lock contention)
"""

import json
import sys
import os
import subprocess
import urllib.request
import urllib.error
import argparse
import fcntl
import logging
from datetime import datetime, timezone
from pathlib import Path

INSTALL_DIR = os.environ.get("INSTALL_DIR", "/opt/ztnet")
TOPOLOGY_FILE = os.path.join(INSTALL_DIR, "topology.json")
ENV_FILE = os.path.join(INSTALL_DIR, ".env.info")
LOCK_FILE = "/var/run/ztnet.lock"
LOG_FILE = os.path.join(INSTALL_DIR, "zt-reconcile.log")

ANSI = {
    "RED": "\033[0;31m", "GREEN": "\033[0;32m", "YELLOW": "\033[1;33m",
    "CYAN": "\033[0;36m", "BOLD": "\033[1m", "NC": "\033[0m",
}

log_fmt = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("zt-reconcile")

_changes_found = False


def _out(level, msg):
    global _changes_found
    if level == "ok":
        logger.info(msg)
    elif level == "warn":
        logger.warning(msg)
    elif level == "fail":
        logger.error(msg)
    elif level == "info":
        logger.info(msg)
        _changes_found = True
    elif level == "change":
        _changes_found = True
        logger.info(f"CHANGE: {msg}")


def cprint(prefix, msg):
    print(f"{prefix} {msg}")


def log_ok(msg):
    _out("ok", msg)
    cprint(f"{ANSI['GREEN']}[OK]{ANSI['NC']}", msg)


def log_warn(msg):
    _out("warn", msg)
    cprint(f"{ANSI['YELLOW']}[!!]{ANSI['NC']}", msg)


def log_fail(msg):
    _out("fail", msg)
    cprint(f"{ANSI['RED']}[XX]{ANSI['NC']}", msg)


def log_info(msg):
    _out("info", msg)
    cprint(f"{ANSI['CYAN']}[>>]{ANSI['NC']}", msg)


def log_change(msg):
    _out("change", msg)
    cprint(f"{ANSI['GREEN']}[APPLY]{ANSI['NC']} {msg}")


def acquire_lock(nonblock=True):
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o644)
        flags = fcntl.LOCK_EX
        if nonblock:
            flags |= fcntl.LOCK_NB
        fcntl.flock(fd, flags)
        return fd
    except (OSError, IOError):
        return None


def release_lock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    except (OSError, IOError):
        pass


def api_healthcheck(token=None):
    try:
        if not token:
            token = get_authtoken()
        if not token:
            return False
        url = "http://localhost:9993/status"
        req = urllib.request.Request(url)
        req.add_header("X-ZT1-Auth", token)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return isinstance(data, dict) and "address" in data
    except Exception:
        return False


def get_authtoken():
    try:
        result = subprocess.run(
            ["docker", "exec", "ztnet_zerotier", "cat", "/var/lib/zerotier-one/authtoken.secret"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_zt_addr():
    try:
        result = subprocess.run(
            ["docker", "exec", "ztnet_zerotier", "zerotier-cli", "info"],
            capture_output=True, text=True, timeout=10
        )
        parts = result.stdout.strip().split()
        return parts[2] if len(parts) >= 3 else ""
    except Exception:
        return ""


def controller_api(method, path, data=None, token=None):
    if not token:
        token = get_authtoken()
    if not token:
        return None

    url = f"http://localhost:9993{path}"
    body = json.dumps(data).encode() if data else None

    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("X-ZT1-Auth", token)
    if data:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None


def get_networks_runtime():
    try:
        result = subprocess.run(
            ["docker", "exec", "ztnet_zerotier", "zerotier-cli", "-j", "listnetworks"],
            capture_output=True, text=True, timeout=10
        )
        return json.loads(result.stdout)
    except Exception:
        return []


def get_members_runtime(nwid, token):
    raw = controller_api("GET", f"/controller/network/{nwid}/member", token=token)
    if not raw or not isinstance(raw, dict):
        return {}

    members = {}
    for addr in raw:
        m = controller_api("GET", f"/controller/network/{nwid}/member/{addr}", token=token)
        if m:
            members[addr] = m
    return members


def load_env():
    env = {}
    if os.path.isfile(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    env[key.strip()] = val.strip()
    return env


def load_topology():
    if not os.path.isfile(TOPOLOGY_FILE):
        return None
    with open(TOPOLOGY_FILE) as f:
        return json.load(f)


def save_topology(topology):
    with open(TOPOLOGY_FILE, "w") as f:
        json.dump(topology, f, indent=2, ensure_ascii=False)
    os.chmod(TOPOLOGY_FILE, 0o600)


def rotate_log(max_size=512 * 1024):
    try:
        if os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > max_size:
            lines = open(LOG_FILE).readlines()
            with open(LOG_FILE, "w") as f:
                f.writelines(lines[-200:])
    except OSError:
        pass


def init_topology():
    token = get_authtoken()

    if not api_healthcheck(token):
        log_fail("Controller API healthcheck FAILED — cannot generate topology")
        sys.exit(1)

    zt_addr = get_zt_addr()
    env = load_env()
    networks = get_networks_runtime()

    log_info("Generating topology.json from current state...")
    topology = {
        "_meta": {
            "version": 1,
            "generated": datetime.now(timezone.utc).isoformat(),
            "zt_addr": zt_addr,
            "description": "Desired-state topology. Edit networks/members, then run zt-reconcile.py --apply",
        },
        "server": {
            "public_ip": env.get("PUBLIC_IP", ""),
            "main_iface": env.get("MAIN_IFACE", ""),
            "is_openvz": env.get("IS_OPENVZ", "false") == "true",
        },
        "networks": {},
    }

    for net in networks:
        if net.get("status") != "OK":
            continue
        nwid = net["id"]
        net_detail = controller_api("GET", f"/controller/network/{nwid}", token=token) or {}
        members_runtime = get_members_runtime(nwid, token)

        members_desired = {}
        for addr, m in members_runtime.items():
            members_desired[addr] = {
                "name": m.get("name", ""),
                "authorized": m.get("authorized", False),
                "ip_assignments": m.get("ipAssignments", []),
            }

        routes = net_detail.get("routes", [])
        has_default_route = any(r.get("target") == "0.0.0.0/0" for r in routes)

        subnet = ""
        pools = net_detail.get("ipAssignmentPools", [])
        if pools:
            start = pools[0].get("ipRangeStart", "")
            if start:
                parts = start.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        topology["networks"][nwid] = {
            "name": net.get("name", ""),
            "subnet": subnet,
            "role": "exit-node" if has_default_route else "mesh",
            "routes": routes,
            "members": members_desired,
        }

    save_topology(topology)
    log_ok(f"Topology saved to {TOPOLOGY_FILE}")
    log_ok(f"Networks: {len(topology['networks'])}")
    for nwid, nd in topology["networks"].items():
        log_info(f"  {nwid} ({nd['name']}): {nd['role']}, {len(nd['members'])} members")


def validate_topology(topology):
    errors = []
    warnings = []

    if not topology:
        return ["topology is None"], []

    if "networks" not in topology:
        return ["missing 'networks' key"], []

    exit_nodes = []
    for nwid, nd in topology.get("networks", {}).items():
        role = nd.get("role", "mesh")
        if role == "exit-node":
            routes = nd.get("routes", [])
            if not any(r.get("target") == "0.0.0.0/0" for r in routes):
                warnings.append(f"{nwid}: exit-node but no 0.0.0.0/0 route")
            exit_nodes.append(nwid)

        subnet = nd.get("subnet", "")
        if not subnet:
            warnings.append(f"{nwid}: no subnet defined")

        for addr, md in nd.get("members", {}).items():
            if not md.get("authorized", False):
                warnings.append(f"{nwid}/{addr}: member not authorized")

    if len(exit_nodes) > 1:
        errors.append(f"MULTIPLE exit-nodes: {exit_nodes}. Only ONE network should have role=exit-node")

    return errors, warnings


def reconcile(dry_run=True):
    global _changes_found
    _changes_found = False

    topology = load_topology()
    if not topology:
        log_fail(f"Topology file not found: {TOPOLOGY_FILE}")
        log_fail("Run: python3 zt-reconcile.py --init")
        return 1

    errors, warnings = validate_topology(topology)
    for e in errors:
        log_fail(f"VALIDATION ERROR: {e}")
    for w in warnings:
        log_warn(f"VALIDATION WARN: {w}")
    if errors:
        log_fail("Fix validation errors before applying")
        return 1

    token = get_authtoken()
    if not token:
        log_fail("Cannot get authtoken — controller unavailable?")
        return 1

    if not api_healthcheck(token):
        log_fail("Controller API healthcheck FAILED — aborting to prevent data loss")
        return 1

    zt_addr = topology.get("_meta", {}).get("zt_addr", get_zt_addr())
    changes = 0

    for nwid, desired in topology.get("networks", {}).items():
        actual_members = get_members_runtime(nwid, token)

        for addr, desired_member in desired.get("members", {}).items():
            actual = actual_members.get(addr, {})

            if actual.get("authorized") != desired_member.get("authorized"):
                action = "authorize" if desired_member["authorized"] else "deauthorize"
                log_change(f"{nwid}/{addr}: {action} (desired={desired_member['authorized']}, actual={actual.get('authorized')})")
                if not dry_run:
                    result = controller_api("POST", f"/controller/network/{nwid}/member/{addr}",
                                           {"authorized": desired_member["authorized"]}, token)
                    if result:
                        log_ok(f"  {addr}: {action}d")
                    else:
                        log_fail(f"  {addr}: failed to {action}")
                changes += 1

            desired_ips = desired_member.get("ip_assignments", [])
            actual_ips = actual.get("ipAssignments", [])
            if desired_ips and set(desired_ips) != set(actual_ips):
                log_change(f"{nwid}/{addr}: update IPs {actual_ips} -> {desired_ips}")
                if not dry_run:
                    result = controller_api("POST", f"/controller/network/{nwid}/member/{addr}",
                                           {"ipAssignments": desired_ips}, token)
                    if result:
                        log_ok(f"  {addr}: IPs updated")
                    else:
                        log_fail(f"  {addr}: failed to update IPs")
                changes += 1

        for addr in actual_members:
            if addr == zt_addr:
                continue
            if addr not in desired.get("members", {}):
                log_warn(f"{nwid}/{addr}: orphan (in controller, not in topology) — NOT deleting")

    if changes == 0:
        if not dry_run or os.isatty(sys.stdout.fileno()):
            log_ok("State is in sync. No changes needed.")
        else:
            logger.info("State is in sync. No changes needed.")
    elif dry_run:
        log_info(f"{changes} changes would be applied. Run with --apply to execute.")
    else:
        log_ok(f"{changes} changes applied.")

    return 0


def main():
    parser = argparse.ArgumentParser(description="ZeroTier Desired-State Reconciler")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")
    group.add_argument("--init", action="store_true", help="Generate topology.json from current state")
    group.add_argument("--validate", action="store_true", help="Validate topology.json schema")
    args = parser.parse_args()

    rotate_log()

    lock_fd = acquire_lock(nonblock=True)
    if lock_fd is None:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [RECONCILE] Lock contention — another instance holds {LOCK_FILE}. Exiting.")
        sys.exit(1)

    try:
        if args.init:
            init_topology()
        elif args.validate:
            topology = load_topology()
            if not topology:
                log_fail(f"Not found: {TOPOLOGY_FILE}")
                sys.exit(1)
            errors, warnings = validate_topology(topology)
            if errors:
                for e in errors:
                    log_fail(e)
                sys.exit(1)
            for w in warnings:
                log_warn(w)
            log_ok("Topology is valid")
        else:
            rc = reconcile(dry_run=not args.apply)
            sys.exit(rc)
    finally:
        release_lock(lock_fd)


if __name__ == "__main__":
    main()
