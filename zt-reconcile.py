#!/usr/bin/env python3
"""
ZeroTier Desired-State Reconciler (P2: Declarative Control Plane)

Reads topology.json (desired state) and reconciles actual ZT state.
Safe operations only — never deletes members, only authorizes and sets IPs.

Usage:
    python3 zt-reconcile.py                    # dry-run (show diff)
    python3 zt-reconcile.py --apply             # apply changes
    python3 zt-reconcile.py --init              # generate topology.json from current state
    python3 zt-reconcile.py --validate          # validate topology.json schema
"""

import json
import sys
import os
import subprocess
import urllib.request
import urllib.error
import argparse
from datetime import datetime, timezone
from pathlib import Path

INSTALL_DIR = os.environ.get("INSTALL_DIR", "/opt/ztnet")
TOPOLOGY_FILE = os.path.join(INSTALL_DIR, "topology.json")
ENV_FILE = os.path.join(INSTALL_DIR, ".env.info")

ANSI = {
    "RED": "\033[0;31m",
    "GREEN": "\033[0;32m",
    "YELLOW": "\033[1;33m",
    "CYAN": "\033[0;36m",
    "BOLD": "\033[1m",
    "NC": "\033[0m",
}


def log(msg):
    print(f"{ANSI['GREEN']}[OK]{ANSI['NC']} {msg}")


def warn(msg):
    print(f"{ANSI['YELLOW']}[!!]{ANSI['NC']} {msg}")


def fail(msg):
    print(f"{ANSI['RED']}[XX]{ANSI['NC']} {msg}")


def info(msg):
    print(f"{ANSI['CYAN']}[>>]{ANSI['NC']} {msg}")


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


def init_topology():
    info("Generating topology.json from current state...")
    token = get_authtoken()
    zt_addr = get_zt_addr()
    env = load_env()
    networks = get_networks_runtime()

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
    log(f"Topology saved to {TOPOLOGY_FILE}")
    log(f"Networks: {len(topology['networks'])}")
    for nwid, nd in topology["networks"].items():
        info(f"  {nwid} ({nd['name']}): {nd['role']}, {len(nd['members'])} members")


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
    topology = load_topology()
    if not topology:
        fail(f"Topology file not found: {TOPOLOGY_FILE}")
        fail("Run: python3 zt-reconcile.py --init")
        return 1

    errors, warnings = validate_topology(topology)
    for e in errors:
        fail(f"VALIDATION ERROR: {e}")
    for w in warnings:
        warn(f"VALIDATION WARN: {w}")
    if errors:
        fail("Fix validation errors before applying")
        return 1

    token = get_authtoken()
    if not token:
        fail("Cannot get authtoken")
        return 1

    zt_addr = topology.get("_meta", {}).get("zt_addr", get_zt_addr())
    changes = 0

    for nwid, desired in topology.get("networks", {}).items():
        info(f"Network {nwid} ({desired.get('name', '?')}):")

        actual_members = get_members_runtime(nwid, token)

        for addr, desired_member in desired.get("members", {}).items():
            actual = actual_members.get(addr, {})

            if actual.get("authorized") != desired_member.get("authorized"):
                action = "authorize" if desired_member["authorized"] else "deauthorize"
                info(f"  {addr}: {action} (desired={desired_member['authorized']}, actual={actual.get('authorized')})")
                if not dry_run:
                    result = controller_api("POST", f"/controller/network/{nwid}/member/{addr}",
                                           {"authorized": desired_member["authorized"]}, token)
                    if result:
                        log(f"  {addr}: {action}d")
                    else:
                        fail(f"  {addr}: failed to {action}")
                changes += 1

            desired_ips = desired_member.get("ip_assignments", [])
            actual_ips = actual.get("ipAssignments", [])
            if desired_ips and set(desired_ips) != set(actual_ips):
                info(f"  {addr}: update IPs {actual_ips} -> {desired_ips}")
                if not dry_run:
                    result = controller_api("POST", f"/controller/network/{nwid}/member/{addr}",
                                           {"ipAssignments": desired_ips}, token)
                    if result:
                        log(f"  {addr}: IPs updated")
                    else:
                        fail(f"  {addr}: failed to update IPs")
                changes += 1

        for addr in actual_members:
            if addr == zt_addr:
                continue
            if addr not in desired.get("members", {}):
                warn(f"  {addr}: exists in controller but NOT in topology (orphan)")
                warn(f"  NOT deleting — add to topology.json to manage, or ignore")

    if changes == 0:
        log("Desired state matches actual state. No changes needed.")
    elif dry_run:
        info(f"{changes} changes would be applied. Run with --apply to execute.")
    else:
        log(f"{changes} changes applied.")

    return 0


def main():
    parser = argparse.ArgumentParser(description="ZeroTier Desired-State Reconciler")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")
    group.add_argument("--init", action="store_true", help="Generate topology.json from current state")
    group.add_argument("--validate", action="store_true", help="Validate topology.json schema")
    args = parser.parse_args()

    if args.init:
        init_topology()
    elif args.validate:
        topology = load_topology()
        if not topology:
            fail(f"Not found: {TOPOLOGY_FILE}")
            sys.exit(1)
        errors, warnings = validate_topology(topology)
        if errors:
            for e in errors:
                fail(e)
            sys.exit(1)
        for w in warnings:
            warn(w)
        log("Topology is valid")
    else:
        sys.exit(reconcile(dry_run=not args.apply))


if __name__ == "__main__":
    main()
