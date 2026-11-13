#!/usr/bin/env python3
import argparse
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path


CONFIG_PATH = Path("/etc/port-forwarder/config.yaml")
SYSCTL_PATH = Path("/etc/sysctl.d/99-port-forwarder.conf")
NAT_PREROUTING_CHAIN = "PORT_FORWARDER_PRE"
NAT_POSTROUTING_CHAIN = "PORT_FORWARDER_POST"
LEGACY_NAT_CHAIN = "PORT_FORWARDER"
FWD_CHAIN = "PORT_FORWARDER"


class ConfigError(Exception):
    pass


def run(cmd, check=True):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def iptables(*args, check=True):
    return run(["iptables", *args], check=check)


def parse_scalar(value):
    value = value.strip()
    if not value:
        return ""
    if value[0:1] in ("'", '"') and value[-1:] == value[0]:
        return value[1:-1]
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    if re.fullmatch(r"[0-9]+", value):
        return int(value)
    return value


def load_simple_yaml(path):
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")

    root = {}
    current_list_name = None
    current_item = None

    for lineno, raw_line in enumerate(path.read_text().splitlines(), 1):
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        if not line.startswith(" "):
            if ":" not in line:
                raise ConfigError(f"line {lineno}: expected key: value")
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value:
                root[key] = parse_scalar(value)
                current_list_name = None
            else:
                root[key] = []
                current_list_name = key
            current_item = None
            continue

        if current_list_name is None:
            raise ConfigError(f"line {lineno}: nested value without a list")

        stripped = line.strip()
        if stripped.startswith("- "):
            current_item = {}
            root[current_list_name].append(current_item)
            remainder = stripped[2:].strip()
            if remainder:
                if ":" not in remainder:
                    raise ConfigError(f"line {lineno}: expected key: value after '-'")
                key, value = remainder.split(":", 1)
                current_item[key.strip()] = parse_scalar(value)
            continue

        if current_item is None or ":" not in stripped:
            raise ConfigError(f"line {lineno}: expected list item key: value")
        key, value = stripped.split(":", 1)
        current_item[key.strip()] = parse_scalar(value)

    return root


def parse_port_range(value, label, index):
    text = str(value).strip()
    match = re.fullmatch(r"([0-9]+)(?:\s*[-:]\s*([0-9]+))?", text)
    if not match:
        raise ConfigError(
            f"mapping #{index}: {label} must be a port or range like 60020-60029"
        )

    start = int(match.group(1))
    end = int(match.group(2) or start)
    if start < 1 or end > 65535:
        raise ConfigError(f"mapping #{index}: {label} must be from 1 to 65535")
    if start > end:
        raise ConfigError(f"mapping #{index}: {label} range start must not exceed its end")
    return start, end


def normalize_mapping(item, index):
    aliases = {
        "source_port": "listen_port",
        "src_port": "listen_port",
        "port_source": "listen_port",
        "destination_port": "target_port",
        "dst_port": "target_port",
        "port_destination": "target_port",
        "destination_ip": "target_ip",
        "dst_ip": "target_ip",
        "ip_destination": "target_ip",
    }
    normalized = {}
    for key, value in item.items():
        normalized[aliases.get(key, key)] = value

    for key in ("listen_port", "target_port", "target_ip", "protocol"):
        if key not in normalized:
            raise ConfigError(f"mapping #{index}: missing required field '{key}'")

    proto = str(normalized["protocol"]).lower()
    if proto not in ("tcp", "udp"):
        raise ConfigError(f"mapping #{index}: protocol must be tcp or udp")

    listen_start, listen_end = parse_port_range(
        normalized["listen_port"], "listen_port", index
    )
    target_start, target_end = parse_port_range(
        normalized["target_port"], "target_port", index
    )
    listen_count = listen_end - listen_start + 1
    target_count = target_end - target_start + 1
    if listen_count != target_count:
        raise ConfigError(
            f"mapping #{index}: source and destination ranges must contain the same number of ports"
        )

    try:
        target_ip = str(ipaddress.ip_address(str(normalized["target_ip"])))
    except ValueError as exc:
        raise ConfigError(f"mapping #{index}: target_ip is not a valid IP address") from exc

    base_name = str(
        normalized.get(
            "name",
            f"{proto}_{listen_start}-{listen_end}_to_{target_ip}_{target_start}-{target_end}",
        )
    )
    mappings = []
    for offset in range(listen_count):
        listen_port = listen_start + offset
        target_port = target_start + offset
        name = base_name if listen_count == 1 else f"{base_name}_{listen_port}"
        mappings.append(
            {
                "name": name,
                "protocol": proto,
                "listen_port": listen_port,
                "target_ip": target_ip,
                "target_port": target_port,
            }
        )
    return mappings


def load_config(path):
    config = load_simple_yaml(path)
    mappings = config.get("mappings")
    if not isinstance(mappings, list) or not mappings:
        raise ConfigError("config must contain a non-empty 'mappings:' list")
    normalized = []
    for idx, item in enumerate(mappings, 1):
        normalized.extend(normalize_mapping(item, idx))
    return normalized


def ensure_chain(table, chain):
    iptables("-t", table, "-N", chain, check=False)
    iptables("-t", table, "-F", chain)


def ensure_jump(table, parent, chain):
    exists = iptables("-t", table, "-C", parent, "-j", chain, check=False)
    if exists.returncode != 0:
        iptables("-t", table, "-A", parent, "-j", chain)


def delete_jump(table, parent, chain):
    while iptables("-t", table, "-D", parent, "-j", chain, check=False).returncode == 0:
        pass


def delete_chain(table, chain):
    iptables("-t", table, "-F", chain, check=False)
    iptables("-t", table, "-X", chain, check=False)


def enable_forwarding():
    SYSCTL_PATH.write_text("net.ipv4.ip_forward = 1\n")
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])


def apply_rules(config_path):
    mappings = load_config(config_path)
    enable_forwarding()

    delete_jump("nat", "PREROUTING", LEGACY_NAT_CHAIN)
    delete_chain("nat", LEGACY_NAT_CHAIN)
    ensure_chain("nat", NAT_PREROUTING_CHAIN)
    ensure_chain("nat", NAT_POSTROUTING_CHAIN)
    ensure_chain("filter", FWD_CHAIN)
    ensure_jump("nat", "PREROUTING", NAT_PREROUTING_CHAIN)
    ensure_jump("nat", "POSTROUTING", NAT_POSTROUTING_CHAIN)
    ensure_jump("filter", "FORWARD", FWD_CHAIN)

    for item in mappings:
        proto = item["protocol"]
        listen_port = str(item["listen_port"])
        target_ip = item["target_ip"]
        target_port = str(item["target_port"])
        to_destination = f"{target_ip}:{target_port}"

        iptables(
            "-t", "nat", "-A", NAT_PREROUTING_CHAIN,
            "-p", proto, "--dport", listen_port,
            "-j", "DNAT", "--to-destination", to_destination,
        )
        iptables(
            "-t", "nat", "-A", NAT_POSTROUTING_CHAIN,
            "-p", proto, "-d", target_ip, "--dport", target_port,
            "-j", "MASQUERADE",
        )
        iptables(
            "-t", "filter", "-A", FWD_CHAIN,
            "-p", proto, "-d", target_ip, "--dport", target_port,
            "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        )
        iptables(
            "-t", "filter", "-A", FWD_CHAIN,
            "-p", proto, "-s", target_ip, "--sport", target_port,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        )

    print(f"applied {len(mappings)} forwarding mapping(s)")


def stop_rules():
    delete_jump("nat", "PREROUTING", NAT_PREROUTING_CHAIN)
    delete_jump("nat", "POSTROUTING", NAT_POSTROUTING_CHAIN)
    delete_jump("nat", "PREROUTING", LEGACY_NAT_CHAIN)
    delete_jump("filter", "FORWARD", FWD_CHAIN)
    delete_chain("nat", NAT_PREROUTING_CHAIN)
    delete_chain("nat", NAT_POSTROUTING_CHAIN)
    delete_chain("nat", LEGACY_NAT_CHAIN)
    delete_chain("filter", FWD_CHAIN)
    print("removed port-forwarder rules")


def status():
    print("NAT PREROUTING rules:")
    print(iptables("-t", "nat", "-S", NAT_PREROUTING_CHAIN, check=False).stdout.strip() or "(none)")
    print("\nNAT POSTROUTING rules:")
    print(iptables("-t", "nat", "-S", NAT_POSTROUTING_CHAIN, check=False).stdout.strip() or "(none)")
    print("\nFORWARD rules:")
    print(iptables("-t", "filter", "-S", FWD_CHAIN, check=False).stdout.strip() or "(none)")
    print("\nIPv4 forwarding:")
    print(run(["sysctl", "net.ipv4.ip_forward"]).stdout.strip())


def check_config(config_path):
    mappings = load_config(config_path)
    print(f"configuration is valid: {len(mappings)} forwarding mapping(s)")


def main():
    parser = argparse.ArgumentParser(description="Apply YAML-driven TCP/UDP port forwarding rules.")
    parser.add_argument("command", choices=["apply", "reload", "start", "stop", "status", "check"])
    parser.add_argument("-c", "--config", type=Path, default=CONFIG_PATH)
    args = parser.parse_args()

    if args.command != "check" and os.geteuid() != 0:
        print("must run as root", file=sys.stderr)
        return 1

    try:
        if args.command in ("apply", "reload", "start"):
            apply_rules(args.config)
        elif args.command == "stop":
            stop_rules()
        elif args.command == "status":
            status()
        elif args.command == "check":
            check_config(args.config)
    except (ConfigError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr.strip(), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
