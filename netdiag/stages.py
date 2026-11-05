"""Collect facts about this machine. These functions read and report. They do not judge."""
import glob
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import time
import xml.etree.ElementTree as ET

from netdiag.commands import error_text, run_command

PING_COUNT = 20
DEFAULT_TARGETS = ["1.1.1.1", "github.com", "s3.amazonaws.com"]
PING_LOSS = re.compile(r"([\d.]+)% packet loss")
PING_RTT = re.compile(r"= ([\d.]+)/([\d.]+)/")
PROCESS_NAME = re.compile(r'users:\(\("([^"]+)"')
IPTABLES_DPORT = re.compile(r"--dport (\d+)")
IPTABLES_PROTO = re.compile(r"-p (tcp|udp)")
IPTABLES_POLICY = re.compile(r"^-P INPUT (\w+)", re.M)
NFT_ACCEPT = re.compile(r"(tcp|udp) dport (\d+)[^\n]*accept")
NFT_DROP_POLICY = re.compile(r"hook input[^\n]*policy drop")
UFW_ALLOW = re.compile(r"^(\d+)(?:/(tcp|udp))?\s+ALLOW", re.M)
MAC_IN_TEXT = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
VIRTUAL_PORT_PREFIXES = ("tailscale", "docker", "veth", "br-", "virbr", "zt", "wg")
NMAP_TIMEOUT = 900  # seconds; a large network can take a few minutes to scan


def read_text(path):
    """Return the text of a file, or None if it cannot be read."""
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return None


def first_line(text):
    """Return the first non-empty line of some text, or None."""
    if not text:
        return None
    lines = text.strip().splitlines()
    return lines[0] if lines else None


def read_number(path):
    """Return a file's content as a whole number, or None if missing or negative."""
    text = read_text(path)
    if text is None:
        return None
    try:
        value = int(text.strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def system_facts():
    return {
        "os": os_name(),
        "jetson_release": first_line(read_text("/etc/nv_tegra_release")),
        "kernel": platform.release(),
        "interfaces": interface_facts(),
    }


def os_name():
    for line in (read_text("/etc/os-release") or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip('"')
    return None


def interface_facts():
    result = run_command(["ip", "-j", "addr"])
    if result["returncode"] != 0:
        return {"error": error_text(result)}
    interfaces = []
    for entry in json.loads(result["stdout"]):
        name = entry["ifname"]
        if name == "lo":
            continue
        interfaces.append({
            "name": name,
            "state": entry.get("operstate"),
            "mtu": entry.get("mtu"),
            "addresses": ipv4_addresses(entry),
            "speed_mbps": read_number("/sys/class/net/" + name + "/speed"),
            "carrier": read_number("/sys/class/net/" + name + "/carrier"),
            "physical": os.path.exists("/sys/class/net/" + name + "/device"),
            "duplex": first_line(read_text("/sys/class/net/" + name + "/duplex")),
        })
    return {"list": interfaces}


def ipv4_addresses(entry):
    return [
        {"ip": info["local"], "prefix": info["prefixlen"], "dynamic": bool(info.get("dynamic"))}
        for info in entry.get("addr_info", [])
        if info.get("family") == "inet"
    ]


def find_interface(system, name):
    for iface in system["interfaces"].get("list", []):
        if iface["name"] == name:
            return iface
    return None


def local_facts():
    return {
        "default_routes": default_routes(),
        "dns_servers": dns_servers(),
        "ports": port_facts(),
        "firewall": firewall_facts(),
    }


def default_routes():
    result = run_command(["ip", "-j", "route", "show", "default"])
    if result["returncode"] != 0:
        return {"error": error_text(result)}
    return [
        {"gateway": route.get("gateway"), "interface": route.get("dev")}
        for route in json.loads(result["stdout"] or "[]")
    ]


def dns_servers():
    text = read_text("/etc/resolv.conf") or ""
    return [line.split()[1] for line in text.splitlines() if line.startswith("nameserver ")]


def port_facts():
    """List every listening TCP and UDP port, and whether the boat network can reach it."""
    result = run_command(["ss", "-H", "-tulnp"], privileged=True)
    if result["returncode"] != 0:
        return {"error": error_text(result)}
    ports = []
    for line in result["stdout"].splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        address, port = parts[4].rsplit(":", 1)
        found = PROCESS_NAME.search(line)
        ports.append({
            "proto": parts[0],
            "address": address,
            "port": int(port),
            "process": found.group(1) if found else None,
            "exposed": not is_local(address),
        })
    return {"list": sorted(ports, key=lambda item: (item["proto"], item["port"]))}


def is_local(address):
    """True when a listener only accepts connections from this machine."""
    return address.startswith("127.") or address == "[::1]"


def firewall_facts():
    """Read the firewall rules from each firewall tool that is present."""
    backends = {"ufw": ufw_facts(), "iptables": iptables_facts(), "nft": nft_facts()}
    usable = {name: part for name, part in backends.items() if is_usable(part)}
    errors = {name: part["error"] for name, part in backends.items() if "error" in part}
    return {
        "default_incoming": combined_default(usable),
        "allowed_ports": [entry for part in usable.values() for entry in part["allowed_ports"]],
        "errors": errors,
        "backends": backends,
    }


def is_usable(part):
    return "error" not in part and part.get("active", True) and not part.get("absent", False)


def combined_default(usable):
    """Incoming traffic is blocked by default if any firewall layer blocks it."""
    if not usable:
        return "unknown"
    if any(part["default_incoming"] == "deny" for part in usable.values()):
        return "deny"
    return "allow"


def ufw_facts():
    result = run_command(["ufw", "status", "verbose"], privileged=True)
    if not result["available"]:
        return {"absent": True}
    if result["returncode"] != 0:
        return {"error": error_text(result)}
    text = result["stdout"]
    if "Status: active" not in text:
        return {"active": False}
    return {
        "active": True,
        "default_incoming": "deny" if "deny (incoming)" in text else "allow",
        "allowed_ports": [
            {"port": int(port), "proto": proto or None}
            for port, proto in UFW_ALLOW.findall(text)
        ],
        "raw": text,
    }


def iptables_facts():
    result = run_command(["iptables", "-S"], privileged=True)
    if not result["available"]:
        return {"absent": True}
    if result["returncode"] != 0:
        return {"error": error_text(result)}
    text = result["stdout"]
    allowed = []
    for line in text.splitlines():
        port = IPTABLES_DPORT.search(line)
        if line.startswith("-A INPUT") and "-j ACCEPT" in line and port:
            proto = IPTABLES_PROTO.search(line)
            allowed.append({"port": int(port.group(1)), "proto": proto.group(1) if proto else None})
    policy = IPTABLES_POLICY.search(text)
    blocks = policy is not None and policy.group(1) in ("DROP", "REJECT")
    return {
        "default_incoming": "deny" if blocks else "allow",
        "allowed_ports": allowed,
        "raw": text,
    }


def nft_facts():
    result = run_command(["nft", "list", "ruleset"], privileged=True)
    if not result["available"]:
        return {"absent": True}
    if result["returncode"] != 0:
        return {"error": error_text(result)}
    text = result["stdout"]
    blocks = NFT_DROP_POLICY.search(text) is not None
    allowed = [{"port": int(port), "proto": proto} for proto, port in NFT_ACCEPT.findall(text)]
    return {
        "default_incoming": "deny" if blocks else "allow",
        "allowed_ports": allowed,
        "raw": text,
    }


def lan_facts(route, system):
    """Check the boat router, the devkit's own address, and the devices on its subnet."""
    if route is None or route["gateway"] is None:
        return {"gateway": None}
    interface = route["interface"]
    return {
        "gateway": route["gateway"],
        "interface": interface,
        "ping": ping_facts(route["gateway"]),
        "neighbours": neighbour_count(),
        "duplicate": own_address_check(interface, system),
        "networks": scan_networks(system),
    }


def own_address_check(interface, system):
    iface = find_interface(system, interface)
    if iface is None or not iface["addresses"]:
        return {"absent": True}
    return duplicate_ip_facts(interface, iface["addresses"][0]["ip"])


def duplicate_ip_facts(interface, ip):
    """Ask the local network whether another device answers for this IP (duplicate address detection)."""
    result = run_command(
        ["arping", "-D", "-c", "2", "-w", "5", "-I", interface, ip], timeout=30, privileged=True,
    )
    if not result["available"]:
        return {"ip": ip, "absent": True}
    if result["returncode"] == 0:
        return {"ip": ip, "conflict": False}
    if result["returncode"] == 1:
        found = MAC_IN_TEXT.search(result["stdout"] + result["stderr"])
        return {"ip": ip, "conflict": True, "other_mac": found.group(1) if found else None}
    return {"ip": ip, "error": error_text(result)}


def scanned_networks(system):
    """Every real network port with an IPv4 address: the boat LAN, Wi-Fi, and any other."""
    networks = []
    for iface in system["interfaces"].get("list", []):
        if iface["name"].startswith(VIRTUAL_PORT_PREFIXES) or not iface["addresses"]:
            continue
        addr = iface["addresses"][0]
        network = ipaddress.ip_interface(addr["ip"] + "/" + str(addr["prefix"])).network
        networks.append({"interface": iface["name"], "address": addr["ip"], "network": str(network)})
    return networks


def scan_networks(system):
    """Find the devices on every network the devkit is on. Always runs: a missing tool is reported, not skipped."""
    results = []
    for net in scanned_networks(system):
        scan = nmap_scan(net["network"])
        net["nmap"] = scan["status"]
        net["error"] = scan.get("error")
        net["devices"] = merge_devices(scan.get("devices", []), neighbour_entries(net["interface"]))
        results.append(net)
    return results


def nmap_scan(network):
    """Ping every address on the network with nmap. Status is ok, absent (not installed), or error."""
    result = run_command(["nmap", "-sn", "-n", "-oX", "-", network], timeout=NMAP_TIMEOUT, privileged=True)
    if not result["available"]:
        return {"status": "absent"}
    if result["returncode"] != 0:
        return {"status": "error", "error": error_text(result)}
    return {"status": "ok", "devices": parse_nmap_xml(result["stdout"])}


def neighbour_entries(interface):
    """Devices this machine has talked to recently, from the kernel's neighbour table. Sends no traffic."""
    result = run_command(["ip", "-j", "neigh", "show", "dev", interface])
    if result["returncode"] != 0:
        return []
    entries = []
    for entry in json.loads(result["stdout"] or "[]"):
        state = entry.get("state", [])
        state = " ".join(state) if isinstance(state, list) else str(state)
        if not entry.get("lladdr") or state in ("FAILED", "INCOMPLETE"):
            continue
        entries.append({"ip": entry["dst"], "mac": entry["lladdr"], "state": state})
    return entries


def merge_devices(scanned, neighbours):
    """One row per IP address, showing how each device was seen: by the ping scan, the neighbour table, or both."""
    by_ip = {}
    for device in scanned:
        if device["ip"] is None:
            continue
        by_ip[device["ip"]] = {"ip": device["ip"], "mac": device["mac"], "vendor": device["vendor"],
                               "seen": ["ping"], "state": None}
    for entry in neighbours:
        device = by_ip.get(entry["ip"])
        if device is None:
            device = {"ip": entry["ip"], "mac": None, "vendor": None, "seen": [], "state": None}
            by_ip[entry["ip"]] = device
        device["mac"] = device["mac"] or entry["mac"]
        device["seen"].append("neighbour table")
        device["state"] = entry["state"]
    return sorted(by_ip.values(), key=lambda device: ipaddress.ip_address(device["ip"]))


def parse_nmap_xml(text):
    devices = []
    for host in ET.fromstring(text).findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = None
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip = address.get("addr")
            if address.get("addrtype") == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor")
        devices.append({"ip": ip, "mac": mac, "vendor": vendor})
    return devices


def neighbour_count():
    result = run_command(["ip", "-j", "neigh"])
    if result["returncode"] != 0:
        return None
    return len(json.loads(result["stdout"] or "[]"))


def path_facts(targets):
    return {host: {"ping": ping_facts(host), "dns_ms": dns_lookup_ms(host)} for host in targets}


def dns_lookup_ms(host):
    start = time.monotonic()
    try:
        socket.getaddrinfo(host, 443)
    except socket.gaierror:
        return None
    return round((time.monotonic() - start) * 1000, 1)


def ping_facts(host):
    result = run_command(
        ["ping", "-c", str(PING_COUNT), "-i", "0.2", "-W", "2", host],
        timeout=PING_COUNT * 2 + 20,
    )
    if not result["available"]:
        return {"error": result["stderr"]}
    stats = parse_ping(result["stdout"])
    if stats is None:
        return {"error": result["stderr"].strip() or "no ping statistics printed"}
    return stats


def parse_ping(text):
    """Read the packet loss and the average round trip from ping's summary."""
    loss = PING_LOSS.search(text)
    if loss is None:
        return None
    rtt = PING_RTT.search(text)
    return {
        "loss_percent": float(loss.group(1)),
        "avg_ms": float(rtt.group(2)) if rtt else None,
    }


def resource_facts():
    """Measure how busy the machine is, and whether a cap or heat is holding it back."""
    return {
        "cpus": os.cpu_count(),
        "load_1_5_15": [round(value, 2) for value in os.getloadavg()],
        "cpu_busy_percent": cpu_busy_percent(),
        "memory": memory_facts(),
        "disk_root_percent": disk_percent("/"),
        "cgroup": cgroup_limits(),
        "cpu_clock": cpu_clock_facts(),
        "thermal_max_c": hottest_zone_c(),
        "jetson_power_mode": jetson_power_mode(),
        "top_processes": top_processes(),
    }


def read_cpu_times():
    """Return (idle, total) counts for all CPUs, from the first line of /proc/stat."""
    fields = read_text("/proc/stat").splitlines()[0].split()[1:]
    values = [int(value) for value in fields[:8]]
    idle = values[3] + values[4]
    return idle, sum(values)


def cpu_busy_percent():
    """Sample the CPU for one second and return the percent of time it was busy."""
    try:
        idle_before, total_before = read_cpu_times()
        time.sleep(1)
        idle_after, total_after = read_cpu_times()
    except (AttributeError, IndexError, OSError, ValueError):
        return None
    total = total_after - total_before
    if total <= 0:
        return None
    return round(100 * (1 - (idle_after - idle_before) / total), 1)


def memory_facts():
    values = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            values[parts[0][:-1]] = int(parts[1]) // 1024
    swap_total = values.get("SwapTotal", 0)
    return {
        "total_mb": values.get("MemTotal"),
        "available_mb": values.get("MemAvailable"),
        "swap_total_mb": swap_total,
        "swap_used_mb": swap_total - values.get("SwapFree", 0),
    }


def disk_percent(path):
    usage = shutil.disk_usage(path)
    return round(100 * (usage.total - usage.free) / usage.total, 1)


def cgroup_limits():
    """Read the CPU and memory caps on the cgroup this check is running in."""
    relative = cgroup_path()
    base = "/sys/fs/cgroup" + relative
    cpu_max = first_line(read_text(base + "/cpu.max")) or ""
    mem_max = first_line(read_text(base + "/memory.max")) or ""
    quota_cores = None
    if cpu_max and not cpu_max.startswith("max"):
        quota, period = cpu_max.split()[:2]
        quota_cores = round(int(quota) / int(period), 2)
    memory_limit_mb = None
    if mem_max.isdigit():
        memory_limit_mb = int(mem_max) // (1024 * 1024)
    return {"path": relative, "cpu_quota_cores": quota_cores, "memory_limit_mb": memory_limit_mb}


def cgroup_path():
    """Return this process's cgroup v2 path, such as /system.slice/example.service."""
    for line in (read_text("/proc/self/cgroup") or "").splitlines():
        if line.startswith("0::"):
            return line[3:]
    return ""


def cpu_clock_facts():
    base = "/sys/devices/system/cpu/cpu0/cpufreq/"
    current = read_number(base + "scaling_cur_freq")
    maximum = read_number(base + "cpuinfo_max_freq")
    return {
        "current_mhz": current // 1000 if current else None,
        "max_mhz": maximum // 1000 if maximum else None,
        "governor": first_line(read_text(base + "scaling_governor")),
    }


def hottest_zone_c():
    temps = []
    for path in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        value = read_number(path)
        if value is not None:
            temps.append(value / 1000)
    return max(temps) if temps else None


def jetson_power_mode():
    """Return the Jetson power mode name (for example MAXN), or None on other machines."""
    result = run_command(["nvpmodel", "-q"])
    if not result["available"] or result["returncode"] != 0:
        return None
    for line in result["stdout"].splitlines():
        if line.startswith("NV Power Mode"):
            return line.split(":", 1)[1].strip()
    return None


def top_processes():
    result = run_command(["ps", "-eo", "comm,pcpu,pmem", "--sort=-pcpu"])
    if result["returncode"] != 0:
        return []
    rows = []
    for line in result["stdout"].splitlines()[1:]:
        parts = line.rsplit(None, 2)
        if len(parts) == 3 and parts[0] != "ps":
            if len(rows) == 5:
                break
            rows.append({"name": parts[0], "cpu_percent": float(parts[1]), "mem_percent": float(parts[2])})
    return rows


CAPTURE_SECONDS = 30
CAPTURE_PACKET = re.compile("^[0-9.]+ IP ([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)(?:[.]([0-9]+))? > ([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)(?:[.]([0-9]+))?:")


def capture_network(net):
    """Listen on one network for 30 seconds and summarise what is seen. Sends nothing; it only listens."""
    result = run_command(
        ["timeout", str(CAPTURE_SECONDS), "tcpdump", "-i", net["interface"], "-nn", "-l", "-tt"],
        timeout=CAPTURE_SECONDS + 60, privileged=True,
    )
    if not result["available"]:
        return {"interface": net["interface"], "error": "tcpdump is not installed"}
    if not result["stdout"].strip():
        return {"interface": net["interface"], "error": error_text(result)}
    summary = parse_capture(result["stdout"])
    summary.update({"interface": net["interface"], "seconds": CAPTURE_SECONDS})
    return summary


def parse_capture(text):
    """Count what a capture shows: packets, ARP requests, multicast, DNS, and the busiest sources and ports."""
    from collections import Counter
    packets = arp_requests = multicast = dns = 0
    sources = Counter()
    ports = Counter()
    for line in text.splitlines():
        if re.match("^[0-9]+[.][0-9]+ ", line):
            packets += 1
        if " ARP, Request" in line:
            arp_requests += 1
        match = CAPTURE_PACKET.match(line)
        if not match:
            continue
        src, dst, dst_port = match.group(1), match.group(3), match.group(4)
        sources[src] += 1
        if dst_port:
            ports[int(dst_port)] += 1
        if dst_port == "53":
            dns += 1
        if int(dst.split(".")[0]) in range(224, 240):
            multicast += 1
    return {
        "packets": packets,
        "arp_requests": arp_requests,
        "multicast_packets": multicast,
        "dns_queries": dns,
        "top_sources": sources.most_common(5),
        "top_ports": ports.most_common(5),
    }
