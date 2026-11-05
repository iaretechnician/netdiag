"""Turn facts into findings. Each rule reads one kind of fact and compares it with a plain limit."""
import ipaddress

LOSS_LIMIT = 2.0             # percent of pings lost
GATEWAY_RTT_LIMIT = 10.0     # ms to the boat router
INTERNET_RTT_LIMIT = 150.0   # ms; VNC starts to feel slow above about this
DNS_LIMIT = 200.0            # ms for one name lookup
SLOW_LINK_MBPS = 100
VNC_PORT = 5900
NORMAL_MTU = 1500
CPU_BUSY_LIMIT = 90.0
LOAD_PER_CPU_LIMIT = 1.5
MEM_FREE_LIMIT = 10.0
SWAP_USED_LIMIT = 50.0
DISK_LIMIT = 90.0
HOT_C = 85.0
CLOCK_LOW_RATIO = 0.6
CLOCK_BUSY_PERCENT = 50.0
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def finding(severity, title, detail, next_step):
    return {"severity": severity, "title": title, "detail": detail, "next_step": next_step}


def main_route(local):
    routes = local["default_routes"]
    if isinstance(routes, list) and routes:
        return routes[0]
    return None


def find_interface(system, name):
    for iface in system["interfaces"].get("list", []):
        if iface["name"] == name:
            return iface
    return None


def analyse(facts):
    findings = []
    findings += route_findings(facts["local"])
    findings += config_findings(facts)
    findings += firewall_findings(facts["local"])
    findings += vnc_findings(facts["local"]["ports"])
    findings += resource_findings(facts["resources"])
    findings += link_findings(facts["system"])
    findings += gateway_findings(facts["lan"])
    findings += device_findings(facts["lan"])
    findings += same_mac_findings(facts["lan"])
    if "capture" in facts:
        findings += capture_findings(facts["capture"])
    if "path" in facts:
        findings += path_findings(facts["path"], facts["lan"])
    findings += module_findings(facts)
    findings += extra_findings(facts)
    return sorted(findings, key=lambda item: SEVERITY_ORDER[item["severity"]])


def extra_findings(facts):
    """Pressure and the remote PC, when the facts were collected."""
    from netdiag import pressure, remote
    out = []
    if "pressure" in facts:
        out += pressure.pressure_findings(facts["pressure"])
    if "remote" in facts:
        out += remote.remote_findings(facts["remote"])
    return out


def module_findings(facts):
    """Run the rules of each selected module. A module that fails is reported, not fatal."""
    from netdiag.plugin import load_modules
    modules = load_modules()
    findings = []
    for name in facts.get("selected_modules", []):
        try:
            findings += modules[name].rules(facts)
        except Exception as error:
            findings.append(finding(
                "warning", "The " + name + " checks could not run", str(error),
                "Run the check again with the same flags. If it repeats, include the report when you ask for help."))
    return findings


def route_findings(local):
    routes = local["default_routes"]
    if isinstance(routes, dict):
        return [finding(
            "warning",
            "Could not read the routes",
            routes["error"],
            "Run `ip route` by hand and check that the iproute2 package is installed.",
        )]
    if not routes:
        return [finding(
            "critical",
            "No default route",
            "The devkit has no route out of its own network, so nothing outside the boat can be reached.",
            "Check the network cable and the router settings. Run `ip route` to see the routes.",
        )]
    if len(routes) > 1:
        via = ", ".join(str(route["gateway"]) + " via " + str(route["interface"]) for route in routes)
        return [finding(
            "warning",
            "There are " + str(len(routes)) + " default routes",
            "Traffic may leave through the wrong one: " + via + ".",
            "Remove the extra default route, or give one route a lower metric so it is always preferred.",
        )]
    return []


def config_findings(facts):
    findings = []
    findings += address_findings(facts["system"])
    findings += gateway_subnet_findings(facts)
    findings += dns_findings(facts["local"])
    findings += mtu_findings(facts)
    findings += duplicate_findings(facts["lan"])
    return findings


def address_findings(system):
    findings = []
    for iface in system["interfaces"].get("list", []):
        if iface["state"] != "UP":
            continue
        for addr in iface["addresses"]:
            ip = ipaddress.ip_address(addr["ip"])
            network = ipaddress.ip_interface(addr["ip"] + "/" + str(addr["prefix"])).network
            if addr["ip"].startswith("169.254."):
                findings.append(finding(
                    "critical",
                    iface["name"] + " has only a 169.254 fallback address",
                    "No DHCP address was received, so the devkit picked a link-local address. It cannot reach the boat router.",
                    "Check that the DHCP server on the boat router is on and serving this port. Or set a static address on the router's subnet.",
                ))
            elif network.num_addresses > 2 and ip in (network.network_address, network.broadcast_address):
                findings.append(finding(
                    "critical",
                    iface["name"] + " uses " + str(ip) + ", the network or broadcast address",
                    "Devices cannot use this address. Packets for it are dropped or sent to everyone on the subnet.",
                    "Use a host address inside " + str(network) + ", for example " + str(network.network_address + 1) + ".",
                ))
    return findings


def gateway_subnet_findings(facts):
    route = main_route(facts["local"])
    if route is None or route["gateway"] is None:
        return []
    iface = find_interface(facts["system"], route["interface"])
    if iface is None or not iface["addresses"]:
        return []
    addr = iface["addresses"][0]
    network = ipaddress.ip_interface(addr["ip"] + "/" + str(addr["prefix"])).network
    gateway = ipaddress.ip_address(route["gateway"])
    if gateway in network:
        return []
    return [finding(
        "critical",
        "Gateway " + str(gateway) + " is outside the devkit's subnet",
        iface["name"] + " is " + addr["ip"] + "/" + str(addr["prefix"]) + " (mask " + str(network.netmask)
        + "), so it only reaches " + str(network) + ". The gateway is not in that range, so the default route cannot work.",
        "Make the address, mask, and gateway match. Example: a router at 192.168.1.1 works with 192.168.1.20 and mask 255.255.255.0 (/24).",
    )]


def dns_findings(local):
    if local["dns_servers"]:
        return []
    return [finding(
        "warning",
        "No DNS servers are set",
        "Names such as github.com cannot be looked up.",
        "Set a DNS server, or check the DHCP settings on the boat router.",
    )]


def mtu_findings(facts):
    route = main_route(facts["local"])
    if route is None:
        return []
    iface = find_interface(facts["system"], route["interface"])
    if iface is None or iface["mtu"] in (None, NORMAL_MTU):
        return []
    return [finding(
        "info",
        iface["name"] + " MTU is " + str(iface["mtu"]),
        "Most networks use " + str(NORMAL_MTU) + ". A different value can make large transfers stall, which VNC notices.",
        "Set the MTU to match the boat router, or set it back to " + str(NORMAL_MTU) + ".",
    )]


def duplicate_findings(lan):
    dup = lan.get("duplicate") or {}
    if not dup.get("conflict"):
        return []
    mac = dup.get("other_mac") or "unknown (see the device list in the report)"
    return [finding(
        "critical",
        "Another device is using this devkit's address " + dup["ip"],
        "A second device with MAC " + mac + " answers for " + dup["ip"] + ". Connections to the devkit drop or go to the wrong device.",
        "Give one of the two devices a different address, or a fixed DHCP address on the router.",
    )]


def firewall_findings(local):
    firewall = local["firewall"]
    if firewall["default_incoming"] == "unknown":
        return [finding(
            "info",
            "Could not read the firewall rules",
            describe_errors(firewall["errors"]) or "No firewall tool was found on this machine.",
            "Run the check with sudo, or install the firewall tools (iptables, nftables).",
        )]
    if firewall["default_incoming"] != "deny":
        return []
    exposed = [item for item in local["ports"].get("list", []) if item["exposed"]]
    blocked = [item for item in exposed if not is_allowed(item, firewall["allowed_ports"])]
    if not blocked:
        return []
    names = [str(item["port"]) + "/" + item["proto"] + " (" + (item["process"] or "unknown") + ")" for item in blocked]
    return [finding(
        "info",
        str(len(blocked)) + " listening port(s) are blocked by the firewall",
        "The firewall blocks incoming traffic by default and has no rule for: " + ", ".join(names)
        + ". This is predicted from the rules. A probe from outside would confirm it.",
        "Open a port only if customers need it. Otherwise no action is needed.",
    )]


def is_allowed(item, allowed):
    return any(rule["port"] == item["port"] and rule["proto"] in (None, item["proto"]) for rule in allowed)


def describe_errors(errors):
    return "; ".join(name + ": " + text for name, text in errors.items())


def vnc_findings(ports):
    entries = ports.get("list", [])
    vnc = [item for item in entries if item["port"] == VNC_PORT and item["proto"] == "tcp"]
    if not vnc:
        return [finding(
            "info",
            "Nothing is listening on the VNC port (" + str(VNC_PORT) + ")",
            "This is normal if VNC is not running on this devkit.",
            "Start the VNC server if customers should connect to this devkit.",
        )]
    if not any(item["exposed"] for item in vnc):
        return [finding(
            "info",
            "VNC listens only on this machine",
            "Nobody on the boat network can reach VNC, because it accepts connections from localhost only.",
            "Set VNC to listen on the network interface if customers should connect to it.",
        )]
    return []


def no_link_findings(iface):
    """A real port that has an address but no cable link. Unused ports without an address are not reported."""
    if not iface.get("physical") or iface.get("carrier") != 0 or not iface["addresses"]:
        return []
    return [finding(
        "critical", "Port " + iface["name"] + " is set up but has no link",
        "The port has an address, but no cable is connected, the cable is bad, or the switch port is off.",
        "Check the cable at both ends and the switch port light. Then run netdiag --nic for the port's counters.",
    )]


def no_ip_findings(iface):
    """A real port with a working link but no IPv4 address: the DHCP server did not answer, or the port is not set up."""
    if not iface.get("physical") or iface.get("carrier") != 1 or iface["addresses"]:
        return []
    return [finding(
        "warning", "Port " + iface["name"] + " has a link but no IPv4 address",
        "The cable works, but the port has no address, so it cannot reach the network.",
        "Check that the port is set up to get an address (netplan, NetworkManager or systemd-networkd), and that its switch port is on a network with DHCP.",
    )]


def link_findings(system):
    findings = []
    for iface in system["interfaces"].get("list", []):
        findings += no_link_findings(iface)
        findings += no_ip_findings(iface)
        if iface["state"] != "UP":
            continue
        speed = iface["speed_mbps"]
        if speed is not None and speed < SLOW_LINK_MBPS:
            findings.append(finding(
                "warning",
                "Link on " + iface["name"] + " runs at " + str(speed) + " Mb/s",
                "A link this slow limits VNC picture quality and speed.",
                "Check the cable and the switch port. A 10 or 100 Mb/s limit often means a bad cable or a port set to a slow speed.",
            ))
        if iface["duplex"] == "Half":
            findings.append(finding(
                "warning",
                "Link on " + iface["name"] + " is half duplex",
                "Half duplex makes the link slow and lossy under load.",
                "Set the switch port and the devkit to full duplex, or check the cable.",
            ))
    return findings


def gateway_findings(lan):
    if lan.get("gateway") is None:
        return []
    gateway = lan["gateway"]
    ping = lan["ping"]
    if "error" in ping:
        return [finding(
            "critical",
            "No replies from the boat router (" + gateway + ")",
            ping["error"],
            "Check the router's power, the cable, and that the devkit is on the router's network.",
        )]
    if ping["loss_percent"] >= LOSS_LIMIT:
        return [finding(
            "critical",
            "Packet loss to the boat router: " + str(ping["loss_percent"]) + "%",
            "Packet loss between the devkit and the router affects every device on the boat network.",
            "Check the cable or Wi-Fi link between the devkit and the router.",
        )]
    if ping["avg_ms"] is not None and ping["avg_ms"] > GATEWAY_RTT_LIMIT:
        return [finding(
            "warning",
            "Slow replies from the boat router: " + str(ping["avg_ms"]) + " ms",
            "Replies this slow point to a busy switch or to Wi-Fi interference.",
            "Check the switch load and any Wi-Fi link. Run the check again when the boat network is quiet.",
        )]
    return []


def path_findings(path, lan):
    gateway_ok = gateway_is_healthy(lan)
    findings = []
    for host, data in path.items():
        findings += host_findings(host, data, gateway_ok)
    return findings


def gateway_is_healthy(lan):
    ping = lan.get("ping") or {}
    return "error" not in ping and ping.get("loss_percent", 100.0) < LOSS_LIMIT


def host_findings(host, data, gateway_ok):
    ping = data["ping"]
    if "error" in ping:
        return [finding(
            "critical",
            "No replies from " + host,
            ping["error"],
            "If the boat router is fine, the problem is past it: check the boat's internet link or modem.",
        )]
    findings = []
    if ping["loss_percent"] >= LOSS_LIMIT and gateway_ok:
        findings.append(finding(
            "warning",
            "Packet loss to " + host + ": " + str(ping["loss_percent"]) + "% while the boat router is fine",
            "The problem is past the boat router, on the internet link or the modem. The traceroute in the report shows where replies stop.",
            "Check the boat's internet link and modem. If it continues, ask the internet provider.",
        ))
    if ping["avg_ms"] is not None and ping["avg_ms"] > INTERNET_RTT_LIMIT:
        findings.append(finding(
            "warning",
            "Slow round trips to " + host + ": " + str(ping["avg_ms"]) + " ms",
            "Round trips this slow make VNC feel laggy.",
            "Check the internet link for heavy use, such as video or updates running at the same time.",
        ))
    if data["dns_ms"] is not None and data["dns_ms"] > DNS_LIMIT:
        findings.append(finding(
            "warning",
            "Slow name lookup for " + host + ": " + str(data["dns_ms"]) + " ms",
            "Slow DNS makes every new connection wait before it starts.",
            "Check the DNS servers in the report. Try a different DNS server.",
        ))
    return findings


def resource_findings(res):
    findings = []
    findings += cpu_findings(res)
    findings += memory_findings(res["memory"])
    findings += limit_findings(res)
    findings += heat_and_clock_findings(res)
    findings += disk_findings(res["disk_root_percent"])
    findings += power_mode_findings(res["jetson_power_mode"])
    return findings


def top_text(res):
    names = [proc["name"] + " " + str(proc["cpu_percent"]) + "%" for proc in res["top_processes"][:3]]
    return ", ".join(names) or "none listed"


def cpu_findings(res):
    findings = []
    busy = res["cpu_busy_percent"]
    cpus = res["cpus"]
    load = res["load_1_5_15"][0]
    if busy is not None and busy >= CPU_BUSY_LIMIT:
        findings.append(finding(
            "warning",
            "CPU is busy: " + str(busy) + "%",
            "The processor is almost fully used, so VNC and other tasks slow down. Top processes: " + top_text(res) + ".",
            "Stop or limit the process that uses the most CPU, or run the check again when the machine is quiet.",
        ))
    if cpus and load / cpus > LOAD_PER_CPU_LIMIT:
        findings.append(finding(
            "warning",
            "High load: " + str(load) + " on " + str(cpus) + " CPUs",
            "More work is queued than the CPUs can run at once.",
            "Check the top processes in the report.",
        ))
    return findings


def memory_findings(mem):
    findings = []
    total = mem["total_mb"]
    available = mem["available_mb"]
    if total and available is not None and 100 * available / total < MEM_FREE_LIMIT:
        findings.append(finding(
            "warning",
            "Low memory: " + str(available) + " MB free of " + str(total) + " MB",
            "Builds and VNC can fail or slow down when memory runs out.",
            "Close unused programs. If this keeps happening, add memory.",
        ))
    swap_total = mem["swap_total_mb"]
    if swap_total and 100 * mem["swap_used_mb"] / swap_total > SWAP_USED_LIMIT:
        findings.append(finding(
            "warning",
            "Swap is heavily used: " + str(mem["swap_used_mb"]) + " MB",
            "Swapping to disk makes everything slow.",
            "Close unused programs, or add memory.",
        ))
    return findings


def limit_findings(res):
    findings = []
    cgroup = res["cgroup"]
    cpus = res["cpus"]
    quota = cgroup["cpu_quota_cores"]
    if quota is not None and cpus and quota < cpus:
        findings.append(finding(
            "warning",
            "CPU is capped at " + str(quota) + " cores for this process group",
            "The machine has " + str(cpus) + " CPUs, but the group this check ran in is limited. Services in the same group get the same cap.",
            "Look for a CPUQuota setting in the systemd service, and raise or remove it.",
        ))
    limit = cgroup["memory_limit_mb"]
    total = res["memory"]["total_mb"]
    if limit is not None and total and limit < total:
        findings.append(finding(
            "warning",
            "Memory is capped at " + str(limit) + " MB for this process group",
            "Only " + str(limit) + " MB of the " + str(total) + " MB is usable in this group.",
            "Look for a MemoryMax setting in the systemd service, and raise or remove it.",
        ))
    return findings


def heat_and_clock_findings(res):
    findings = []
    temp = res["thermal_max_c"]
    clock = res["cpu_clock"]
    busy = res["cpu_busy_percent"]
    if temp is not None and temp >= HOT_C:
        findings.append(finding(
            "warning",
            "Hot: " + str(temp) + " C",
            "The chip slows itself down when it gets this hot.",
            "Check airflow, the fan, and the heatsink.",
        ))
    if clock["current_mhz"] and clock["max_mhz"] and busy is not None and busy >= CLOCK_BUSY_PERCENT:
        if clock["current_mhz"] < CLOCK_LOW_RATIO * clock["max_mhz"]:
            findings.append(finding(
                "warning",
                "CPU clock is low: " + str(clock["current_mhz"]) + " of " + str(clock["max_mhz"]) + " MHz while busy",
                "The chip is running well below its top speed. Power limits or heat are the usual causes.",
                "Check the Jetson power mode and the temperature in the report.",
            ))
    return findings


def disk_findings(percent):
    if percent is not None and percent >= DISK_LIMIT:
        return [finding(
            "warning",
            "Root disk is " + str(percent) + "% full",
            "A nearly full disk makes logs, builds, and uploads fail.",
            "Remove old files or add storage.",
        )]
    return []


def power_mode_findings(mode):
    if mode and "MAXN" not in mode:
        return [finding(
            "info",
            "Jetson power mode is " + mode,
            "Low-power modes limit CPU and GPU clocks.",
            "Set a higher power mode with nvpmodel if the devkit must run at full speed.",
        )]
    return []


def lossy_hosts(facts):
    return [host for host, data in facts.get("path", {}).items() if is_lossy(data["ping"])]


def is_lossy(ping):
    return "error" in ping or ping["loss_percent"] >= LOSS_LIMIT


def device_findings(lan):
    """Problems with the device scan itself. The devices it finds are listed in the report."""
    out = []
    for net in lan.get("networks", []):
        if net["nmap"] == "absent":
            out.append(finding(
                "warning",
                "The device scan could not run on " + net["interface"] + ": nmap is not installed",
                "Only devices the devkit has talked to recently are listed for " + net["network"] + ". Other devices on that network are not found.",
                "Install nmap with: sudo apt install nmap. Then run the check again.",
            ))
        elif net["nmap"] == "error":
            out.append(finding(
                "warning",
                "The device scan failed on " + net["interface"],
                net["error"],
                "Run the check again. If it repeats, include the report when you ask for help.",
            ))
    return out


def same_mac_findings(lan):
    """One device that answers on two networks joins them, so traffic can pass between them."""
    where = {}
    for net in lan.get("networks", []):
        for device in net["devices"]:
            if device["mac"]:
                where.setdefault(device["mac"], set()).add(net["interface"])
    out = []
    for mac, interfaces in sorted(where.items()):
        if len(interfaces) > 1:
            out.append(finding(
                "warning",
                "One device (MAC " + mac + ") answers on two networks",
                "It answers on " + ", ".join(sorted(interfaces)) + ". That joins the networks through it.",
                "Check whether one router is connected to both networks. If that is not intended, unplug the extra link.",
            ))
    return out


ARP_PER_SECOND_LIMIT = 5.0


def capture_findings(captures):
    """Problems seen in the packet captures. A capture that could not run is reported as info."""
    out = []
    for cap in captures:
        if cap.get("error"):
            out.append(finding(
                "info",
                "The packet capture did not run on " + cap["interface"],
                cap["error"],
                "Install tcpdump (sudo apt install tcpdump), then run --deep again.",
            ))
            continue
        if cap["arp_requests"] / float(cap["seconds"]) > ARP_PER_SECOND_LIMIT:
            out.append(finding(
                "warning",
                "Many ARP requests on " + cap["interface"] + ": " + str(cap["arp_requests"]) + " in " + str(cap["seconds"]) + " seconds",
                "Devices keep asking who has each address. This usually means a loop, a duplicate address, or a device that cannot find its gateway.",
                "Check the device table for duplicate addresses, and look for a loop between the two networks.",
            ))
    return out
