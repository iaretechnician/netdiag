"""Write results.json and report.md, and print the short terminal summary.

Both outputs put the problems last, so the most serious issues are the final lines a reader sees.
"""
import datetime
import json

from netdiag import pressure, remote, rules


def write_results(folder, facts, findings):
    saved = {"facts": facts, "findings": findings}
    (folder / "results.json").write_text(json.dumps(saved, indent=2))
    (folder / "report.md").write_text(render(facts, findings))


def stamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def count_line(findings):
    counts = {"critical": 0, "warning": 0, "info": 0}
    for item in findings:
        counts[item["severity"]] += 1
    return "{} critical, {} warning, {} info".format(counts["critical"], counts["warning"], counts["info"])


def render(facts, findings):
    lines = ["# Network diagnostic report", "", "Run: " + stamp(), "", "Result: " + count_line(findings), ""]
    lines += machine_section(facts)
    lines += network_section(facts)
    lines += remote_section(facts)
    lines += devices_section(facts["lan"])
    if "capture" in facts:
        lines += capture_section(facts["capture"])
    lines += ports_section(facts["local"])
    lines += firewall_section(facts["local"])
    lines += internet_section(facts)
    lines += resources_section(facts["resources"])
    lines += pressure_section(facts)
    lines += traceroute_section(facts)
    lines += module_sections(facts)
    lines += not_run_section(facts)
    lines += problems_section(findings)
    return "\n".join(lines) + "\n"


def machine_section(facts):
    system = facts["system"]
    return [
        "## Machine", "",
        "- OS: " + (system["os"] or "unknown"),
        "- Jetson release: " + (system["jetson_release"] or "not a Jetson"),
        "- Kernel: " + str(system["kernel"]),
        "- CPUs: " + str(facts["resources"]["cpus"]),
        "",
    ]


def network_section(facts):
    system = facts["system"]
    local = facts["local"]
    lines = ["## Network", ""]
    for iface in system["interfaces"].get("list", []):
        if iface["state"] == "UP":
            addresses = ", ".join(a["ip"] + "/" + str(a["prefix"]) for a in iface["addresses"]) or "no IPv4 address"
            lines.append("- {}: {}, MTU {}".format(iface["name"], addresses, iface["mtu"]))
    routes = local["default_routes"]
    if isinstance(routes, dict):
        lines.append("- Default route: could not read (" + routes["error"] + ")")
    elif routes:
        lines.append("- Default route: " + ", ".join(
            str(route["gateway"]) + " via " + str(route["interface"]) for route in routes))
    else:
        lines.append("- Default route: none")
    lines.append("- DNS servers: " + (", ".join(local["dns_servers"]) or "none set"))
    lines.append("")
    return lines


def devices_section(lan):
    lines = ["## Devices on each network", ""]
    networks = lan.get("networks", [])
    if not networks:
        return lines + ["No network port with an IPv4 address was found.", ""]
    for net in networks:
        lines += ["### " + net["interface"] + " (" + net["network"] + ")", ""]
        if net["nmap"] == "absent":
            lines += ["The full scan did not run, because nmap is not installed. Only devices the devkit has talked to recently are listed.", ""]
        elif net["nmap"] == "error":
            lines += ["The scan failed: " + net["error"], ""]
        if not net["devices"]:
            lines += ["No devices found.", ""]
            continue
        lines += ["Found " + str(len(net["devices"])) + " device(s).", "",
                  "| IP | MAC | Vendor | Seen by | Neighbour state |", "|---|---|---|---|---|"]
        for device in net["devices"]:
            lines.append("| {} | {} | {} | {} | {} |".format(
                device["ip"], device["mac"] or "unknown", device["vendor"] or "unknown",
                ", ".join(device["seen"]), device["state"] or "-"))
        lines.append("")
    return lines


def ports_section(local):
    """Two lists: OPEN for ports the boat network can reach, CLOSED for ports the firewall blocks."""
    reachable, blocked = split_ports(local)
    local_only = [item for item in local["ports"].get("list", []) if not item["exposed"]]
    lines = ["## Ports", "", "### OPEN: reachable from the boat network", ""]
    lines += port_bullets(reachable) or ["- none"]
    lines += ["", "### CLOSED: blocked by the firewall", ""]
    if local["firewall"]["default_incoming"] == "unknown":
        lines.append("- unknown: the firewall rules could not be read")
    else:
        lines += port_bullets(blocked) or ["- none"]
    lines += ["", "Listening only on this machine: " + str(len(local_only)), ""]
    return lines


def split_ports(local):
    """Exposed ports, split into reachable and blocked by the firewall."""
    firewall = local["firewall"]
    reachable, blocked = [], []
    for item in local["ports"].get("list", []):
        if not item["exposed"]:
            continue
        if firewall["default_incoming"] == "deny" and not rules.is_allowed(item, firewall["allowed_ports"]):
            blocked.append(item)
        else:
            reachable.append(item)
    return reachable, blocked


def port_bullets(items):
    return ["- {} {} ({})".format(port, proto, process) for port, proto, process in unique_ports(items, with_proto=True)]


def unique_ports(items, with_proto=False):
    """One line per port and process. ss lists IPv4 and IPv6 separately, so the same port can appear twice."""
    seen = []
    for item in items:
        key = (item["port"], item["proto"], item["process"] or "unknown")
        if key not in seen:
            seen.append(key)
    if with_proto:
        return seen
    return [(port, process) for port, _proto, process in seen]


def firewall_section(local):
    firewall = local["firewall"]
    allowed = firewall["allowed_ports"]
    allowed_text = ", ".join(
        str(rule["port"]) + "/" + (rule["proto"] or "any") for rule in allowed
    ) or "none found"
    lines = [
        "## Firewall",
        "",
        "Default for incoming traffic: " + firewall["default_incoming"],
        "",
        "Ports the firewall allows: " + allowed_text,
        "",
    ]
    if firewall["errors"]:
        lines += ["Could not read: " + "; ".join(
            name + " (" + text + ")" for name, text in firewall["errors"].items()), ""]
    return lines


def internet_section(facts):
    lines = ["## Internet path", ""]
    if "path" not in facts:
        return lines + ["Skipped in a quick run.", ""]
    lines += ["| Target | Loss | Average | Name lookup |", "|---|---|---|---|"]
    for host, data in facts["path"].items():
        ping = data["ping"]
        if "error" in ping:
            loss, avg = "no replies", "-"
        else:
            loss = str(ping["loss_percent"]) + "%"
            avg = str(ping["avg_ms"]) + " ms" if ping["avg_ms"] is not None else "-"
        lookup = str(data["dns_ms"]) + " ms" if data["dns_ms"] is not None else "failed"
        lines.append("| {} | {} | {} | {} |".format(host, loss, avg, lookup))
    lines.append("")
    return lines


def resources_section(res):
    mem = res["memory"]
    cg = res["cgroup"]
    caps = []
    if cg["cpu_quota_cores"] is not None:
        caps.append("CPU cap " + str(cg["cpu_quota_cores"]) + " cores")
    if cg["memory_limit_mb"] is not None:
        caps.append("memory cap " + str(cg["memory_limit_mb"]) + " MB")
    lines = [
        "## Resources",
        "",
        "Caps below apply to the group this check ran in (" + (cg["path"] or "/") + "). A service may have its own caps.",
        "",
        "| Item | Value |",
        "|---|---|",
        "| CPUs | " + str(res["cpus"]) + " |",
        "| CPU busy (1 second sample) | " + str(res["cpu_busy_percent"]) + "% |",
        "| Load 1/5/15 min | " + " / ".join(str(value) for value in res["load_1_5_15"]) + " |",
        "| Memory | " + str(mem["available_mb"]) + " MB free of " + str(mem["total_mb"]) + " MB |",
        "| Swap used | " + str(mem["swap_used_mb"]) + " of " + str(mem["swap_total_mb"]) + " MB |",
        "| Root disk | " + str(res["disk_root_percent"]) + "% used |",
        "| CPU clock | " + clock_text(res["cpu_clock"]) + " |",
        "| Hottest sensor | " + value_or_na(res["thermal_max_c"], " C") + " |",
        "| Jetson power mode | " + value_or_na(res["jetson_power_mode"], "") + " |",
        "| Caps in this group | " + (", ".join(caps) or "none") + " |",
        "",
        "Top processes by CPU:",
        "",
    ]
    for proc in res["top_processes"]:
        lines.append("- " + proc["name"] + ": " + str(proc["cpu_percent"]) + "% CPU, " + str(proc["mem_percent"]) + "% memory")
    lines.append("")
    return lines


def value_or_na(value, unit):
    """Show a measured value, or 'not available' when this machine has no such sensor."""
    if value is None:
        return "not available"
    return str(value) + unit


def clock_text(clock):
    if clock["current_mhz"] is None:
        return "not available"
    return str(clock["current_mhz"]) + " of " + str(clock["max_mhz"]) + " MHz (" + str(clock["governor"]) + ")"


def traceroute_section(facts):
    traces = facts.get("follow_up", {}).get("traceroute", {})
    if not traces:
        return []
    lines = ["## Follow-up: traceroute", ""]
    for host, text in traces.items():
        lines += ["Traceroute to " + host + ":", "", "```", text.strip(), "```", ""]
    return lines


def problems_section(findings):
    lines = ["## Problems, most serious first", ""]
    if not findings:
        return lines + ["No problems found in this run.", ""]
    for number, item in enumerate(findings, start=1):
        lines += [
            "### {}. {}: {}".format(number, item["severity"].upper(), item["title"]),
            "",
            "Why: " + item["detail"],
            "",
            "Fix: " + item["next_step"],
            "",
        ]
    return lines


def terminal_text(facts, findings, folder):
    """The short summary printed to the terminal. Problems come last."""
    system = facts["system"]
    lines = [
        "NETDIAG  " + stamp() + "  " + (system["os"] or "Linux"),
        "Result: " + count_line(findings),
        "Full report: " + str(folder / "report.md"),
        "",
        "NETWORK",
    ]
    lines += ["  " + text for text in network_summary(facts)]
    lines += ["", "PORTS"]
    lines += ["  " + text for text in ports_summary(facts["local"])]
    lines += ["", "INTERNET"]
    lines += ["  " + text for text in internet_summary(facts)]
    lines += ["", "RESOURCES"]
    lines += ["  " + text for text in resources_summary(facts["resources"])]
    lines += remote_terminal_lines(facts)
    lines += pressure_terminal_lines(facts)
    lines += checks_summary_lines(facts)
    lines += ["", "PROBLEMS, most serious first"]
    lines += problem_lines(findings)
    return "\n".join(lines)


def network_summary(facts):
    lines = []
    for iface in facts["system"]["interfaces"].get("list", []):
        if iface["state"] == "UP":
            addresses = ", ".join(a["ip"] + "/" + str(a["prefix"]) for a in iface["addresses"]) or "no IPv4 address"
            lines.append("{}: {}, MTU {}".format(iface["name"], addresses, iface["mtu"]))
    lan = facts["lan"]
    lines.append("Gateway: " + str(lan.get("gateway") or "none")
                 + "   DNS: " + (", ".join(facts["local"]["dns_servers"]) or "none"))
    for net in lan.get("networks", []):
        lines.append("Devices on " + net["interface"] + " (" + net["network"] + "): " + str(len(net["devices"])))
    return lines


def ports_summary(local):
    """Terminal lines: OPEN and CLOSED, one port per line."""
    reachable, blocked = split_ports(local)
    lines = ["OPEN (reachable from the boat network)"]
    lines += ["  {:<6} {}".format(port, process) for port, process in unique_ports(reachable)] or ["  none"]
    lines.append("CLOSED (blocked by the firewall)")
    if local["firewall"]["default_incoming"] == "unknown":
        lines.append("  unknown, the firewall rules could not be read")
    else:
        lines += ["  {:<6} {}".format(port, process) for port, process in unique_ports(blocked)] or ["  none"]
    return lines


def port_names(items):
    return list(dict.fromkeys("{} {}".format(item["port"], item["process"] or "?") for item in items))


def internet_summary(facts):
    if "path" not in facts:
        return ["Skipped in a quick run"]
    lines = []
    for host, data in facts["path"].items():
        ping = data["ping"]
        if "error" in ping:
            lines.append(host + ": no replies")
        else:
            avg = str(ping["avg_ms"]) + " ms" if ping["avg_ms"] is not None else "-"
            lines.append("{}: {}% loss, {} average".format(host, ping["loss_percent"], avg))
    return lines


def resources_summary(res):
    mem = res["memory"]
    cpu = str(res["cpu_busy_percent"]) + "% busy" if res["cpu_busy_percent"] is not None else "busy unknown"
    memory = str(mem["available_mb"]) + " of " + str(mem["total_mb"]) + " MB free" if mem["total_mb"] else "unknown"
    return [
        "CPU: " + cpu + ", load " + " / ".join(str(value) for value in res["load_1_5_15"]),
        "Memory: " + memory + ", swap used " + str(mem["swap_used_mb"]) + " MB",
        "Disk: root " + str(res["disk_root_percent"]) + "% used",
    ]


def problem_lines(findings):
    if not findings:
        return ["  None found."]
    lines = []
    for number, item in enumerate(findings, start=1):
        lines += [
            "  {}. {}  {}".format(number, item["severity"].upper(), item["title"]),
            "     Why: " + item["detail"],
            "     Fix: " + item["next_step"],
        ]
    return lines


def module_sections(facts):
    """One report section per devkit module that ran."""
    from netdiag.plugin import load_modules
    modules = load_modules()
    lines = []
    for name in facts.get("selected_modules", []):
        module = modules[name]
        lines += ["## Check: " + name + " (" + module.flag + ")", ""]
        try:
            lines += module.section(facts)
        except Exception as error:
            lines.append("This section could not be shown: " + str(error))
        lines.append("")
    return lines


def not_run_section(facts):
    """Modules that were not selected, with the flag that adds them."""
    selected = facts.get("selected_modules", [])
    waiting = [m for m in facts.get("available_modules", []) if m["name"] not in selected]
    if not waiting:
        return []
    lines = ["## Checks not run", "", "Add these flags to include them:", ""]
    for module in waiting:
        lines.append("- {} : {}".format(module["flag"], module["summary"]))
    return lines + [""]


def checks_summary_lines(facts):
    """Terminal lines saying which checks ran and which flags add the rest."""
    selected = facts.get("selected_modules", [])
    waiting = [m["flag"] for m in facts.get("available_modules", []) if m["name"] not in selected]
    lines = ["", "CHECKS", "  Run: " + ", ".join(["network"] + selected)]
    if waiting:
        lines.append("  Not run, add the flag to include: " + " ".join(waiting))
    return lines


def pressure_section(facts):
    if "pressure" not in facts:
        return ["## Pressure", "", "Not collected.", ""]
    return ["## Pressure", ""] + pressure.section_lines(facts["pressure"]) + [""]


def remote_section(facts):
    if "remote" not in facts:
        return []
    return ["## Remote PC", ""] + remote.section_lines(facts["remote"]) + [""]


def remote_terminal_lines(facts):
    if "remote" not in facts:
        return []
    return ["", "REMOTE PC"] + ["  " + text for text in remote.section_lines(facts["remote"])]


def pressure_terminal_lines(facts):
    if "pressure" not in facts:
        return []
    return ["", "PRESSURE"] + ["  " + text for text in pressure.terminal_lines(facts["pressure"])]


def capture_section(captures):
    lines = ["## Packet capture", ""]
    for cap in captures:
        if cap.get("error"):
            lines += ["### " + cap["interface"], "", "Not captured: " + cap["error"], ""]
            continue
        sources = ", ".join(ip + " (" + str(count) + ")" for ip, count in cap["top_sources"]) or "none"
        ports = ", ".join(str(port) + " (" + str(count) + ")" for port, count in cap["top_ports"]) or "none"
        lines += [
            "### " + cap["interface"] + " (" + str(cap["seconds"]) + " seconds)", "",
            "- Packets: " + str(cap["packets"]),
            "- ARP requests: " + str(cap["arp_requests"]),
            "- Multicast packets: " + str(cap["multicast_packets"]),
            "- DNS queries: " + str(cap["dns_queries"]),
            "- Busiest sources: " + sources,
            "- Busiest destination ports: " + ports,
            "",
        ]
    return lines
