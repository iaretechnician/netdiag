"""Follow-up checks: after the first pass, run more commands for the areas that need a closer look.

Every command is listed in plan(). Output is kept whole and shown in the report.
Commands run one at a time, and the terminal shows which one is running.
"""
import sys
import time

from netdiag.commands import run_command

TIMEOUT = 120  # seconds for one command


def say(text):
    print(text, file=sys.stderr, flush=True)


def plan(facts):
    """Choose the follow-up commands from what the first pass found. Rules only, no AI."""
    steps = [
        ("ip route get 1.1.1.1", ["ip", "route", "get", "1.1.1.1"], False),
        ("ip rule show", ["ip", "rule", "show"], False),
        ("VNC connections", ["ss", "-tin", "sport", "=", ":5900"], False),
        ("firewall rules (nftables)", ["nft", "list", "ruleset"], True),
        ("kernel warnings this boot", ["journalctl", "-k", "-b", "-p", "warning", "--no-pager", "-n", "200"], True),
    ]
    for iface in facts["system"]["interfaces"].get("list", []):
        name = iface["name"]
        if iface.get("physical"):
            steps += [
                ("ethtool " + name, ["ethtool", name], True),
                ("ethtool -S " + name, ["ethtool", "-S", name], True),
                ("ethtool -i " + name, ["ethtool", "-i", name], True),
                ("ip -s link " + name, ["ip", "-s", "link", "show", name], False),
            ]
        if name.startswith("wl"):
            steps += [
                ("iw dev " + name + " link", ["iw", "dev", name, "link"], False),
                ("iw dev " + name + " station dump", ["iw", "dev", name, "station", "dump"], False),
            ]
        if name.startswith("tailscale"):
            steps += [
                ("tailscale status", ["tailscale", "status"], False),
                ("tailscale netcheck", ["tailscale", "netcheck"], False),
            ]
    return steps


def run_one(number, total, name, args, privileged):
    say("  [{}/{}] {} ...".format(number, total, name))
    started = time.time()
    result = run_command(args, timeout=TIMEOUT, privileged=privileged)
    seconds = round(time.time() - started, 1)
    say("        done in {} s".format(seconds))
    return {
        "name": name,
        "command": " ".join(args),
        "returncode": result["returncode"],
        "seconds": seconds,
        "output": (result["stdout"] or "") + (result["stderr"] or ""),
    }


def follow_up(facts):
    """Run the chosen commands one at a time, showing progress, and keep every output."""
    steps = plan(facts)
    say("Follow-up checks: {} commands".format(len(steps)))
    return [run_one(number, len(steps), name, args, privileged)
            for number, (name, args, privileged) in enumerate(steps, 1)]


MAX_FOLLOW_UP = 6

TEMPLATES = {
    "ethtool": (["ethtool", "{if}"], True, True),
    "ethtool_stats": (["ethtool", "-S", "{if}"], True, True),
    "ethtool_driver": (["ethtool", "-i", "{if}"], True, True),
    "ip_link_stats": (["ip", "-s", "link", "show", "{if}"], False, True),
    "iw_link": (["iw", "dev", "{if}", "link"], False, True),
    "iw_station": (["iw", "dev", "{if}", "station", "dump"], False, True),
    "iw_info": (["iw", "dev", "{if}", "info"], False, True),
    "ip_route_internet": (["ip", "route", "get", "1.1.1.1"], False, False),
    "ip_rules": (["ip", "rule", "show"], False, False),
    "ip_multicast": (["ip", "maddr", "show"], False, False),
    "vnc_connections": (["ss", "-tin", "sport", "=", ":5900"], False, False),
    "firewall_nftables": (["nft", "list", "ruleset"], True, False),
    "firewall_iptables": (["iptables", "-S"], True, False),
    "kernel_warnings": (["journalctl", "-k", "-b", "-p", "warning", "--no-pager", "-n", "200"], True, False),
    "tailscaled_log": (["journalctl", "-u", "tailscaled", "-b", "--no-pager", "-n", "200"], True, False),
    "networkd_log": (["journalctl", "-u", "systemd-networkd", "-b", "--no-pager", "-n", "200"], True, False),
    "networkmanager_log": (["journalctl", "-u", "NetworkManager", "-b", "--no-pager", "-n", "200"], True, False),
    "tailscale_status": (["tailscale", "status"], False, False),
    "tailscale_netcheck": (["tailscale", "netcheck"], False, False),
    "nic_hardware": (["lspci", "-k"], False, False),
}


def template_steps(requests, facts):
    """Turn the requests from the AI into commands. Unknown names and unknown interfaces are dropped."""
    known = [iface["name"] for iface in facts["system"]["interfaces"].get("list", [])]
    steps = []
    for request in requests:
        if not isinstance(request, dict) or request.get("name") not in TEMPLATES:
            continue
        name = request["name"]
        args, privileged, needs_interface = TEMPLATES[name]
        if needs_interface:
            interface = request.get("interface")
            if interface not in known:
                continue
            steps.append((name + " " + interface, [part.replace("{if}", interface) for part in args], privileged))
        else:
            steps.append((name, list(args), privileged))
    return steps[:MAX_FOLLOW_UP]


def run_steps(steps):
    """Run a list of (name, args, privileged) one at a time, with progress, and keep every output."""
    say("Follow-up checks: {} commands".format(len(steps)))
    return [run_one(number, len(steps), name, args, privileged)
            for number, (name, args, privileged) in enumerate(steps, 1)]
