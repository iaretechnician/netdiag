"""--nic, --wifi and --cellular: the network ports of this machine, read from /sys.

Each port's link state comes from its carrier file: 1 means a link, 0 means no link.
The carrier file needs no extra tool. ethtool, iw, and dmesg add detail when they are installed.
"""
import os
import re

from netdiag.commands import error_text, run_command
from netdiag.plugin import Module
from netdiag.rules import finding
from netdiag.stages import find_interface, first_line, read_number, read_text

SYS_NET = "/sys/class/net"
STAT_KEYS = ("rx_packets", "tx_packets", "rx_errors", "tx_errors")
CELLULAR_DRIVERS = ("qmi_wwan", "cdc_mbim", "cdc_ncm")


def list_port_names():
    """Names of hardware network ports. Virtual ports, such as docker bridges, have no device link."""
    names = sorted(os.listdir(SYS_NET))
    return [name for name in names if name != "lo" and os.path.exists(os.path.join(SYS_NET, name, "device"))]


def driver_name(base):
    """The driver's name, such as igb, or None when the port has no driver link."""
    try:
        return os.path.basename(os.readlink(os.path.join(base, "device", "driver")))
    except OSError:
        return None


def kind_of(is_wireless, name, driver):
    """Return wifi, cellular, or wired."""
    if is_wireless:
        return "wifi"
    if name.startswith("wwan") or driver in CELLULAR_DRIVERS:
        return "cellular"
    return "wired"


def has_address(name, system):
    """True when the port has an IPv4 address configured."""
    iface = find_interface(system, name)
    return bool(iface and iface["addresses"])


def port_facts(name, system):
    """Read one port's facts from /sys. No command runs here."""
    base = os.path.join(SYS_NET, name)
    driver = driver_name(base)
    is_wireless = os.path.isdir(os.path.join(base, "wireless")) or os.path.exists(os.path.join(base, "phy80211"))
    return {
        "name": name,
        "driver": driver,
        "kind": kind_of(is_wireless, name, driver),
        "operstate": first_line(read_text(os.path.join(base, "operstate"))),
        "carrier": read_number(os.path.join(base, "carrier")),
        "stats": {key: read_number(os.path.join(base, "statistics", key)) for key in STAT_KEYS},
        "has_ip": has_address(name, system),
    }


def parse_link_detected(text):
    """True or False from the 'Link detected:' line of ethtool output. None when the line is missing."""
    for line in text.splitlines():
        if line.strip().startswith("Link detected:"):
            return line.split(":", 1)[1].strip() == "yes"
    return None


def parse_wifi_link(text):
    """The network name and signal from 'iw dev <name> link'. The name is None when not connected."""
    result = {"ssid": None, "signal": None}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("SSID:"):
            result["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("signal:"):
            result["signal"] = line.split(":", 1)[1].strip()
    return result


def mentions(line, word):
    """True when the word appears in the line as a whole word, so igb does not match bigbang."""
    return re.search(r"\b" + re.escape(word) + r"\b", line) is not None


def driver_log_lines(driver, name, kernel_lines):
    """The last kernel log lines that name this port's driver or this port."""
    if not driver:
        return []
    hits = [line for line in kernel_lines if mentions(line, driver) or mentions(line, name)]
    return hits[-10:]


def read_kernel_log():
    """Kernel log lines. dmesg needs sudo on most systems, so the error text says so when it fails."""
    result = run_command(["dmesg"], privileged=True)
    if not result["available"] or result["returncode"] != 0:
        return {"lines": [], "error": error_text(result)}
    return {"lines": result["stdout"].splitlines(), "error": None}


def add_details(port, kernel_lines):
    """Add the facts that need a command: ethtool link, WiFi link, and driver log lines."""
    name = port["name"]
    port["ethtool_link"] = None
    port["wifi"] = None
    if port["kind"] == "wired":
        result = run_command(["ethtool", name])
        port["ethtool_link"] = parse_link_detected(result["stdout"])
    if port["kind"] == "wifi":
        result = run_command(["iw", "dev", name, "link"])
        if result["available"]:
            port["wifi"] = parse_wifi_link(result["stdout"])
    port["kernel_log"] = driver_log_lines(port["driver"], name, kernel_lines)
    return port


def collect_kind(kind):
    """Build the collect function for one kind of port: wired, wifi, or cellular."""
    def collect(ctx):
        kernel = read_kernel_log()
        ports = []
        for name in list_port_names():
            port = port_facts(name, ctx["system"])
            if port["kind"] == kind:
                ports.append(add_details(port, kernel["lines"]))
        return {"ports": ports, "kernel_error": kernel["error"]}
    return collect


def is_wired_without_link(port):
    """True when a wired port shows no link, by its carrier file or by ethtool."""
    return port["kind"] == "wired" and (port["carrier"] == 0 or port["ethtool_link"] is False)


def port_findings(port):
    """The problems one port shows. A port can show more than one."""
    name = port["name"]
    stats = port["stats"]
    found = []
    if is_wired_without_link(port):
        found.append(finding(
            "critical", "Port " + name + " has no link",
            "No cable is connected, the cable is bad, or the switch port is off. No packets can move on this port.",
            "Check the cable at both ends and the switch port light. Try a cable you know works, then run the check again.",
        ))
    if port["wifi"] is not None and port["wifi"]["ssid"] is None:
        found.append(finding(
            "warning", "WiFi adapter " + name + " is not connected",
            "The adapter is present but has no network, so traffic cannot use it.",
            "Connect the adapter to its WiFi network, then run the check again.",
        ))
    silent = stats["rx_packets"] == 0 and stats["tx_packets"] == 0
    if port["has_ip"] and silent and not is_wired_without_link(port):
        found.append(finding(
            "warning", "Port " + name + " has an address but no packets",
            "The port is set up, but no frame has crossed it since the last boot.",
            "Check the cable and the switch port. If the link is up, read the driver messages in the report.",
        ))
    if (stats["rx_errors"] or 0) + (stats["tx_errors"] or 0) > 0:
        found.append(finding(
            "warning", "Port " + name + " shows errors",
            "Errors often come from a bad cable, a duplex mismatch, or a failing port.",
            "Check the cable and the switch port's speed and duplex settings.",
        ))
    return found


def rules_for(name):
    """The rules function for one module: the findings for each of its ports."""
    def rules(facts):
        findings = []
        for port in facts["modules"][name]["ports"]:
            findings += port_findings(port)
        return findings
    return rules


def shown(value):
    """The value as text, or unknown when the value is missing."""
    return "unknown" if value is None else str(value)


def link_text(port):
    """Plain words for the link state of one port."""
    if port["kind"] == "wired":
        if port["carrier"] == 1 or port["ethtool_link"] is True:
            return "link up"
        if is_wired_without_link(port):
            return "no link (no cable or no signal)"
        return "link state unknown"
    if port["kind"] == "wifi":
        if port["wifi"] is None:
            return "connection unknown (install iw to read it)"
        if port["wifi"]["ssid"] is None:
            return "not connected"
        return "connected to " + port["wifi"]["ssid"]
    return "state " + shown(port["operstate"])


def port_line(port):
    """One line with the link, driver, and packet counts of a port."""
    stats = port["stats"]
    return "- {} ({}, driver {}): {}. Packets in {}, out {}. Errors in {}, out {}.".format(
        port["name"], port["kind"], shown(port["driver"]), link_text(port),
        shown(stats["rx_packets"]), shown(stats["tx_packets"]),
        shown(stats["rx_errors"]), shown(stats["tx_errors"]))


def section_for(name, kind):
    """The report section for one module, with its driver messages under each port."""
    def section(facts):
        data = facts["modules"][name]
        lines = []
        if data["kernel_error"]:
            lines.append("- Kernel log: not read (" + data["kernel_error"] + ")")
        if not data["ports"]:
            lines.append("- No " + kind + " port found on this machine")
        for port in data["ports"]:
            lines.append(port_line(port))
            for entry in port["kernel_log"]:
                lines.append("  - driver message: " + entry)
        return lines
    return section


def make_module(name, flag, summary, kind):
    return Module(
        name=name, flag=flag, summary=summary,
        collect=collect_kind(kind), rules=rules_for(name), section=section_for(name, kind),
    )


MODULES = [
    make_module("nic", "--nic", "wired network ports: link, packets, errors and driver messages", "wired"),
    make_module("wifi", "--wifi", "WiFi adapters: connected network, packets and driver messages", "wifi"),
    make_module("cellular", "--cellular", "cellular modems: interface, state and driver messages", "cellular"),
]
