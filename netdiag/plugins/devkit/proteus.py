"""--proteus: ProteusCore, the radar software. Includes the Ironman checks."""
import ipaddress
import re

from netdiag.commands import run_command
from netdiag.plugin import Module
from netdiag.plugins.devkit.api import find_key, get_json, listening, port_lines
from netdiag.rules import finding

HTTP_PORT = 8080        # ProteusCore REST, from the install guide
WEBSOCKET_PORT = 5000   # ProteusCore WebSocket, from the install guide
LABELS = {"8080": "ProteusCore REST", "5000": "ProteusCore WebSocket"}
# Radar multicast groups from the Proteus brief, not the install guide. Verify on a devkit.
RADAR_GROUPS = [
    "236.6.7.5", "236.6.7.8", "236.6.7.9", "236.6.7.13", "236.6.7.4",  # Simrad Halo
    "239.238.55.72",                                                  # Simrad navigation
    "239.254.2.2", "239.254.2.11",                                    # Garmin
    "224.18.7.30",                                                    # Raymarine Cyclone
]


def valid_multicast(address):
    try:
        return ipaddress.ip_address(address).is_multicast
    except ValueError:
        return False


def joined_groups(interface):
    """Multicast groups the interface has joined, read with ip maddr."""
    result = run_command(["ip", "maddr", "show", "dev", interface])
    return re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", result["stdout"])


def collect(ctx):
    config, error = get_json(HTTP_PORT, "/api")
    lan_interface = ctx["lan"].get("interface")
    joined = joined_groups(lan_interface) if lan_interface else []
    return {
        "config_error": error,
        "listening": {str(port): listening(ctx["local"]["ports"], port) for port in (HTTP_PORT, WEBSOCKET_PORT)},
        "multicast_enabled": find_key(config, "multicast_enable"),
        "multicast_addr": find_key(config, "multicast_addr"),
        "lan_interface": lan_interface,
        "radar_groups_joined": sorted(set(joined) & set(RADAR_GROUPS)),
    }


def rules(facts):
    data = facts["modules"]["proteus"]
    out = []
    for port in (HTTP_PORT, WEBSOCKET_PORT):
        if not data["listening"][str(port)]:
            out.append(finding(
                "critical", "Nothing is listening on port {} (ProteusCore)".format(port),
                "The radar data and the ProteusCore REST API both need this port.",
                "Start ProteusCore on the devkit, then run the check again."))
    if data["config_error"]:
        out.append(finding(
            "warning", "Could not read the ProteusCore config on port 8080", data["config_error"],
            "Check that the ProteusCore REST API answers on port 8080."))
    address = data["multicast_addr"]
    if address and not valid_multicast(address):
        out.append(finding(
            "warning", "ProteusCore multicast address {} is not valid".format(address),
            "Multicast needs a group address from 224.0.0.0 to 239.255.255.255. The Ironman brief flags 293.255.1.1 as a default found in the code.",
            "Set the multicast address to 239.255.1.1 in the ProteusCore configuration, then restart ProteusCore."))
    if data["multicast_enabled"]:
        out.append(finding(
            "info", "ProteusCore multicast output is on",
            "Every device on the network that joins the group receives the radar stream, which adds traffic.",
            "Turn multicast off in the ProteusCore configuration if nothing on the network needs it."))
    if data["listening"][str(HTTP_PORT)] and data["lan_interface"] and not data["radar_groups_joined"]:
        out.append(finding(
            "info", "No radar multicast group is joined on " + data["lan_interface"],
            "Radar data arrives on these groups. Either no radar is connected, or the router is blocking the traffic.",
            "If a radar is connected, turn off IGMP snooping on the router. Both install guides require this."))
    return out


def section(facts):
    data = facts["modules"]["proteus"]
    lines = port_lines(data["listening"], LABELS)
    if data["config_error"]:
        lines.append("- Config: could not read (" + data["config_error"] + ")")
    lines.append("- Multicast output: {}, address: {}".format(data["multicast_enabled"], data["multicast_addr"]))
    lines.append("- Radar groups joined on {}: {}".format(
        data["lan_interface"], ", ".join(data["radar_groups_joined"]) or "none"))
    return lines


MODULE = Module(
    name="proteus", flag="--proteus",
    summary="ProteusCore radar software: ports, multicast and radar traffic",
    collect=collect, rules=rules, section=section,
    requires=("ironman", "poseidon"), group="devkit-product",
)
