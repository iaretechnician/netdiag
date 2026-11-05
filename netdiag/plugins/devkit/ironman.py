"""--ironman: the Ironman web portal's link to the devkit. Base module for every devkit."""
from netdiag.plugin import Module
from netdiag.plugins.devkit.api import find_key, get_json, listening, port_lines
from netdiag.rules import finding

POSEIDON_PORTS = (5058, 5059)  # hardcoded in the app manager (Ironman brief)
LABELS = {"5058": "Poseidon REST", "5059": "Poseidon WebSocket"}


def collect(ctx):
    network, error = get_json(5058, "/network/status")
    return {
        "listening": {str(port): listening(ctx["local"]["ports"], port) for port in POSEIDON_PORTS},
        "network": network,
        "network_error": error,
    }


def rules(facts):
    data = facts["modules"]["ironman"]
    out = []
    for port, up in data["listening"].items():
        if not up:
            out.append(finding(
                "critical", "Nothing is listening on port " + port + " (Poseidon app manager)",
                "The Ironman web portal needs this port to manage apps, WiFi, updates and logs.",
                "Start the Poseidon app manager on the devkit, then run the check again."))
    if data["network_error"]:
        out.append(finding(
            "warning", "Could not read the network status from Poseidon", data["network_error"],
            "Check that the Poseidon app manager answers on port 5058."))
        return out
    net = data["network"]
    if find_key(net, "wifi_internet") is False and find_key(net, "lte_internet") is False:
        out.append(finding(
            "critical", "Neither WiFi nor LTE has internet",
            "The devkit cannot reach our servers, so uploads and remote support will fail.",
            "Check the WiFi network, or the LTE antenna and SIM, and the router's internet link."))
    if find_key(net, "wifi_primary") and find_key(net, "lte_primary"):
        out.append(finding(
            "warning", "WiFi and LTE both hold the default route",
            "Traffic can split between the two links, and VNC may stall when the route moves.",
            "Give one link a higher metric so only one holds the default route."))
    return out


def section(facts):
    data = facts["modules"]["ironman"]
    lines = port_lines(data["listening"], LABELS)
    if data["network_error"]:
        lines.append("- Network status: could not read (" + data["network_error"] + ")")
        return lines
    net = data["network"]
    lines.append("- WiFi internet: {}, LTE internet: {}".format(
        find_key(net, "wifi_internet"), find_key(net, "lte_internet")))
    lines.append("- Default route: WiFi {}, LTE {}".format(
        find_key(net, "wifi_primary"), find_key(net, "lte_primary")))
    return lines


MODULE = Module(
    name="ironman", flag="--ironman",
    summary="Ironman web portal link: Poseidon ports and network status",
    collect=collect, rules=rules, section=section,
)
