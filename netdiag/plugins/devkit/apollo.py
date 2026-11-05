"""--apollo: ApolloCore (camera and radar), including the ProteusCore checks."""
import ipaddress

from netdiag.plugin import Module
from netdiag.plugins.devkit.api import dotted, find_key, get_json, listening, port_lines
from netdiag.rules import find_interface, finding
from netdiag.stages import ping_facts

REST_PORT = 8180        # ApolloCore REST, from the install guide
WEBSOCKET_PORT = 5101   # ApolloCore WebSocket, from the install guide
VIDEO_PORT = 8889       # WebRTC video signalling for EO and IR, from the install guide
MULTICAST_PORT = 5102   # ApolloCore multicast, from the Ironman brief
ETH_A = "enP4p1s0"      # Ethernet A, from the install guide
ETH_B = "enP7p1s0f0"    # Ethernet B, from the install guide
GIGABIT = 1000
LABELS = {"8180": "ApolloCore REST", "5101": "ApolloCore WebSocket", "8889": "camera video WebRTC"}


def camera_interface(system, address):
    """The Apollo Ethernet port on the camera's subnet, or None."""
    try:
        camera = ipaddress.ip_address(address)
    except (TypeError, ValueError):
        return None
    for name in (ETH_A, ETH_B):
        iface = find_interface(system, name) or {}
        for addr in iface.get("addresses", []):
            network = ipaddress.ip_interface(addr["ip"] + "/" + str(addr["prefix"])).network
            if camera in network:
                return name
    return None


def no_replies(ping):
    return "error" in ping or ping.get("loss_percent", 100.0) >= 100.0


def collect(ctx):
    config, error = get_json(REST_PORT, "/api")
    address = dotted(config, "camera.address") if isinstance(config, dict) else None
    ports = ctx["local"]["ports"]
    iface = camera_interface(ctx["system"], address)
    speed = find_interface(ctx["system"], iface)["speed_mbps"] if iface else None
    return {
        "config_error": error,
        "listening": {str(port): listening(ports, port) for port in (REST_PORT, WEBSOCKET_PORT, VIDEO_PORT)},
        "multicast_enabled": find_key(config, "multicast_enable"),
        "eth_a_present": find_interface(ctx["system"], ETH_A) is not None,
        "camera_address": address,
        "camera_interface": iface,
        "camera_speed": speed,
        "camera_ping": ping_facts(address) if address else None,
    }


def rules(facts):
    data = facts["modules"]["apollo"]
    out = []
    for port, label in ((REST_PORT, "ApolloCore REST"), (WEBSOCKET_PORT, "ApolloCore WebSocket")):
        if not data["listening"][str(port)]:
            out.append(finding(
                "critical", "Nothing is listening on port {} ({})".format(port, label),
                "The Configuration App and the data stream both need this port.",
                "Start the ApolloCore service on the devkit, then run the check again."))
    if not data["listening"][str(VIDEO_PORT)]:
        out.append(finding(
            "warning", "Camera video port {} is not listening".format(VIDEO_PORT),
            "The EO and IR video cannot be viewed in a browser.",
            "Check the ApolloCore video service on the devkit."))
    if data["config_error"]:
        out.append(finding(
            "warning", "Could not read the ApolloCore config on port 8180", data["config_error"],
            "Check that the ApolloCore REST API answers on port 8180."))
    if not data["eth_a_present"]:
        out.append(finding(
            "info", "Ethernet A ({}) was not found".format(ETH_A),
            "The port names in the install guide are for the Apollo hardware. This machine may be different.",
            "Confirm this is an ApolloCore devkit before reading the camera results."))
    if data["camera_address"] is None and not data["config_error"]:
        out.append(finding(
            "warning", "No camera address in the ApolloCore config",
            "ApolloCore cannot find the camera without camera.address.",
            "Set camera.address to the camera's IP address in the ApolloCore config."))
    if data["camera_address"] and data["camera_interface"] is None:
        out.append(finding(
            "critical", "Camera {} is not on the subnet of {} or {}".format(data["camera_address"], ETH_A, ETH_B),
            "The camera and the devkit must share a subnet, or ApolloCore cannot reach the camera.",
            "Give the camera an address on the subnet of {}, or use {} for its subnet.".format(ETH_A, ETH_B)))
    elif data["camera_address"] and no_replies(data["camera_ping"]):
        out.append(finding(
            "critical", "No replies from the camera at " + data["camera_address"],
            "Without the camera, the EO and IR tracking stops.",
            "Check the camera's power, its Ethernet cable and its switch port."))
    elif data["camera_speed"] is not None and data["camera_speed"] < GIGABIT:
        out.append(finding(
            "warning", "Camera link runs at {} Mb/s".format(data["camera_speed"]),
            "The install guide asks for a Gigabit path to the camera, and video stutters below that.",
            "Check the camera cable and switch port for a Gigabit link."))
    if data["multicast_enabled"]:
        out.append(finding(
            "info", "ApolloCore multicast output is on (UDP {})".format(MULTICAST_PORT),
            "Every device on the network that joins the group receives the stream, which adds traffic.",
            "Turn multicast off in the ApolloCore configuration if nothing on the network needs it."))
    return out


def section(facts):
    data = facts["modules"]["apollo"]
    lines = port_lines(data["listening"], LABELS)
    if data["config_error"]:
        lines.append("- Config: could not read (" + data["config_error"] + ")")
    if data["camera_address"]:
        ping = data["camera_ping"] or {}
        reply = "no replies" if no_replies(ping) else "{}% loss, {} ms average".format(
            ping.get("loss_percent"), ping.get("avg_ms"))
        lines.append("- Camera {} on {}: {}".format(
            data["camera_address"], data["camera_interface"] or "no matching Ethernet port", reply))
        if data["camera_speed"] is not None:
            lines.append("- Camera link speed: {} Mb/s".format(data["camera_speed"]))
    else:
        lines.append("- Camera: no address in the config")
    return lines


MODULE = Module(
    name="apollo", flag="--apollo",
    summary="ApolloCore: camera video, camera link, and radar (includes ProteusCore)",
    collect=collect, rules=rules, section=section,
    requires=("ironman", "poseidon", "proteus"), group="devkit-product",
)
