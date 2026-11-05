"""Read the devkit's own services over HTTP, and pick values out of their JSON."""
import json
import urllib.request

TIMEOUT_SECONDS = 3
HOST = "127.0.0.1"  # the check runs on the devkit, so its services answer locally


def get_json(port, path):
    """Return (data, error). A failure comes back as text, never as an exception."""
    url = "http://{}:{}{}".format(HOST, port, path)
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as reply:
            return json.loads(reply.read().decode() or "null"), None
    except Exception as error:  # any failure becomes a finding
        return None, str(error)


def listening(ports, port, proto="tcp"):
    """True when the port check found this port open."""
    return any(item["port"] == port and item["proto"] == proto for item in ports.get("list", []))


def find_key(data, key):
    """Find a key anywhere in nested JSON, so a check still works if the layout moves."""
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for value in data.values():
            found = find_key(value, key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = find_key(value, key)
            if found is not None:
                return found
    return None


def dotted(data, path):
    """Read a dotted path such as camera.address. Returns None if any part is missing."""
    for part in path.split("."):
        if not isinstance(data, dict) or part not in data:
            return None
        data = data[part]
    return data


def port_lines(listening_map, labels):
    """Report lines for a map of port number (as text) to listening state."""
    lines = []
    for port, up in listening_map.items():
        label = labels.get(port, "service")
        lines.append("- Port {} ({}): {}".format(port, label, "listening" if up else "not listening"))
    return lines
