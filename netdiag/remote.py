"""The PC you are logged in from. Ping it. If it does not answer, say so; a client test app can cover that later."""
import os
import re
import subprocess

from netdiag.rules import finding
from netdiag.stages import ping_facts


def parse_who(text):
    """The remote address in brackets at the end of `who -m` output, or None for a local login."""
    found = re.search(r"\(([^)]+)\)\s*$", (text or "").strip())
    if not found or found.group(1).startswith(":"):
        return None
    return found.group(1)


def address_from_who():
    """Fallback for when sudo drops the SSH variables: `who -m` still shows the login's address."""
    try:
        result = subprocess.run(["who", "-m"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_who(result.stdout)


def client_address():
    """The IP of the SSH client. None when not logged in over SSH."""
    value = os.environ.get("SSH_CLIENT") or os.environ.get("SSH_CONNECTION")
    if value:
        return value.split()[0]
    return address_from_who()


def no_replies(ping):
    return "error" in ping or ping.get("loss_percent", 100.0) >= 100.0


def remote_facts():
    address = client_address()
    return {"address": address, "ping": ping_facts(address) if address else None}


def remote_findings(remote):
    if not remote["address"] or not no_replies(remote["ping"]):
        return []
    return [finding(
        "info", "Your PC ({}) does not answer ping".format(remote["address"]),
        "Windows firewalls block ping by default, so latency to this PC cannot be measured this way. "
        "A client test app, as a separate plugin, can measure it end to end.",
        "Allow ping (ICMP echo) on the PC, or install the client test app when it is available.")]


def section_lines(remote):
    if not remote["address"]:
        return ["No SSH session found, so there is no PC to test. Run the check over SSH from your PC."]
    ping = remote["ping"] or {}
    if no_replies(ping):
        return ["Address: {}. No replies to ping.".format(remote["address"])]
    return ["Address: {}. Ping loss {}%, average {} ms.".format(
        remote["address"], ping.get("loss_percent"), ping.get("avg_ms"))]
