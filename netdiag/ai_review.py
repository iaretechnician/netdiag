"""Optional AI review, turned on with --ai.

One review runs after the first pass. A second review runs only if the follow-up commands it asked for
find something new. The model sees a short digest, never the whole output, and it can only ask for the
commands listed in investigate.TEMPLATES. The API key is read at run time and is never printed or saved.
"""
import json
import os
import stat
import urllib.error
import urllib.request

from netdiag import investigate

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-haiku-5-5"
DEFAULT_KEY_FILE = os.path.join(os.path.expanduser("~"), ".config", "netdiag", "ai-key")
DIGEST_LIMIT = 12000       # characters of output sent to the model in one review
OUTPUT_PER_COMMAND = 800   # characters of each command's output sent to the model
MAX_ROUNDS = 2             # a review, then at most one more after its follow-up commands

SYSTEM = ("You review output from a Linux network diagnostic tool for a devkit on a boat network. "
          "Be specific and brief. Reply with JSON only.")

PROMPT = (
    "Below is the output of a network check on a Linux devkit. The devkit is on a boat LAN and a shore Wi-Fi network. "
    "Find what matters most. For each finding, say the likely cause and what to check. "
    "Only ask for follow-up commands that would change the diagnosis. "
    "Use only these command names: NAMES. For a command that needs an interface, put the name from the INTERFACE lines in the interface field. "
    "Reply with JSON only, in this shape: "
    '{"findings": [{"severity": "critical, warning or info", "title": "", "why": "", "next": ""}], '
    '"follow_up": [{"name": "", "interface": "", "reason": ""}]}'
)

NEW_ROUND = (
    "New output from the follow-up commands is below. Update the findings in the same JSON shape. "
    "Do not ask for more commands, so return an empty follow_up list."
)


def read_key(path):
    """Return (key, problem). The key is never printed."""
    if not os.path.exists(path):
        return None, "No API key found. Put the key in " + path + ", or use --ai-key-file."
    problem = None
    if os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        problem = "The key file " + path + " can be read by other users. Run: chmod 600 " + path
    with open(path) as handle:
        key = handle.read().strip()
    if not key:
        return None, "The key file " + path + " is empty."
    return key, problem


def load_key(key_file=None):
    """Find the key: --ai-key-file, then NETDIAG_AI_KEY_FILE, then ANTHROPIC_API_KEY, then the default file."""
    if key_file:
        return read_key(str(key_file))
    if os.environ.get("NETDIAG_AI_KEY_FILE"):
        return read_key(os.environ["NETDIAG_AI_KEY_FILE"])
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return os.environ["ANTHROPIC_API_KEY"].strip(), None
    return read_key(DEFAULT_KEY_FILE)


def port_label(port):
    return "{}/{} {}".format(port["port"], port["proto"], port["process"] or "unknown")


def digest(facts, findings, commands=None):
    """A short plain-text summary of the run for the model. Not the full output."""
    lines = ["OS: " + str(facts["system"].get("os"))]
    for iface in facts["system"]["interfaces"].get("list", []):
        addresses = ", ".join(a["ip"] + "/" + str(a["prefix"]) for a in iface["addresses"]) or "no IPv4"
        lines.append("INTERFACE {} state={} physical={} carrier={} speed_mbps={} addresses={}".format(
            iface["name"], iface["state"], iface.get("physical"), iface.get("carrier"),
            iface.get("speed_mbps"), addresses))
    lines.append("DEFAULT ROUTES: " + str(facts["local"].get("default_routes")))
    lines.append("FIREWALL DEFAULT INCOMING: " + str(facts["local"]["firewall"].get("default_incoming")))
    ports = facts["local"]["ports"].get("list", [])
    lines.append("PORTS EXPOSED: " + ", ".join(port_label(p) for p in ports if p["exposed"]))
    lines.append("PORTS LOCAL ONLY: " + ", ".join(port_label(p) for p in ports if not p["exposed"]))
    for net in facts["lan"].get("networks", []):
        lines.append("NETWORK {} {}: {} devices, nmap={}".format(
            net["interface"], net["network"], len(net["devices"]), net["nmap"]))
    for host, data in facts.get("path", {}).items():
        lines.append("PATH " + host + ": " + str(data.get("ping"))[:200])
    for cap in facts.get("capture", []):
        if cap.get("error"):
            lines.append("CAPTURE " + cap["interface"] + ": " + cap["error"])
        else:
            lines.append("CAPTURE {} {}s: packets={} arp={} multicast={} dns={} top_sources={} top_ports={}".format(
                cap["interface"], cap["seconds"], cap["packets"], cap["arp_requests"], cap["multicast_packets"],
                cap["dns_queries"], cap["top_sources"], cap["top_ports"]))
    for item in findings:
        lines.append("RULE FINDING {}: {}".format(item["severity"], item["title"]))
    for entry in (facts.get("commands", []) if commands is None else commands):
        lines.append("COMMAND $ {} (exit {})".format(entry["command"], entry["returncode"]))
        lines.append(entry["output"].strip()[:OUTPUT_PER_COMMAND])
    return "\n".join(lines)[:DIGEST_LIMIT]


def http_error_text(error):
    try:
        return json.loads(error.read().decode()).get("error", {}).get("message", "")
    except (ValueError, OSError, AttributeError):
        return ""


def call_model(key, model, system, prompt):
    """Send one request. Returns (reply_text, error_text)."""
    body = json.dumps({"model": model, "max_tokens": 1500, "system": system,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    request = urllib.request.Request(API_URL, data=body, headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        return None, "HTTP " + str(error.code) + ": " + http_error_text(error)
    except (urllib.error.URLError, OSError, ValueError) as error:
        return None, "could not reach the AI service: " + str(error)
    return "".join(block.get("text", "") for block in data.get("content", [])), None


def parse_reply(text):
    """Find the JSON object in the reply. Returns a dict, or None."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        reply = json.loads(text[start:end + 1])
    except ValueError:
        return None
    return reply if isinstance(reply, dict) else None


def review(facts, findings, key_file=None, model=DEFAULT_MODEL):
    """Run the AI review. Returns a dict for the report: findings, the follow-ups asked for, and any problem."""
    key, problem = load_key(key_file)
    if key is None:
        return {"skipped": problem}
    result = {"model": model, "rounds": [], "findings": [], "warnings": [problem] if problem else [], "error": None}
    names = ", ".join(sorted(investigate.TEMPLATES))
    prompt = PROMPT.replace("NAMES", names) + "\n\n" + digest(facts, findings)
    for number in range(1, MAX_ROUNDS + 1):
        investigate.say("AI review {}: sending {} characters to {} ...".format(number, len(prompt), model))
        text, error = call_model(key, model, SYSTEM, prompt)
        reply = parse_reply(text) if text is not None else None
        if error or reply is None:
            result["error"] = error or "the reply was not JSON"
            investigate.say("  stopped: " + result["error"])
            break
        result["rounds"].append({"findings": reply.get("findings", []), "follow_up": reply.get("follow_up", [])})
        result["findings"] += reply.get("findings", [])
        steps = investigate.template_steps(reply.get("follow_up", []), facts)
        if not steps or number == MAX_ROUNDS:
            break
        new_entries = investigate.run_steps(steps)
        facts.setdefault("commands", []).extend(new_entries)
        prompt = NEW_ROUND + "\n\n" + digest(facts, findings, commands=new_entries)
    return result
