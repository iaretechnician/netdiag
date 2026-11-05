"""--poseidon: services and log uploads, as the Poseidon app manager reports them."""
from netdiag.plugin import Module
from netdiag.plugins.devkit.api import find_key, get_json
from netdiag.rules import finding


def collect(ctx):
    status, error = get_json(5058, "/status")
    return {
        "error": error,
        "uploading": find_key(status, "uploading"),
        "auto_upload": find_key(status, "auto_upload"),
    }


def rules(facts):
    data = facts["modules"]["poseidon"]
    if data["error"]:
        return [finding(
            "warning", "Could not read service status from Poseidon", data["error"],
            "Check that the Poseidon app manager answers on port 5058.")]
    out = []
    if data["uploading"] is True:
        out.append(finding(
            "warning", "A log upload is running now",
            "Uploads fill the uplink, so VNC and the WebSocket data streams slow down while one runs.",
            "Wait for the upload to finish, or pause uploads in the Log Control panel."))
    if data["auto_upload"] is True:
        out.append(finding(
            "info", "Automatic log upload is on",
            "Uploads start in the background and can begin during a VNC session.",
            "Turn automatic upload off while customers use VNC on a slow link."))
    return out


def section(facts):
    data = facts["modules"]["poseidon"]
    if data["error"]:
        return ["- Service status: could not read (" + data["error"] + ")"]
    return [
        "- Uploading now: " + str(data["uploading"]),
        "- Automatic upload: " + str(data["auto_upload"]),
    ]


MODULE = Module(
    name="poseidon", flag="--poseidon",
    summary="Services and log uploads from the Poseidon app manager",
    collect=collect, rules=rules, section=section,
    requires=("ironman",),
)
