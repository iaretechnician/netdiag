"""Collect facts: the base network checks, the Pressure readings, the remote PC, then each selected module."""
from netdiag import pressure, remote, rules, stages
from netdiag.commands import run_command
from netdiag.plugin import load_modules


def collect(quick, selected, deep=False):
    """Collect all facts. The base network always runs. Modules run only when selected."""
    local = stages.local_facts()
    system = stages.system_facts()
    lan = stages.lan_facts(rules.main_route(local), system)
    facts = {
        "system": system,
        "local": local,
        "lan": lan,
        "resources": stages.resource_facts(),
        "remote": remote.remote_facts(),
        "pressure": pressure.collect_pressure(),
        "selected_modules": selected,
        "modules": {},
    }
    modules = load_modules()
    facts["available_modules"] = [
        {"name": module.name, "flag": module.flag, "summary": module.summary}
        for module in modules.values()
    ]
    if deep:
        facts["capture"] = [stages.capture_network(net) for net in lan.get("networks", [])]
        from netdiag import investigate
        facts["commands"] = investigate.follow_up(facts)
    if not quick:
        facts["path"] = stages.path_facts(stages.DEFAULT_TARGETS)
        facts["follow_up"] = run_follow_ups(facts)
    context = {"system": system, "local": local, "lan": lan}
    for name in selected:
        try:
            facts["modules"][name] = modules[name].collect(context)
        except Exception as error:
            facts["modules"][name] = {"crashed": str(error)}
    return facts


def run_follow_ups(facts):
    """Run a traceroute to the first target that lost packets."""
    hosts = rules.lossy_hosts(facts)
    if not hosts:
        return {}
    host = hosts[0]
    result = run_command(["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", host], timeout=180)
    return {"traceroute": {host: result["stdout"] or result["stderr"]}}
