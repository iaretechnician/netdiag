"""Modules are optional checks. Each product plugin lists its modules; the base tool stays generic."""
import importlib
from pathlib import Path

PLUGIN_DIR = Path(__file__).parent / "plugins"
ENABLED_FILE = PLUGIN_DIR / "enabled.txt"


class Module:
    """One optional check set, selected by its flag, for example --proteus."""

    def __init__(self, name, flag, summary, collect, rules, section, requires=()):
        self.name = name
        self.flag = flag                 # command line flag, for example "--proteus"
        self.summary = summary           # one line shown in the menu
        self.collect = collect           # function(context) -> dict of facts
        self.rules = rules               # function(facts) -> list of findings
        self.section = section           # function(facts) -> list of report lines
        self.requires = tuple(requires)  # other modules that must also run


def enabled_plugin_names():
    """Plugins listed in plugins/enabled.txt. Products choose which plugins ship with them."""
    if not ENABLED_FILE.exists():
        return []
    lines = ENABLED_FILE.read_text().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def load_modules():
    """Every module from every enabled plugin, keyed by name, in plugin order."""
    modules = {}
    for plugin in enabled_plugin_names():
        package = importlib.import_module("netdiag.plugins." + plugin)
        for module in package.MODULES:
            modules[module.name] = module
    return modules


def resolve(selected, modules):
    """Add the modules that the selected ones need. Required modules run first."""
    chosen = []

    def add(name):
        if name in chosen:
            return
        for dependency in modules[name].requires:
            add(dependency)
        chosen.append(name)

    for name in selected:
        add(name)
    return chosen
