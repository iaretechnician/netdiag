"""Command line for netdiag: run the checks, record a pressure log, or rebuild a report from saved results."""
import argparse
import datetime
import json
from pathlib import Path

from netdiag import pressure, remote, report, rules, runner
from netdiag.plugin import load_modules, resolve


def build_parser(modules):
    parser = argparse.ArgumentParser(
        prog="netdiag",
        description="Check this machine's network and say what is wrong.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="run the checks and write a report")
    run_parser.add_argument("--network", action="store_true", help="base network checks (always run)")
    run_parser.add_argument("--quick", action="store_true", help="skip the internet path checks")
    run_parser.add_argument("--all", action="store_true", help="run every check module")
    run_parser.add_argument("--deep", action="store_true", help="more detail: a 30-second packet capture on each network")
    run_parser.add_argument("--ai", action="store_true", help="ask an AI model to review the results and choose follow-up checks (uses API credit)")
    run_parser.add_argument("--ai-key-file", type=Path, help="file holding the AI API key (default: ~/.config/netdiag/ai-key)")
    run_parser.add_argument("--ai-model", default="claude-haiku-5-5", help="AI model used with --ai")
    run_parser.add_argument("--out", type=Path, help="folder for results (default: ./netdiag-results/<time>)")
    # Modules in one group, such as proteus and apollo, cannot be picked together.
    groups = {}
    for module in modules.values():
        target = run_parser
        if module.group:
            if module.group not in groups:
                groups[module.group] = run_parser.add_mutually_exclusive_group()
            target = groups[module.group]
        target.add_argument(module.flag, action="store_true", help=module.summary)
    log_parser = commands.add_parser("log", help="record CPU, memory, disk-stall and GPU use over time")
    log_parser.add_argument("--minutes", type=int, default=10,
                            help="how long to record, 1 to {} (default 10)".format(pressure.MAX_MINUTES))
    pressure_parser = commands.add_parser("pressure", help="report the Pressure section from a saved log")
    pressure_parser.add_argument("path", type=Path, nargs="?",
                                 help="a pressure.csv file or its folder (default: the latest log)")
    report_parser = commands.add_parser("report", help="rebuild a report from saved results")
    report_parser.add_argument("folder", type=Path, help="a folder made by netdiag run")
    return parser


def chosen_modules(args, modules):
    """The flags picked, plus anything they need. Nothing is picked on a bare run."""
    if args.all:
        names = list(modules)
    else:
        names = [name for name in modules if getattr(args, name)]
    return resolve(names, modules)


def run(args, modules):
    selected = chosen_modules(args, modules)
    folder = args.out or default_folder()
    folder.mkdir(parents=True, exist_ok=True)
    facts = runner.collect(quick=args.quick, selected=selected, deep=args.deep)
    findings = rules.analyse(facts)
    if args.ai:
        from netdiag import ai_review
        facts["ai"] = ai_review.review(facts, findings, key_file=args.ai_key_file, model=args.ai_model)
    report.write_results(folder, facts, findings)
    print(report.terminal_text(facts, findings, folder))
    return 0


def record(args):
    if not 1 <= args.minutes <= pressure.MAX_MINUTES:
        print("--minutes must be between 1 and {}".format(pressure.MAX_MINUTES))
        return 2
    path = pressure.run_log(args.minutes, client=remote.client_address())
    print("Recorded to " + str(path))
    print("\n".join(pressure.report_for_log(path)))
    return 0


def pressure_report(path):
    if path is None:
        found = pressure.latest_log()
        if not found:
            print("No pressure log found in " + str(pressure.LOG_ROOT))
            return 1
        path = found[0]
    elif path.is_dir():
        path = path / "pressure.csv"
    print("\n".join(pressure.report_for_log(path)))
    return 0


def rebuild(folder):
    saved = json.loads((folder / "results.json").read_text())
    report.write_results(folder, saved["facts"], saved["findings"])
    print("Report rebuilt at " + str(folder / "report.md"))
    return 0


def default_folder():
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("netdiag-results") / stamp


def main(argv=None):
    modules = load_modules()
    args = build_parser(modules).parse_args(argv)
    if args.command == "run":
        return run(args, modules)
    if args.command == "log":
        return record(args)
    if args.command == "pressure":
        return pressure_report(args.path)
    return rebuild(args.folder)
