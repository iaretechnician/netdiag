"""Pressure: how long work waited on disk, memory and CPU, plus GPU load and disk space.

The live section reads the kernel's averages, which need no logging. A log written by `netdiag log`
keeps one sample each second, so it can show the worst 10-second stall in the period.
"""
import csv
import datetime
import re
import time
from pathlib import Path

from netdiag.commands import run_command
from netdiag.rules import finding
from netdiag.stages import disk_percent, memory_facts, read_cpu_times, read_number, read_text

LOG_ROOT = Path.home() / "netdiag-logs"
MAX_MINUTES = 1440
WINDOW_SAMPLES = 10  # about 10 seconds at one sample per second
GPU_LOAD_FILES = ("/sys/devices/platform/gpu.0/load", "/sys/devices/gpu.0/load")  # Jetson; verify on a devkit
LOG_FIELDS = ["time", "elapsed_s", "io_total_us", "mem_some_total_us", "mem_full_total_us",
              "cpu_some_total_us", "cpu_busy_percent", "mem_available_mb", "gpu_percent", "remote_ping_ms"]

# key, label, what it means, warning at, critical at (percent)
ROWS = [
    ("io_some", "Disk writes", "Programs that write to disk, including SSH sessions, freeze while a write waits.", 10, 40),
    ("mem_some", "Memory waiting", "Some programs waited for memory to be paged in or out.", 10, None),
    ("mem_full", "Memory full", "Every program waited for memory at once, so nothing could run.", None, 5),
    ("cpu_some", "CPU waiting", "Work waited for a free CPU core.", 50, 80),
    ("swap_percent", "Swap", "Swap is memory moved to disk. Heavy swapping makes every program slow.", 50, 80),
    ("disk_percent", "Root disk space", "How full the root filesystem is. This is space, not speed.", 90, 95),
    ("gpu_percent", "GPU busy", "How busy the GPU is. Shown only where the platform reports it.", 90, None),
]

FIXES = {
    "io_some": "Find the program that writes the most (install iotop and run `sudo iotop -oPa` for a live view). Move its writes off the system disk, or slow them down.",
    "mem_some": "Stop the program that uses the most memory, or add memory.",
    "mem_full": "Stop the largest memory user now. Everything stops while memory is full.",
    "cpu_some": "Stop or limit the process that uses the most CPU (see the top processes in the report).",
    "swap_percent": "Close programs or add memory. Heavy swap means memory is short.",
    "disk_percent": "Remove old files or add storage.",
    "gpu_percent": "Reduce GPU work (fewer streams or a lower frame rate) if the GPU is the bottleneck.",
}


def metric(main, detail):
    """One reading: the number used for the verdict, and the text that shows the amount."""
    return {"main": main, "detail": detail}


def pct(value):
    return "n/a" if value is None else "{:.1f}%".format(value)


def parse_psi(text):
    """Parse one /proc/pressure file into {'some': {'avg10': ..., 'total': ...}, 'full': {...}}."""
    result = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("some", "full"):
            continue
        values = {}
        for item in parts[1:]:
            key, _, value = item.partition("=")
            try:
                values[key] = float(value)
            except ValueError:
                pass
        result[parts[0]] = values
    return result


def read_psi():
    return {name: parse_psi(read_text("/proc/pressure/" + name)) for name in ("cpu", "memory", "io")}


def gpu_percent():
    for path in GPU_LOAD_FILES:
        value = read_number(path)
        if value is not None:
            return value / 10  # the load file is in tenths of a percent
    return None


def live_values():
    """The kernel's averages for the last 10 s, 1 min and 5 min, plus disk, swap and GPU."""
    psi = read_psi()

    def stall(resource, kind):
        block = psi[resource].get(kind, {})
        a10, a60, a300 = block.get("avg10"), block.get("avg60"), block.get("avg300")
        if a10 is None:
            return metric(None, "not reported by this kernel")
        return metric(a10, "{} over 10 s, {} over 1 min, {} over 5 min".format(pct(a10), pct(a60), pct(a300)))

    mem = memory_facts()
    swap = 100 * mem["swap_used_mb"] / mem["swap_total_mb"] if mem["swap_total_mb"] else None
    disk = disk_percent("/")
    gpu = gpu_percent()
    return {
        "io_some": stall("io", "some"),
        "mem_some": stall("memory", "some"),
        "mem_full": stall("memory", "full"),
        "cpu_some": stall("cpu", "some"),
        "swap_percent": metric(swap, "{} of swap in use ({} MB used)".format(pct(swap), mem["swap_used_mb"])),
        "disk_percent": metric(disk, "{} of the root filesystem is used".format(pct(disk))),
        "gpu_percent": metric(gpu, "{} busy".format(pct(gpu)) if gpu is not None else "not reported on this machine"),
    }


def psi_totals():
    """Running totals of time waited, in microseconds. A log turns these into per-second stall."""
    psi = read_psi()

    def total(resource, kind):
        value = psi[resource].get(kind, {}).get("total")
        return int(value) if value is not None else None

    return {
        "io_total_us": total("io", "some"),
        "mem_some_total_us": total("memory", "some"),
        "mem_full_total_us": total("memory", "full"),
        "cpu_some_total_us": total("cpu", "some"),
    }


def busy_percent(before, after):
    idle1, total1 = before
    idle2, total2 = after
    if total2 <= total1:
        return None
    return round(100 * (1 - (idle2 - idle1) / (total2 - total1)), 1)


def ping_once(address):
    """One ping to the PC you are logged in from. Returns the time in ms, or None."""
    if not address:
        return None
    result = run_command(["ping", "-c", "1", "-W", "1", address], timeout=5)
    found = re.search(r"time=([\d.]+) ms", result["stdout"])
    return float(found.group(1)) if found else None


def run_log(minutes, root=LOG_ROOT, client=None):
    """Record one sample per second for the given minutes. Returns the CSV path."""
    folder = root / datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "pressure.csv"
    previous_cpu = read_cpu_times()
    started = time.monotonic()
    deadline = started + minutes * 60
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOG_FIELDS)
        writer.writeheader()
        while time.monotonic() < deadline:
            tick = time.monotonic()
            cpu_now = read_cpu_times()
            row = {
                "time": datetime.datetime.now().isoformat(timespec="seconds"),
                "elapsed_s": round(tick - started, 2),
                "cpu_busy_percent": busy_percent(previous_cpu, cpu_now),
                "mem_available_mb": memory_facts()["available_mb"],
                "gpu_percent": gpu_percent(),
                "remote_ping_ms": ping_once(client),
            }
            row.update(psi_totals())
            writer.writerow(row)
            handle.flush()
            previous_cpu = cpu_now
            time.sleep(max(0.0, 1.0 - (time.monotonic() - tick)))
    return path


def load_log(path):
    with open(path, newline="") as handle:
        rows = []
        for raw in csv.DictReader(handle):
            row = {"time": raw["time"]}
            for key in LOG_FIELDS[1:]:
                text = raw.get(key)
                row[key] = float(text) if text not in (None, "") else None
            rows.append(row)
    return rows


def stall_stats(rows, key):
    """Average percent of time stalled over the log, and the worst 10-second window."""
    times = [row["elapsed_s"] for row in rows]
    totals = [row[key] for row in rows]
    if any(total is None for total in totals) or times[-1] <= times[0]:
        return None
    average = (totals[-1] - totals[0]) / ((times[-1] - times[0]) * 1e6) * 100
    worst = average if len(rows) <= WINDOW_SAMPLES else 0.0
    for i in range(len(rows) - WINDOW_SAMPLES):
        seconds = times[i + WINDOW_SAMPLES] - times[i]
        if seconds > 0:
            worst = max(worst, (totals[i + WINDOW_SAMPLES] - totals[i]) / (seconds * 1e6) * 100)
    return {"average": round(average, 2), "worst10": round(worst, 2)}


def summarise_log(rows):
    if len(rows) < 2:
        return None
    busy = [row["cpu_busy_percent"] for row in rows if row["cpu_busy_percent"] is not None]
    gpu = [row["gpu_percent"] for row in rows if row["gpu_percent"] is not None]
    pings = [row["remote_ping_ms"] for row in rows if row["remote_ping_ms"] is not None]
    return {
        "minutes": round((rows[-1]["elapsed_s"] - rows[0]["elapsed_s"]) / 60, 1),
        "start": rows[0]["time"],
        "end": rows[-1]["time"],
        "io_some": stall_stats(rows, "io_total_us"),
        "mem_some": stall_stats(rows, "mem_some_total_us"),
        "mem_full": stall_stats(rows, "mem_full_total_us"),
        "cpu_some": stall_stats(rows, "cpu_some_total_us"),
        "cpu_busy_max": max(busy) if busy else None,
        "gpu_max": max(gpu) if gpu else None,
        "ping_replies": len(pings),
        "ping_samples": len(rows),
        "ping_avg_ms": round(sum(pings) / len(pings), 1) if pings else None,
    }


def log_values(summary):
    def stall(key):
        item = summary.get(key)
        if not item:
            return metric(None, "not in this log")
        return metric(item["worst10"], "average {}%, worst 10 s {}%".format(item["average"], item["worst10"]))

    gpu = summary.get("gpu_max")
    return {
        "io_some": stall("io_some"),
        "mem_some": stall("mem_some"),
        "mem_full": stall("mem_full"),
        "cpu_some": stall("cpu_some"),
        "gpu_percent": metric(gpu, "highest in log: {}%".format(gpu)) if gpu is not None else metric(None, "not in this log"),
    }


def latest_log(root=LOG_ROOT):
    """The newest saved log as (path, age in minutes), or None."""
    if not root.exists():
        return None
    paths = sorted(root.glob("*/pressure.csv"), key=lambda p: p.stat().st_mtime)
    if not paths:
        return None
    path = paths[-1]
    return path, round((time.time() - path.stat().st_mtime) / 60, 1)


def collect_pressure():
    result = {"live": live_values(), "log": None}
    found = latest_log()
    if found:
        path, age = found
        try:
            summary = summarise_log(load_log(path))
            if summary:
                result["log"] = {"path": str(path), "age_minutes": age,
                                 "summary": summary, "values": log_values(summary)}
        except (OSError, KeyError, ValueError) as error:
            result["log_error"] = "could not read " + str(path) + ": " + str(error)
    return result


def verdict(value, warn, critical):
    if value is None:
        return "not measured"
    if critical is not None and value >= critical:
        return "critical"
    if warn is not None and value >= warn:
        return "warning"
    return "ok"


def threshold_text(warn, critical):
    parts = []
    if warn is not None:
        parts.append("warning at {:g}%".format(warn))
    if critical is not None:
        parts.append("critical at {:g}%".format(critical))
    return ", ".join(parts)


def rows_lines(values):
    """Report subsections: amount, what it means, and the verdict with its thresholds."""
    lines = []
    for key, label, meaning, warn, critical in ROWS:
        item = values.get(key, metric(None, "not in this source"))
        status = verdict(item["main"], warn, critical)
        verdict_text = status
        if status in ("warning", "critical"):
            verdict_text += " (" + threshold_text(warn, critical) + ")"
        lines += [
            "#### " + label,
            "",
            "- Amount: " + item["detail"],
            "- What it means: " + meaning,
            "- Verdict: " + verdict_text,
            "",
        ]
    return lines


def findings_for(values, source):
    out = []
    for key, label, meaning, warn, critical in ROWS:
        item = values.get(key)
        if not item:
            continue
        status = verdict(item["main"], warn, critical)
        if status in ("warning", "critical"):
            out.append(finding(
                status, "Pressure: " + label + " is " + status + " (" + source + ")",
                item["detail"] + ". " + meaning, FIXES[key]))
    return out


def pressure_findings(pressure):
    out = findings_for(pressure["live"], "live")
    if pressure.get("log"):
        out += findings_for(pressure["log"]["values"], "latest log")
    return out


def section_lines(pressure):
    lines = ["Live readings are the kernel's averages over 10 s, 1 min and 5 min. They are not a per-second history.", ""]
    lines += ["### Live", ""]
    lines += rows_lines(pressure["live"])
    log = pressure.get("log")
    if log:
        s = log["summary"]
        lines += ["### Latest log", "",
                  "File: {}, recorded {} to {} ({} minutes), saved {} minutes ago.".format(
                      log["path"], s["start"], s["end"], s["minutes"], log["age_minutes"]),
                  "Remote PC: answered {} of {} pings{}.".format(
                      s["ping_replies"], s["ping_samples"],
                      ", average {} ms".format(s["ping_avg_ms"]) if s["ping_avg_ms"] is not None else ""),
                  ""]
        lines += rows_lines(log["values"])
    elif pressure.get("log_error"):
        lines += ["### Latest log", "", pressure["log_error"], ""]
    else:
        lines += ["### Latest log", "",
                  "No log found in {}. Run `netdiag log --minutes 10` to record one.".format(LOG_ROOT), ""]
    return lines


def report_for_log(path):
    """The Pressure section for one saved log file, used by `netdiag pressure`."""
    summary = summarise_log(load_log(Path(path)))
    if summary is None:
        return ["The log in {} has fewer than two samples.".format(path)]
    lines = ["## Pressure", "", "File: {}".format(path),
             "Recorded {} to {} ({} minutes).".format(summary["start"], summary["end"], summary["minutes"]), ""]
    lines += rows_lines(log_values(summary))
    return lines


def terminal_lines(pressure):
    lines = []
    for key, label, meaning, warn, critical in ROWS:
        item = pressure["live"].get(key, metric(None, "not measured"))
        status = verdict(item["main"], warn, critical)
        lines.append("{}: {} ({})".format(label, status.upper() if status in ("warning", "critical") else status, item["detail"]))
    return lines
