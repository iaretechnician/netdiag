"""Run one command and return what it printed. Nothing here raises for a normal failure.

This tool runs on Linux only. It uses ip, ss, ping, and the firewall tools.
"""
import os
import shutil
import subprocess

# Tools such as iptables live in sbin folders that a non-login shell may not search.
EXTRA_DIRS = ["/usr/local/sbin", "/usr/sbin", "/sbin"]


def find_program(name):
    """Return the full path of a program, or None if it is not installed."""
    search = os.pathsep.join([os.environ.get("PATH", "")] + EXTRA_DIRS)
    return shutil.which(name, path=search)


def run_command(args, timeout=60, privileged=False):
    """Run a command. Returns a dict with the return code, stdout, and stderr.

    When privileged is True and we are not root, the command runs through
    sudo without a password prompt (sudo -n). If that is not allowed, the
    error text says so.
    """
    program = find_program(args[0])
    if program is None:
        return {
            "available": False,
            "returncode": None,
            "stdout": "",
            "stderr": args[0] + " is not installed",
        }
    command = [program] + args[1:]
    if privileged and os.geteuid() != 0:
        command = ["sudo", "-n"] + command
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "returncode": None,
            "stdout": "",
            "stderr": "timed out after " + str(timeout) + " seconds",
        }
    return {
        "available": True,
        "returncode": done.returncode,
        "stdout": done.stdout,
        "stderr": done.stderr,
    }


def error_text(result):
    """Return the most useful error text from a failed command."""
    return result["stderr"].strip() or "no output (exit " + str(result["returncode"]) + ")"
