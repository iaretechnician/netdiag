# netdiag

netdiag checks a Linux machine's network and tells you, in plain words, what is wrong and what to try next. It runs on Ubuntu 22.04 and 24.04.

## Install

Download the installer and run it. It asks for your password when it installs the packages it needs.

```bash
curl -fsSLO https://raw.githubusercontent.com/iaretechnician/netdiag/main/install.sh
bash install.sh
```

The code goes to `~/devkit-netdiag`. To check the install later, run `bash install.sh --check`. To update, run `bash install.sh --refresh`.

## Run

```bash
~/devkit-netdiag/bin/netdiag run             # base network checks
~/devkit-netdiag/bin/netdiag run --nic       # wired network ports, with driver messages
~/devkit-netdiag/bin/netdiag run --wifi      # WiFi adapters
~/devkit-netdiag/bin/netdiag run --cellular  # cellular modems
~/devkit-netdiag/bin/netdiag run --all       # every check
```

Each run writes a report folder with a plain report (`report.md`) and the raw results. The bottom of the terminal output lists the checks that were not run and the flag that adds each one.

## Other commands

```bash
~/devkit-netdiag/bin/netdiag log --minutes 10   # record CPU, memory and disk use over time
~/devkit-netdiag/bin/netdiag pressure           # report the latest recording
~/devkit-netdiag/bin/netdiag report <folder>    # rebuild a report from saved results
```

## Notes

- Some checks read kernel messages and need `sudo` without a password prompt. Without it, the report says that section could not be read.
- The devkit checks (`--ironman`, `--poseidon`, `--proteus`, `--apollo`) only apply to the devkit software and say so when it is not installed.
