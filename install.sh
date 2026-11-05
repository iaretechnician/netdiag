#!/usr/bin/env bash
# install.sh: install, check, or refresh the netdiag tool on an Ubuntu machine.
#
#   bash install.sh            download the code, install packages, save the version list
#   bash install.sh --refresh  reinstall packages, then compare them with the saved version list
#   bash install.sh --check    compare only. Changes nothing.
#
# Environment variables:
#   NETDIAG_BRANCH       branch to install (default: main)
#   NETDIAG_INSTALL_DIR  where the code goes (default: $HOME/devkit-netdiag)

set -euo pipefail

# Non-login shells often leave out the sbin folders, where iptables lives.
export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"

BRANCH="${NETDIAG_BRANCH:-main}"
INSTALL_DIR="${NETDIAG_INSTALL_DIR:-$HOME/devkit-netdiag}"
STATE_DIR="$HOME/.local/state/netdiag"
STATE_FILE="$STATE_DIR/installed-versions.txt"
REQUIRED_COMMANDS="curl tar python3 ip ping traceroute ss iptables"

MODE="install"
case "${1:-}" in
  "") MODE="install" ;;
  --refresh) MODE="refresh" ;;
  --check) MODE="check" ;;
  *)
    echo "Unknown option: $1" >&2
    echo "Use --refresh or --check, or no option." >&2
    exit 2
    ;;
esac

fetch_code() {
  # Download the branch as an archive from GitHub and unpack it. Git is not needed.
  local url="https://github.com/iaretechnician/netdiag/archive/refs/heads/$BRANCH.tar.gz"
  local tmp
  tmp=$(mktemp -d)
  if ! curl -fsSL "$url" -o "$tmp/code.tar.gz"; then
    echo "Could not download the code from $url" >&2
    exit 1
  fi
  tar -xzf "$tmp/code.tar.gz" -C "$tmp"
  rm -rf "$INSTALL_DIR"
  mv "$tmp/netdiag-$BRANCH" "$INSTALL_DIR"
  rm -rf "$tmp"
  echo "Downloaded the code from branch $BRANCH."
}

package_list() {
  grep -v -e '^#' -e '^$' "$INSTALL_DIR/deps/apt-packages.txt"
}

install_packages() {
  local missing="" pkg
  if [ "$MODE" = "refresh" ]; then
    sudo apt-get update -qq
    # shellcheck disable=SC2046
    sudo apt-get install -y -qq $(package_list)
    echo "Reinstalled the packages."
    return
  fi
  for pkg in $(package_list); do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing="$missing $pkg"
    fi
  done
  if [ -n "$missing" ]; then
    sudo apt-get update -qq
    # shellcheck disable=SC2086
    sudo apt-get install -y -qq $missing
    echo "Installed:$missing"
  else
    echo "All packages were already installed."
  fi
}

installed_versions() {
  # shellcheck disable=SC2046
  dpkg-query -W -f='${Package} ${Version}\n' $(package_list) 2>/dev/null || true
}

save_versions() {
  mkdir -p "$STATE_DIR"
  installed_versions > "$STATE_FILE"
  echo "Saved the package version list to $STATE_FILE"
}

verify_tools() {
  local problems=0 cmd
  for cmd in $REQUIRED_COMMANDS; do
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "ok       $cmd"
    else
      echo "MISSING  $cmd"
      problems=$((problems + 1))
    fi
  done
  if [ ! -f "$STATE_FILE" ]; then
    echo "note     no saved version list yet"
  elif installed_versions | diff -q - "$STATE_FILE" >/dev/null; then
    echo "ok       package versions match the saved list"
  else
    echo "DIFFERS  package versions do not match the saved list:"
    installed_versions | diff - "$STATE_FILE" || true
    problems=$((problems + 1))
  fi
  return "$problems"
}

link_command() {
  sudo ln -sf "$INSTALL_DIR/bin/netdiag" /usr/local/bin/netdiag
  echo "Installed the command: netdiag"
}

run_self_test() {
  mkdir -p "$STATE_DIR"
  if (cd "$INSTALL_DIR" && python3 -m unittest discover -s netdiag/tests -t . >"$STATE_DIR/selftest.log" 2>&1); then
    echo "ok       self-test passed"
    return 0
  fi
  echo "FAILED   self-test. See $STATE_DIR/selftest.log"
  return 1
}

main() {
  if [ "$MODE" = "check" ]; then
    if [ ! -f "$INSTALL_DIR/bin/netdiag" ]; then
      echo "Not installed at $INSTALL_DIR. Run: bash install.sh" >&2
      exit 1
    fi
  else
    fetch_code
    install_packages
  fi

  if [ "$MODE" = "install" ]; then
    save_versions
    link_command
  fi

  local problems=0
  verify_tools || problems=$?
  run_self_test || problems=$((problems + 1))

  if [ "$problems" -eq 0 ]; then
    echo "Done. All checks passed."
  else
    echo "Done with $problems problem(s). See above." >&2
    exit 1
  fi
}

main
