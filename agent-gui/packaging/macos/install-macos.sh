#!/bin/bash
# Install, update or remove the EagleEye agent on a Mac (macOS 12 or later), from the agent's source
# package (eagleeye-agent-<version>.tar.gz, the dashboard's Agents > Install > macOS download).
#
#   sudo bash install-macos.sh eagleeye-agent-0.1.0.tar.gz --code-file code.txt   # first install: connects it
#   sudo bash install-macos.sh eagleeye-agent-0.1.0.tar.gz                        # update (keeps its connection)
#   sudo bash install-macos.sh --uninstall [--purge]                               # remove (--purge: and its settings)
#   add --no-gui to leave out the desktop window (a Mac without anyone signed in)
#
# It needs Python 3.12 or later: the python.org installer, or `brew install python@3.12` (macOS's own
# /usr/bin/python3 is too old). The agent runs as a launchd daemon (com.umeagleeye.agent, as root, from
# /usr/local/eagleeye with its own Python environment); its settings, state and logs are in
# /Library/Application Support/EagleEye. `eagleeye gui` opens its window; `sudo eagleeye service status`.
set -euo pipefail
DIR=/usr/local/eagleeye
DATA="/Library/Application Support/EagleEye"
TARBALL=""
CODE_FILE=""
GUI=1
UNINSTALL=0
PURGE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --code-file) CODE_FILE="$2"; shift 2 ;;
    --no-gui) GUI=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE="--purge"; shift ;;
    *) TARBALL="$1"; shift ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run it with sudo"; exit 1; }

if [ "$UNINSTALL" -eq 1 ]; then
  if [ -x "$DIR/.venv/bin/python" ]; then (cd "$DIR" && .venv/bin/python -m eagleeye service uninstall $PURGE) || true; fi
  rm -rf "$DIR" /usr/local/bin/eagleeye
  echo "Removed the agent${PURGE:+ and its settings ($DATA)}."
  exit 0
fi
[ -n "$TARBALL" ] && [ -f "$TARBALL" ] || { echo "Usage: sudo bash $0 <eagleeye-agent-*.tar.gz> [--code-file FILE] [--no-gui]"; exit 1; }

find_python() {
  for p in /Library/Frameworks/Python.framework/Versions/3.1[2-9]/bin/python3 \
           /opt/homebrew/bin/python3.1[2-9] /usr/local/bin/python3.1[2-9] /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    [ -x "$p" ] || continue
    if "$p" -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' 2>/dev/null; then echo "$p"; return 0; fi
  done
  return 1
}
PY="$(find_python)" || { echo "Python 3.12 or later is needed: install it from python.org or run 'brew install python@3.12', then run this again."; exit 1; }
echo "== Python: $PY ($("$PY" --version))"

echo "== installing $(basename "$TARBALL")"
launchctl bootout system/com.umeagleeye.agent 2>/dev/null || true
rm -rf "$DIR/eagleeye"                          # no files left over from the last version
mkdir -p "$DIR"
tar xzf "$TARBALL" -C "$DIR" --strip-components=1
chown -R root:wheel "$DIR" && chmod -R go-w "$DIR"   # the root daemon runs this code: only root may change it
cd "$DIR"
if [ ! -x .venv/bin/python ] || ! .venv/bin/python -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' 2>/dev/null; then
  rm -rf .venv
  "$PY" -m venv .venv
fi
# Passive listening uses macOS's own BPF devices (built in); scapy is kept for the libpcap
# comparison (`eagleeye listen --capture npcap`).
PACKAGES="keyring>=25.0 truststore>=0.10 scapy>=2.5.0"
[ "$GUI" -eq 1 ] && PACKAGES="$PACKAGES PySide6>=6.7"
.venv/bin/python -m pip install --quiet --upgrade pip
# shellcheck disable=SC2086
.venv/bin/python -m pip install --quiet $PACKAGES

# `eagleeye ...` from any folder (the daemon itself runs .venv/bin/python -m eagleeye service run)
cat > /usr/local/bin/eagleeye <<EOF
#!/bin/sh
cd "$DIR" && exec "$DIR/.venv/bin/python" -m eagleeye "\$@"
EOF
chmod 755 /usr/local/bin/eagleeye

if [ -n "$CODE_FILE" ]; then
  echo "== connecting with the code in $CODE_FILE"
  .venv/bin/python -m eagleeye service enrol --connection-code-file "$CODE_FILE"
fi
echo "== the daemon"
.venv/bin/python -m eagleeye service install        # (re)writes /Library/LaunchDaemons/com.umeagleeye.agent.plist and starts it
sleep 5
.venv/bin/python -m eagleeye service status || true
echo "== last lines of the log"
tail -n 15 "$DATA/logs/agent.log" 2>/dev/null || true
echo
echo "Done. Open its window with: eagleeye gui"
echo "Syft and Grype (SBOM and CVEs) and Nmap are optional: brew install syft grype nmap"
