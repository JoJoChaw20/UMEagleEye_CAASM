#!/usr/bin/env bash
# Install or update the agent on an Ubuntu test VM from a Linux package built on the PC.
#
#   sudo bash ~/update-ubuntu-vm.sh ~/eagleeye-agent-0.1.0.tar.gz                      # update (keeps its connection)
#   sudo bash ~/update-ubuntu-vm.sh ~/eagleeye-agent-0.1.0.tar.gz --code-file ~/code.txt   # first install: connect it
#   sudo bash ~/update-ubuntu-vm.sh --purge                                           # remove the agent and its settings
#
# The service runs the code in /opt/eagleeye-dev with the system python3 (its unit points there), so
# an update replaces that folder and restarts it. Settings and state stay in /var/lib/eagleeye.
# See TESTING-VMS.md.
set -euo pipefail
DIR=/opt/eagleeye-dev
TARBALL=""
CODE_FILE=""
PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --code-file) CODE_FILE="$2"; shift 2 ;;
    --purge) PURGE=1; shift ;;
    *) TARBALL="$1"; shift ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run it with sudo"; exit 1; }

if [ "$PURGE" -eq 1 ]; then
  if [ -d "$DIR/eagleeye" ]; then (cd "$DIR" && python3 -m eagleeye service uninstall --purge) || true; fi
  rm -rf "$DIR"
  echo "Removed the agent service, its settings (/var/lib/eagleeye) and $DIR"
  exit 0
fi
[ -n "$TARBALL" ] && [ -f "$TARBALL" ] || { echo "Usage: sudo bash $0 <eagleeye-agent-*.tar.gz> [--code-file FILE]"; exit 1; }

echo "== installing $(basename "$TARBALL") ($(date -r "$TARBALL" '+%Y-%m-%d %H:%M'))"
systemctl stop eagleeye-agent 2>/dev/null || true
rm -rf "$DIR"                                   # no files left over from the last build
mkdir -p "$DIR"
tar xzf "$TARBALL" -C "$DIR" --strip-components=1
chown -R root:root "$DIR" && chmod -R go-w "$DIR"   # the root service runs this code: only root may change it
cd "$DIR"

if [ -n "$CODE_FILE" ]; then
  echo "== connecting with the code in $CODE_FILE"
  python3 -m eagleeye service enrol --connection-code-file "$CODE_FILE"
fi
echo "== the service"
python3 -m eagleeye service install            # (re)writes the unit to run $DIR; keeps /var/lib/eagleeye
systemctl restart eagleeye-agent
sleep 5
python3 -m eagleeye service status || true
echo "== last lines of the log"
tail -n 15 /var/lib/eagleeye/logs/agent.log 2>/dev/null || journalctl -u eagleeye-agent -n 15 --no-pager
