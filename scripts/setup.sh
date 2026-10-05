#!/bin/bash
# Install or update the egressguard root daemon and the menu bar login item.
# Run through `sudo egressguard setup`, which passes:
#   EGRESSGUARD_DAEMON   the egressguard binary; launchd runs a root-owned copy, never
#                        code from a prefix the user can write to (such as Homebrew's)
#   EGRESSGUARD_CONFIG   the administrator config template
#   EGRESSGUARD_APP      the menu bar app (may be empty)
#   EGRESSGUARD_INITIAL  the switch on a first install: "pending" (off until the user
#                        sets it up) or "on"; empty on an update, which leaves it alone
# It refuses to leave the Mac offline: it needs the internet to start, dry-runs the
# decision first, checks the internet with the switch on, and on any doubt turns the
# switch off and flushes the rules.
set -euo pipefail

[[ $(id -u) == 0 && -n ${SUDO_USER:-} && $SUDO_USER != root ]] || { echo "run it as: sudo egressguard setup" >&2; exit 2; }
[[ -f ${EGRESSGUARD_DAEMON:-} && -f ${EGRESSGUARD_CONFIG:-} ]] || { echo "EGRESSGUARD_DAEMON and EGRESSGUARD_CONFIG must name files" >&2; exit 2; }
readonly INITIAL=${EGRESSGUARD_INITIAL:-}
[[ $INITIAL == "" || $INITIAL == pending || $INITIAL == on ]] || { echo "EGRESSGUARD_INITIAL must be pending, on or empty" >&2; exit 2; }

readonly LABEL=com.sentiens.egressguard
readonly MENU_LABEL=com.sentiens.egressguard-menu
readonly ANCHOR=com.apple/050.EgressGuard
readonly DEST="/Library/Application Support/EgressGuard"
readonly PLIST="/Library/LaunchDaemons/$LABEL.plist"
readonly LOG=/Library/Logs/egressguard.log
USER_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | awk '{print $2}')
USER_ID=$(id -u "$SUDO_USER")
readonly USER_HOME USER_ID
readonly USER_DIR="$USER_HOME/Library/Application Support/EgressGuard"
readonly CONTROL="$USER_DIR/control.json"
readonly MENU_PLIST="$USER_HOME/Library/LaunchAgents/$MENU_LABEL.plist"

as_user() { sudo -u "$SUDO_USER" "$@"; }

# control writes the user's control file, as the user. Each step is checked
# explicitly: callers use it in conditions, where set -e does not apply.
control() {
  as_user mkdir -p "$USER_DIR" &&
    printf '%s\n' "$1" | as_user tee "$CONTROL.tmp" >/dev/null &&
    as_user mv -f "$CONTROL.tmp" "$CONTROL"
}

# stop_daemon unloads the daemon and waits until it has exited.
stop_daemon() {
  launchctl bootout "system/$LABEL" 2>/dev/null
  for _ in $(seq 40); do
    pgrep -f "$DEST/egressguard daemon" >/dev/null || return 0
    sleep 0.25
  done
  return 1
}

online() {
  curl --noproxy '*' -sS -o /dev/null -m 6 https://1.1.1.1/cdn-cgi/trace ||
    curl --noproxy '*' -sS -o /dev/null -m 6 https://www.apple.com/library/test/success.html
}

# field prints a JSON file's top-level field, or nothing (also for a missing file).
field() { plutil -extract "$2" raw -o - "$1" 2>/dev/null || true; }

flush() { pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || true; }

# rollback turns the switch off (or, if even that fails, stops the daemon) and
# flushes the rules, so nothing can load them again.
rollback() {
  echo "$1; turning the switch off (see $LOG)" >&2
  if control '{"mode": "off"}'; then
    sleep 3 # the daemon flushes its rules within a second
  else
    echo "the switch could not be turned off: stopping the daemon" >&2
    stop_daemon || echo "the daemon is still running: sudo egressguard uninstall" >&2
  fi
  flush
  if online; then
    echo "the internet works with the switch off" >&2
  else
    echo "still offline: sudo egressguard uninstall" >&2
  fi
  exit 1
}

write_daemon_plist() {
  cat > "$1" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$DEST/egressguard</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
  plutil -lint "$1" >/dev/null
}

install_menu_app() {
  if [[ -z ${EGRESSGUARD_APP:-} || ! -d $EGRESSGUARD_APP ]]; then
    echo "menu bar app: not found, skipped"
    return
  fi
  as_user mkdir -p "$USER_HOME/Library/LaunchAgents"
  as_user tee "$MENU_PLIST" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$MENU_LABEL</string>
  <key>ProgramArguments</key><array><string>$EGRESSGUARD_APP/Contents/MacOS/EgressGuard</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$USER_ID/$MENU_LABEL" 2>/dev/null || true
  for _ in $(seq 10); do
    launchctl bootstrap "gui/$USER_ID" "$MENU_PLIST" 2>/dev/null && break
    sleep 0.5
  done
  if launchctl print "gui/$USER_ID/$MENU_LABEL" >/dev/null 2>&1; then
    echo "menu bar app: started ($EGRESSGUARD_APP)"
  else
    echo "menu bar app: not started; open $EGRESSGUARD_APP once"
  fi
}

online || { echo "no internet even before installing; not touching anything" >&2; exit 1; }

STAGE=$(mktemp -d /private/tmp/egressguard-setup.XXXXXX) # sticky /tmp: no one else can swap it
trap 'rm -rf "$STAGE"' EXIT

# Dry run, with the very copy that will be installed.
install -o root -g wheel -m 0755 "$EGRESSGUARD_DAEMON" "$STAGE/egressguard"
sed "s|@CONTROL@|$CONTROL|" "$EGRESSGUARD_CONFIG" > "$STAGE/config.json"
as_user mkdir -p "$USER_DIR"
"$STAGE/egressguard" check-config "$STAGE/config.json" > "$STAGE/check.json" || true
if [[ $(field "$STAGE/check.json" syntax_ok) != true ]]; then
  echo "the dry run failed:" >&2
  cat "$STAGE/check.json" >&2
  exit 1
fi
state=$(field "$STAGE/check.json" state)
echo "dry run: with the switch on, this network would be: $state"
case $INITIAL in
  pending) control '{"mode": "off", "setup_pending": true}' || { echo "the control file was not written" >&2; exit 1; } ;;
  on) control '{"mode": "on"}' || { echo "the control file was not written" >&2; exit 1; } ;;
esac
if [[ $state == blocked && $INITIAL != pending ]]; then
  echo "this network is neither trusted nor tunnelled: installing with the switch OFF"
  echo "  trust it with: egressguard trust-current [name]   (or the menu bar shield, Settings…)"
  echo "  then: egressguard on"
  control '{"mode": "off"}'
fi

install -d -o root -g wheel -m 0755 "$DEST"
install -o root -g wheel -m 0755 "$STAGE/egressguard" "$DEST/egressguard"
install -o root -g wheel -m 0644 "$STAGE/config.json" "$DEST/config.json"
write_daemon_plist "$STAGE/$LABEL.plist"

# From here a failure must not leave rules with nothing maintaining them.
trap 'flush; rm -rf "$STAGE"' EXIT
stop_daemon || true # the old daemon must be gone before the new one starts
install -o root -g wheel -m 0644 "$STAGE/$LABEL.plist" "$PLIST"
started=$(date +%s)
bootstrapped=false
for _ in $(seq 20); do # bootout returns before the old job is gone
  if launchctl bootstrap system "$PLIST" 2>/dev/null; then
    bootstrapped=true
    break
  fi
  sleep 0.5
done
$bootstrapped || { echo "launchctl bootstrap failed; rules flushed, nothing running" >&2; exit 1; }

updated=0
for _ in $(seq 30); do
  sleep 0.5
  updated=$(field "$DEST/status.json" updated)
  (( ${updated:-0} >= started )) && break
done
(( ${updated:-0} >= started )) || rollback "the daemon did not report within 15 s"
sleep 1
online || rollback "the internet check failed with the switch on"
trap 'rm -rf "$STAGE"' EXIT
echo "daemon installed: $(field "$DEST/status.json" state), anchor $ANCHOR, log $LOG"
if [[ $INITIAL == pending ]]; then
  echo "EgressGuard is OFF until you set it up: in the window the menu bar shield opens"
  echo "  (or: egressguard trust-current [name], then egressguard on)"
fi

install_menu_app
