#!/bin/bash
# Remove egressguard from the system: the daemon, its pf rules, its pf reference and
# the menu bar login item. Run through `sudo egressguard uninstall`.
# pf itself stays enabled for anyone else holding a reference; nothing else is
# touched. The user's settings.json stays for a later reinstall; the Homebrew files
# go with `brew uninstall egressguard`. Exits non-zero if anything was left behind.
set -uo pipefail

[[ $(id -u) == 0 ]] || { echo "run it as: sudo egressguard uninstall" >&2; exit 2; }
readonly DEST="/Library/Application Support/EgressGuard"
readonly LABEL=com.sentiens.egressguard
readonly ANCHOR=com.apple/050.EgressGuard
failures=0

fail() {
  echo "$1" >&2
  failures=$((failures + 1))
}

launchctl bootout "system/$LABEL" 2>/dev/null
rm -f "/Library/LaunchDaemons/$LABEL.plist" || fail "the daemon's plist was not removed"
# bootout returns before the daemon has exited; a last step could still load rules.
for _ in $(seq 40); do
  pgrep -f "$DEST/egressguard daemon" >/dev/null || break
  sleep 0.25
done
pkill -9 -f "$DEST/egressguard daemon" 2>/dev/null

flushed=true
pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || { fail "pfctl could not flush $ANCHOR"; flushed=false; }
# Released tokens leave the file at once, so another try only retries the rest.
released=true
if [[ -f $DEST/pf-tokens ]]; then
  remaining=()
  while read -r token; do
    [[ $token =~ ^[0-9]+$ ]] || continue
    if ! pfctl -X "$token" >/dev/null 2>&1; then
      fail "pf reference $token was not released (pfctl -X $token)"
      remaining+=("$token")
      released=false
    fi
  done < "$DEST/pf-tokens"
  if ((${#remaining[@]} > 0)); then
    printf '%s\n' "${remaining[@]}" > "$DEST/pf-tokens"
  else
    : > "$DEST/pf-tokens"
  fi
fi
if $flushed && $released; then
  rm -rf "$DEST" || fail "$DEST was not removed"
else
  echo "kept $DEST (its pf-tokens) for another try: sudo egressguard uninstall" >&2
fi

if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
  uid=$(id -u "$SUDO_USER")
  home=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | awk '{print $2}')
  launchctl bootout "gui/$uid/$LABEL-menu" 2>/dev/null
  rm -f "$home/Library/LaunchAgents/$LABEL-menu.plist" || fail "the menu bar login item was not removed"
  rm -f "$home/Library/Application Support/EgressGuard/control.json" || fail "the control file was not removed"
  echo "settings kept: $home/Library/Application Support/EgressGuard/settings.json"
fi

left=$(pfctl -a "$ANCHOR" -s rules 2>/dev/null)
if [[ -z $left ]]; then
  echo "pf: egressguard rules gone"
else
  fail "pf: rules still loaded:"$'\n'"$left"
fi
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
  fail "the daemon is still registered with launchd"
else
  echo "daemon: removed"
fi
if curl --noproxy '*' -sS -o /dev/null -m 6 https://1.1.1.1/cdn-cgi/trace ||
  curl --noproxy '*' -sS -o /dev/null -m 6 https://www.apple.com/library/test/success.html; then
  echo "internet: works"
else
  echo "internet: no answer (the switch is gone, so the cause is elsewhere)" >&2
fi

if ((failures > 0)); then
  echo "egressguard was not removed completely: $failures problem(s) above" >&2
  exit 1
fi
echo "egressguard removed from the system; the Homebrew files go with: brew uninstall egressguard"
