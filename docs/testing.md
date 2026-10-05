# Testing

## Automated

```
make test
```

`make test` runs gofmt, go vet, shellcheck (when installed) and the Go tests with
the race detector; CI adds staticcheck with every check on and errcheck (no
error or type assertion goes unchecked), builds the menu bar app, builds the tree
the way Homebrew does (`scripts/check-homebrew-build.sh`) and stages an install.

The tests run the daemon over a fake Mac (network tools, pf, clocks, the
settings files), so every rule of the policy is exercised without root:

| Area | Files |
|---|---|
| config, settings and control files | `internal/guard/config_test.go`, `files_test.go` |
| observing uplinks, ARP, pins | `network_test.go` |
| the pf rules, and `pfctl -n` accepting them | `rules_test.go`, `pf_test.go` |
| route-monitor messages | `monitor_test.go` |
| VPN configurations and learning | `learn_test.go` |
| the decision loop, trust breaks, the self-test | `daemon_test.go`, `urgent_test.go` |
| dropping pf states on every transition | `revoke_test.go` |
| sleep, the seal, dark wakes | `power_test.go` |
| Step, Urgent and Seal at once, under `-race` | `urgent_test.go` |
| pcap/pcapng parsing and verdicts | `internal/leak/leak_test.go` |
| the CLI, its files, judging captures | `cmd/egressguard/app_test.go` |

Every safety rule of the daemon has a test that fails when the rule is removed:
this was checked by mutating the code (47 mutations, such as skipping the close,
keeping states, trusting a stale observation, skipping the fresh check of an
uplink that did not answer, forgetting a failed pf check, following symlinks,
unsealing on any input or passing a cut-short capture) and running the tests
against each.

`./build/egressguard check-config config/config.example.json` prints the
decision the daemon would take on this Mac and checks the rules with
`pfctl -n`, without loading anything.

## On a real Mac

Each step has to pass before the next. On any problem: `egressguard off` at once,
then `sudo egressguard uninstall` if needed.

1. **Install.** `sudo egressguard setup` prints `dry run: ... trusted`, then
   `daemon installed: trusted`. `egressguard endpoints` lists the endpoints and
   where they came from.
2. **Ordinary use at home** for a while: sites, messengers, a large download.
   Nothing may differ.
3. **Leak test at home, nothing trusted for 30 s.**
   - `sudo egressguard leaktest 30 --safari` with the VPN off. It must end with no
     packet past the rules. On a closed uplink pf drops everything else before the
     capture sees it, so any other packet, local or internet, fails the test and
     points to a pf bypass.
   - The same with the VPN on: tunnel traffic keeps working, and the capture shows
     only the endpoint.
4. **Phone hotspot.**
   - VPN off: status `blocked`, no site opens. Run the leak test there too.
   - VPN on: status `tunnel`, sites open.
   - VPN off again: sites stop at once.
   - With learning on: connect once at home, check `egressguard endpoints` shows
     `connection: ...`, then repeat on the hotspot.
5. **Network switch while awake.** Home → hotspot → home. On the hotspot nothing
   goes direct; back home the internet returns within about a second.
6. **Sleep.**
   - Close the lid at home, wait over a minute, open it on the hotspot: closed
     until the VPN connects.
   - Close it on the hotspot and open it at home: the internet returns within
     about a second of the first key press or mouse movement.
   - `/Library/Logs/egressguard.log` shows `system going to sleep`, then
     `system woke`.
7. **Off and on.** Menu: off for 15 minutes, then on. `egressguard off 1`: on by
   itself after a minute.
8. **Reboot.** After login the status is `trusted`.
9. **Uninstall.** `sudo egressguard uninstall` reports the rules gone, the daemon
   removed and the internet working.
