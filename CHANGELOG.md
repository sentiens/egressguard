# Changelog

## 0.1.0 (unreleased)

First release.

- Root daemon (`egressguard daemon`, Go, standard library only) keeping the pf
  anchor `com.apple/050.EgressGuard`: trusted networks by router address, router
  MAC and interface, an address pin on trusted uplinks, tunnel endpoints from the
  config, the user's settings, macOS VPN configurations and (opt-in) connections
  of VPN apps.
- Trust breaks on start, link and default-route changes, settings changes, sleep,
  wake and off→on; a sleep seal; pf re-enabled within a second.
- pf states dropped on every transition that closes an address, retried until
  they are gone.
- `egressguard` CLI: status, on, off [minutes], trust-current, endpoints, detect,
  test, leaktest, setup, uninstall, version.
- Menu bar app with a settings window.
- Homebrew formula in `sentiens/tap`; `sudo egressguard setup` installs the daemon
  as a root-owned copy.
