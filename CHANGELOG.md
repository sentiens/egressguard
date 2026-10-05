# Changelog

## 0.2.1 (2026-10-05)

- The setup window builds under Homebrew: its state is an `ObservableObject`, not
  `@State`, which newer SDKs implement as a macro that Homebrew's build cannot
  load. 0.2.0 did not install from Homebrew on such SDKs.
- CI builds the tree the way Homebrew does (`scripts/check-homebrew-build.sh`).

## 0.2.0 (2026-10-05)

- A first install leaves EgressGuard off until the user sets it up: `setup` asks
  in the terminal, and otherwise the menu bar app opens a setup window that asks
  whether to trust the current network and turns EgressGuard on only on request.
  `control.json` and `status.json` carry `setup_pending` meanwhile.
- Several prompts in one `setup` read the same input, so answers typed ahead are
  no longer lost.

## 0.1.0 (2026-10-05)

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
