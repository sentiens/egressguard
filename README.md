# EgressGuard

A kill switch for macOS that works with any VPN app. The Mac reaches the
internet only through networks you trust, or through a VPN tunnel, or not at
all. It is not tied to any VPN client: it lets out only what can leak nothing,
the packets that go to a tunnel's server, and stays out of the tunnel's own
interface.

```
                 packet leaving the Mac on a physical uplink (en0, en5, ...)
                                       |
                 is this uplink on a trusted network (router IP + router MAC,
                 confirmed by a fresh ARP check)?
                      |                                   |
                     yes                                  no
                      |                                   |
         passes, but only from the address      only to tunnel endpoints, plus DHCP,
         it had when the network was checked    IPv6 neighbour discovery and ping to
                                                the LAN; everything else is dropped

   VPN interfaces (utun*, ipsec*) and local ones (lo0, awdl0, bridge*, ...) are untouched.
```

- **Any VPN.** WireGuard, IKEv2, OpenVPN or any other client with a tunnel
  mode: the switch only needs to know where the tunnel's server is. Servers of
  VPN configurations in macOS are picked up automatically; others can be learned
  on a trusted network or entered by hand.
- **Trusted networks** are your own routers, identified by router address and
  router MAC (as macOS identifies networks), optionally tied to an interface.
- **Nothing trusted** is a valid mode: VPN only, even at home.
- **Quick off.** `egressguard off 15` or the menu bar shield, no password. It
  guards against leaks, not against its own user.
- **No Apple developer account needed.** It uses the packet filter built into
  macOS (pf) and a root daemon in Go (standard library only). Homebrew builds it
  from source; nothing is notarized.

## How it fails safe

- Every change of network, sleep, wake, settings change or restart of the daemon
  first closes all uplinks and drops their pf states, then re-checks the network
  from scratch.
- A trusted uplink may send only from the address it had when it was checked. On
  another network the address differs and the kernel drops the packets, even if
  the daemon is slow or dead.
- The network is sealed before the Mac sleeps and stays sealed until a real wake.
- pf being disabled by anyone is undone within a second.

The full design, its event list and its known gaps are in
[docs/design.md](docs/design.md).

## Install

Requires macOS 14 or newer. Homebrew builds it with Go and the Xcode Command
Line Tools (`xcode-select --install`).

```
brew tap sentiens/tap
brew install egressguard
egressguard detect              # this network's router and MAC
sudo egressguard setup          # installs the root daemon and the menu bar app
```

`setup` copies the `egressguard` binary into `/Library/Application Support/EgressGuard`
(root-owned: launchd never runs code from the Homebrew prefix, which your user
can write to) and registers `com.sentiens.egressguard` with launchd, running
`egressguard daemon`. It will not leave
the Mac offline:

- it needs the internet before it starts;
- with no trusted network yet it offers to trust the current one;
- it dry-runs the decision and installs with the switch **off** if this network
  is neither trusted nor tunnelled;
- it checks the internet with the switch on and turns the switch off if that
  check fails.

After `brew upgrade egressguard`, run `sudo egressguard setup` again: the
running daemon is a copy and is not replaced by Homebrew. `egressguard status`
warns when the two differ.

## Use

```
egressguard                      status
egressguard off 15               off for 15 minutes, then on by itself
egressguard off                  off until turned on
egressguard on
egressguard trust-current [name] trust the network this Mac is on now
egressguard endpoints            every allowed tunnel endpoint and where it came from
egressguard detect               each uplink's router and MAC
egressguard test                 a few seconds with nothing trusted: a direct request must fail
sudo egressguard leaktest [seconds] [--safari]
                                 capture every packet leaving the uplinks while nothing is
                                 trusted, generate traffic and count what got past the rules
```

The menu bar shield shows the state and offers on and off (15 minutes, 1 hour,
until turned on). **Settings…** edits:

- trusted networks, with **Trust this network**;
- the ways out on other networks: servers of VPN configurations in macOS, and
  servers learned from VPN apps on a trusted network (off by default);
- your own endpoints (`ip:port`, TCP or UDP);
- **No trusted networks: VPN only, even at home**.

The window writes `~/Library/Application Support/EgressGuard/settings.json`; the
daemon checks every entry and keeps the last good settings if the file is bad.
An administrator can add entries that the window cannot remove in
`/Library/Application Support/EgressGuard/config.json` (see
[config/config.example.json](config/config.example.json)).

## Check it on your Mac

```
sudo egressguard leaktest 30 --safari
```

With nothing trusted for 30 seconds it captures every packet leaving the
physical uplinks while it makes requests (curl, ping, DNS, optionally Safari),
and it fails on any packet that is not to a tunnel endpoint. Run it with the VPN
off and on, at home and on a phone hotspot. The full test plan is in
[docs/testing.md](docs/testing.md).

## Limits

- **Boot.** Between boot and the daemon's start pf has no rules. Turn off
  auto-join for Wi-Fi networks other than your own.
- **Bridged VMs** bypass pf. The status warns about bridged uplinks; use NAT mode.
- **The same address on another network** cannot be told apart by the address
  pin; there safety rests on the daemon reacting to the link change.
- **pf is not an Apple-supported API for apps** (TN3165). Some macOS releases let
  some Apple processes past pf; `leaktest --safari` checks yours.
- **Captive portals and LAN services** on untrusted networks are blocked; turn
  the switch off for a portal.
- **Tunnels with changing server addresses** (provider pools) need learning
  or manual endpoints.
- **Router MACs can be spoofed** by someone on your local network.

## Uninstall

```
sudo egressguard uninstall      # daemon, pf rules, menu bar login item
brew uninstall egressguard
```

Your `settings.json` stays for a later reinstall.

## Develop

```
make               # build/egressguard and build/EgressGuard.app (ad-hoc signed)
make test          # gofmt, go vet, shellcheck, go test -race
./build/egressguard detect   # the CLI works from a checkout
```

The code is Go with no dependencies outside the standard library (cgo only for
IOKit's sleep notifications and the clocks) and a small Swift menu bar app:

| Path | What it is |
|---|---|
| `internal/guard` | the daemon: policy, observing the network, pf rules, the decision loop |
| `internal/leak` | reading packet captures for `leaktest` |
| `cmd/egressguard` | the CLI; `egressguard daemon` runs the daemon |
| `app/` | the menu bar app |
| `scripts/` | `setup.sh` and `uninstall.sh`, run through the CLI as root |

See [docs/design.md](docs/design.md) and [docs/testing.md](docs/testing.md).

## License

MIT, see [LICENSE](LICENSE).
