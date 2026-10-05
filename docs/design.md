# Design

EgressGuard keeps one pf anchor, `com.apple/050.EgressGuard`, in step with the
network the Mac is on. A root daemon (`egressguard daemon`, LaunchDaemon
`com.sentiens.egressguard`) decides; the CLI and the menu bar app only write the
user's own files.

## Parts

| Part | Where | Runs as |
|---|---|---|
| `egressguard daemon` | `/Library/Application Support/EgressGuard/egressguard` (a copy made by `setup`), log `/Library/Logs/egressguard.log` | root |
| `config.json` (administrator) | same directory | root-owned, re-read on change |
| `learned.json`, `status.json`, `pf-tokens`, `settings.last-good.json` | same directory | written by the daemon |
| `settings.json` (trusted networks, endpoints, switches) | `~/Library/Application Support/EgressGuard/` | the user, through the settings window or `trust-current` |
| `control.json` (`on`, `off`, `off` until, `lock` until; `off` with `setup_pending` after a first install) | same directory | the user, through the menu or the CLI; `setup` on a first install |
| `egressguard` CLI | Homebrew `bin` | the user (`setup`, `uninstall`, `leaktest`: sudo) |
| `EgressGuard.app` | Homebrew prefix, LaunchAgent `com.sentiens.egressguard-menu` | the user |

The daemon reads the user's files without following symlinks, only as regular
files and up to a size limit, and validates every entry. Anything missing,
stale or malformed in `control.json` means **on**. A bad `settings.json` keeps the
last good settings and is reported in the status, the menu and the window.

A first install leaves the switch off: `setup` writes `{"mode": "off",
"setup_pending": true}` unless the user turned it on in the terminal, and the
status reports `setup_pending`. The menu bar app then opens its setup window,
which asks whether to trust the current network and turns the switch on only
when the user says so. No network is trusted, and nothing is turned on, without
an answer. An update leaves `control.json` alone.

launchd never runs code from the Homebrew prefix: the user can write there.
`setup` copies the binary into a root-owned directory, dry-runs that copy, and the
job runs it as `egressguard daemon`. Under sudo, the CLI reads and writes the
user's files as that user (effective user, group and groups), so a path the user
controls can neither show them a root-only file nor lead a write anywhere only
root may write. System tools are run from the system directories, never through
the caller's PATH.

macOS hides the ARP table from command line tools that are not Apple's unless
they may use the local network. The daemon, a root launchd job, reads it to check
a router's MAC; `egressguard detect` and `trust-current`, run by the user, fall back
to the router MAC configd recorded for the network (`NetworkSignature`) to propose a
network. Should the daemon not see a MAC it needs, the status says so.

## Decision

```
                     packet on an interface of the Mac
                                  |
      +---------------------------+----------------------------+
      |                                                        |
 lo0, utunN, ipsecN (any VPN app),                 uplink: en0..en9 always, and any
 awdl0, llw0, bridgeN, anpiN,                      other interface once observed
 apN, nanN, vmenetN                                            |
      |                                  matches a trusted network? (router IP +
  untouched                              router MAC, verified by a fresh ARP probe;
                                         or the interface; or both)
                                           |                         |
                                          yes                        no
                                           |                         |
                          leaves only from the address it   only to/from tunnel endpoints,
                          had when verified (pin); every    DHCP, IPv6 ND, ping to LAN;
                          other source dropped              everything else dropped
```

- **Trusted network.** An entry with any of `interface`, `router`, `router_mac`.
  A router address alone is refused: 192.168.1.1 is everyone's router. macOS
  identifies networks the same way
  (`NetworkSignature: IPv4.Router=...;IPv4.RouterHardwareAddress=...`).
- **Pin.** A trusted uplink may send only from the IPv4 address it had when it
  was verified (plus `0.0.0.0` for DHCP), and over IPv6 only from link-local,
  `::` or its own prefixes. On another network the address differs, so the
  kernel drops the packets even if the daemon is slow or dead. `pin` is
  `address` (default), `subnet` (for bridged VMs) or `none`.
- **Endpoints.** Where a VPN client may connect from an untrusted network:
  - `ip[:port]/udp|tcp|esp`, IPv4 or IPv6, from the administrator's `tunnels`
    and the user's own endpoints;
  - the server address of every VPN configuration macOS has (`scutil --nc`).
    WireGuard-like clients are taken as UDP, IKEv2/IPsec as UDP 500/4500 plus
    ESP. This is a live view: deleting a configuration removes its endpoint;
  - opt-in: the connections a running tunnel provider (a Network Extension of a
    connected VPN, or a process named in `learn.processes`) makes over a trusted
    uplink while the internet route is a tunnel. Connect once at home and the
    server is learned. It is off by default because a provider also connects to
    things that are not its tunnel (control servers, DNS bootstrap), and each of
    those would stay open everywhere. Learned endpoints are kept in
    `learned.json` and forgotten after 180 days unseen.

  Replies from an endpoint are let in only to client ports (1024–65535), so a
  spoofed "VPN server" on a hostile network cannot reach SSH or file sharing.
  ICMP unreachable and too-big from endpoints pass, so path MTU discovery works.
- **Nothing configured.** No trusted networks and no endpoints: nothing passes.

## Rule placement

pf runs `com.apple/*` child anchors in name order, so `050` comes before Apple's
`200.AirDrop` and `250.ApplicationFirewall` and before third-party anchors such
as SelfControl's `org.eyebeam`.

- Its blocks are `quick`; its only passes are narrow `quick` exceptions on
  closed uplinks. No rule keeps state.
- A `pass quick` or `set skip` earlier in the main ruleset, or an existing pf
  state, would still get past it: pf matches states before rules. See *Dropping
  states* below.
- The main ruleset must evaluate `com.apple/*`. If it does not (someone ran
  `pfctl -F all`, or loaded another `pf.conf`), the daemon reloads
  `/etc/pf.conf`; if that does not bring the anchor back, the status says the
  rules are not in force.
- pf is enabled with a reference token (`pfctl -E`); the daemon keeps one and
  releases its old ones. Every token stays in `pf-tokens` until it is released,
  so the uninstaller can always give them back. pf being disabled is undone
  within a second.
- A problem a check finds (pf off, the anchor not attached) stands in the status,
  and is checked again every step, until a check finds none.

## Dropping states

The daemon remembers which addresses pf lets through directly (the open
uplinks' IPv4 addresses and IPv6 prefixes) and which it has seen at all. Whenever
a set of rules is in place that no longer leaves an address open, or closes an
address the daemon has not seen before (its states may come from anywhere), it
drops the pf states that started from that address (`pfctl -k`), after the rules
are loaded. This one mechanism covers
every transition: a trust break, a routine observation that finds another
network, a self-test, the seal before sleep, a new address on a trusted uplink,
the switch turning on after connections were made while it was off, and the
daemon's start (where everything it sees that is not open counts as closed). A
drop that fails stays queued, is retried every step, and keeps the status at
"not in force" until it succeeds.

## When trust is re-checked

Every trust break closes all uplinks first (dropping their states, above), then
re-observes. The closing rules are loaded before anything else is checked; if
loading them fails, the next step tries again before it looks at the network. An uplink is trusted again only
by an observation that began after the break, with a fresh ARP entry (`arp -d`
must succeed); the daemon retries every second for 15 seconds.

| Event | Source |
|---|---|
| daemon start | its first action, before anything is looked at |
| link change, lost IPv4 address, a default route removed or changed on a trusted uplink | `route -n monitor`, handled on the monitor goroutine at once |
| the network tools not answering for 15 s | the last observation is kept that long, then nothing is trusted; an uplink whose own probe does not answer is closed at once and needs a fresh check (a new ARP entry) before it is trusted again, while the others are still observed |
| settings or config change | re-read when it changes; a broken file keeps the old one and is reported |
| off → on | the control file |
| going to sleep | IOKit `WillSleep`: the network is **sealed** before the Mac sleeps |
| a sleep seen on the clocks | `CLOCK_MONOTONIC` minus `CLOCK_UPTIME_RAW`, in case the notice was missed |
| a full wake | IOKit `HasPoweredOn` (`WillPowerOn` comes before it is known whether a wake is full) |

A seal lasts until a full wake: the wake notice, or keyboard or mouse input
after the seal. Dark wakes (Power Nap, Wake on Demand) deliver neither; in one,
only the network that was trusted when the seal began can be trusted again,
after a fresh check, so remote access to a sleeping Mac at home keeps working.
As a last resort the seal is lifted after 10 minutes awake, reported as an
error until the next full wake.

## Failure

The daemon never flushes its rules on the way out: a crash or a restart stays
closed. If a step panics, the daemon logs the stack, flushes the rules only if
the switch is off (an off switch must never be stranded), and exits; launchd
starts it again within seconds, and the new daemon closes every uplink before
anything else. SIGTERM (the uninstaller) stops it from loading any more rules.

## Known gaps

- **Boot.** Between boot and the daemon's start pf has no rules.
- **Bridged VMs** bypass pf (`net.link.bridge.output_skip_filters`). Uplinks that
  are bridge members with an address are reported.
- **Interface flag changes** on a trusted uplink (promiscuous mode when tcpdump
  starts) count as a link change and cause a brief re-check.
- **Same address on another network**: the pin cannot tell it apart; safety rests
  on the daemon reacting to the link change, which comes before the new network
  is usable.
- **Apple processes and pf.** On macOS 15.0–15.3.1 some Apple processes were
  reported to get past pf. pf is not an API Apple supports for apps (TN3165);
  the supported route is a Network Extension, which needs a paid developer
  account. `leaktest --safari` checks the Mac it runs on.
- **iCloud Private Relay** is reportedly mostly disabled while pf rules are loaded.
- **Router MAC spoofing** by someone on the local network makes their network look
  trusted.
- **Learned endpoints** are whatever a VPN provider connected to; anything that
  can add a VPN configuration to macOS (which needs the user's approval) can add
  an endpoint.
