// Package guard is the EgressGuard daemon: a system-wide kill switch for macOS.
// The Mac reaches the internet through trusted networks, through a VPN tunnel,
// or not at all.
//
// The daemon runs as root (LaunchDaemon com.sentiens.egressguard) and owns one
// pf anchor, com.apple/050.EgressGuard. The stock /etc/pf.conf evaluates every
// com.apple/* anchor in name order, so this one runs before Apple's own
// (200.AirDrop, 250.ApplicationFirewall) and before later anchors such as
// SelfControl's org.eyebeam.
//
// Policy while the switch is on:
//
//   - An uplink is trusted when it matches a configured trusted network: its
//     interface, its DHCP router and the router's MAC address (each optional,
//     but a router address alone never proves anything). A trusted uplink is
//     left alone, except that it may only send from the addresses it had when
//     it was verified (the pin): on any other network the kernel drops its
//     packets even before the daemon reacts.
//   - Every other uplink is closed. Only traffic to and from tunnel endpoints,
//     DHCP, IPv6 neighbour discovery and a ping to the local network (to learn
//     the router's MAC) pass; everything else, IPv4 and IPv6, is dropped.
//   - Tunnel interfaces (utun, ipsec), loopback, Apple peer-to-peer links and
//     bridges are never touched, so any VPN client whose endpoint is known keeps
//     working on any network, and nothing works when the tunnel is down.
//
// Endpoints come from the configuration and are also learned: from the server
// address of every VPN configuration macOS has (scutil --nc) and, on a trusted
// network, from the connections a running tunnel provider makes over the
// uplink. With no trusted networks and no endpoints, nothing passes.
//
// pf has no match rules here, so allowed traffic is never passed with a
// non-quick rule (that would override earlier non-quick blocks). The narrow
// exceptions are quick passes on closed uplinks only, the blocks are quick, and
// no rule keeps state. pf matches states before rules, so whenever an uplink
// stops being open the daemon drops the states that started from its
// addresses, after the closing rules are in place.
//
// Trust is granted only by an observation that began after the last event that
// could have changed the network: the daemon's start, a link change, a lost
// IPv4 address or default route on a trusted uplink, a settings change, the
// switch turning on, a sleep and a wake. Each of these closes every
// uplink at once; the uplinks are then checked again with a fresh ARP entry,
// every second for 15 seconds. Before the system sleeps the network is sealed
// (IOKit power notification), and it stays sealed until a full wake: the wake
// notification, or keyboard or mouse input after the seal. A sleep is also
// recognised on the clocks, should the notification be missed. pf being
// enabled is checked every second.
//
// The daemon never flushes its rules on exit, so a crash or restart stays
// closed; only the uninstaller removes them. The user steers it through a
// control file in their home (the egressguard CLI, the menu bar app):
// {"mode": "on"}, {"mode": "off"[, "until": epoch]} or {"mode": "lock",
// "until": epoch} (no network counts as trusted, for a self-test, at most ten
// minutes). A missing or malformed file means on; a timed off expires.
package guard
