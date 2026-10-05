package guard

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// localMacro is the pf list of localNets.
var localMacro = func() string {
	nets := make([]string, len(localNets))
	for i, net := range localNets {
		nets[i] = net.String()
	}
	return "{ " + strings.Join(nets, " ") + " }"
}()

// Render is the pf anchor for an enabled switch. Uplinks trusted in uplinks stay
// open (pinned to their addresses) if trust is set; every other uplink is closed
// except to the endpoints.
func Render(uplinks map[string]Link, endpoints []Endpoint, trust bool) string {
	open := map[string]bool{}
	for name, link := range uplinks {
		open[name] = link.Trusted && trust
	}
	closed := map[string]bool{}
	for _, name := range alwaysClosed {
		closed[name] = !open[name]
	}
	for name := range uplinks {
		closed[name] = !open[name]
	}

	var r ruleset
	r.macros = []string{"# egressguard: trusted networks, tunnels, or nothing",
		fmt.Sprintf(`closed = "{ %s }"`, strings.Join(namesWhere(closed), " ")),
		fmt.Sprintf(`local = "%s"`, localMacro)}
	r.pins(uplinks, namesWhere(open))
	r.endpoints(endpoints)
	r.add("pass out quick on $closed inet proto udp from any port 68 to any port 67 no state")
	r.add("pass in quick on $closed inet proto udp from any port 67 to any port 68 no state")
	r.add("pass out quick on $closed inet proto icmp to $local icmp-type echoreq no state")
	r.add("pass in quick on $closed inet proto icmp from $local icmp-type echorep no state")
	for _, name := range sortedKeys(uplinks) {
		// A router outside the local ranges is pinged on its own uplink, to learn its MAC.
		if router := uplinks[name].Router; router != "" && closed[name] && !isLocal(router) {
			r.add("pass out quick on %s inet proto icmp to %s icmp-type echoreq no state", name, router)
			r.add("pass in quick on %s inet proto icmp from %s icmp-type echorep no state", name, router)
		}
	}
	nd := "icmp6-type { 133 134 135 136 137 143 }"
	r.add("pass quick on $closed inet6 proto icmp6 from fe80::/10 to any %s no state", nd)
	r.add("pass quick on $closed inet6 proto icmp6 from any to { fe80::/10 ff02::/16 } %s no state", nd)
	r.add("block drop quick on $closed all")
	return r.String()
}

// ruleset collects pf lines in the order pf wants them: macros, tables, rules.
type ruleset struct{ macros, tables, rules []string }

func (r *ruleset) add(format string, args ...any) {
	r.rules = append(r.rules, fmt.Sprintf(format, args...))
}

func (r *ruleset) String() string {
	return strings.Join(slices.Concat(r.macros, r.tables, r.rules), "\n") + "\n"
}

// pins keeps each open uplink to the addresses it was verified with.
func (r *ruleset) pins(uplinks map[string]Link, open []string) {
	for _, name := range open {
		link := uplinks[name]
		if link.Pin == "none" {
			continue
		}
		v4, v6 := Pins(link)
		r.tables = append(r.tables,
			fmt.Sprintf("table <ks_%s_v4> const { %s }", name, strings.Join(v4, ", ")),
			fmt.Sprintf("table <ks_%s_v6> const { %s }", name, strings.Join(v6, ", ")))
		r.add("block drop out quick on %s inet from ! <ks_%s_v4>", name, name)
		r.add("block drop out quick on %s inet6 from ! <ks_%s_v6>", name, name)
	}
}

// endpoints lets closed uplinks reach the tunnel endpoints, and their replies back.
func (r *ruleset) endpoints(endpoints []Endpoint) {
	seen := map[string]bool{}
	type host struct{ address, family string }
	var hosts []host
	for _, e := range endpoints {
		if !slices.Contains(hosts, host{e.Address, e.Family}) {
			hosts = append(hosts, host{e.Address, e.Family})
		}
		if seen[e.String()] {
			continue
		}
		seen[e.String()] = true
		port := ""
		if e.Port != 0 {
			port = fmt.Sprintf(" port %d", e.Port)
		}
		// Replies only reach client ports: a spoofed "endpoint" cannot reach SSH or
		// file sharing. IKE answers to its own ports.
		clientPorts := ""
		if (e.Proto == "tcp" || e.Proto == "udp") && e.Port != 500 && e.Port != 4500 {
			clientPorts = " to any port 1024:65535"
		}
		r.add("pass out quick on $closed %s proto %s to %s%s no state", e.Family, e.Proto, e.Address, port)
		r.add("pass in quick on $closed %s proto %s from %s%s%s no state", e.Family, e.Proto, e.Address, port, clientPorts)
	}
	slices.SortFunc(hosts, func(a, b host) int {
		return cmp.Or(strings.Compare(a.address, b.address), strings.Compare(a.family, b.family))
	})
	for _, h := range hosts {
		// "Too big" and "unreachable" from a server keep the tunnel's path MTU working.
		if h.family == "inet" {
			r.add("pass in quick on $closed inet proto icmp from %s icmp-type unreach no state", h.address)
		} else {
			r.add("pass in quick on $closed inet6 proto icmp6 from %s icmp6-type toobig no state", h.address)
		}
	}
}

// namesWhere are the names set in a map, in natural order (en2 before en10).
func namesWhere(set map[string]bool) []string {
	var names []string
	for name, ok := range set {
		if ok {
			names = append(names, name)
		}
	}
	slices.SortFunc(names, naturalCompare)
	return names
}
