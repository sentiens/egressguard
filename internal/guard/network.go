package guard

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// internalPrefixes name interfaces that never carry the Mac's own traffic to the
	// internet directly: loopback, tunnels, Apple peer-to-peer links, bridges and VM
	// switches whose egress still leaves through an uplink (and is filtered there).
	// ppp is an uplink: PPPoE would otherwise bypass the switch.
	internalPrefixes = []string{"lo", "utun", "ipsec", "awdl", "llw", "bridge", "anpi", "ap", "nan", "vmenet", "vmnet"}
	// alwaysClosed are uplinks closed even before they are seen (pf matches
	// interfaces by name); any other uplink is closed once observed.
	alwaysClosed = func() []string {
		var names []string
		for _, family := range []struct {
			prefix string
			count  int
		}{{"en", 32}, {"ppp", 4}} {
			for i := range family.count {
				names = append(names, fmt.Sprint(family.prefix, i))
			}
		}
		return names
	}()
	// localNets is where a router may be pinged while its uplink is closed (to learn its MAC).
	localNets = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("169.254.0.0/16")}
)

// IsInternal reports whether an interface is one the switch leaves alone.
func IsInternal(name string) bool {
	match := interfacePattern.FindStringSubmatch(name)
	return match != nil && slices.Contains(internalPrefixes, match[1])
}

// IPv4 is the canonical text of a dotted-quad address, or "".
func IPv4(text string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !address.Is4() {
		return ""
	}
	return address.String()
}

func isLocal(address string) bool {
	parsed, err := netip.ParseAddr(address)
	return err == nil && slices.ContainsFunc(localNets, func(net netip.Prefix) bool { return net.Contains(parsed) })
}

// Interface is one interface as ifconfig lists it.
type Interface struct {
	MAC     string   // its own hardware address
	V4, V6  []string // "address/prefixlen"
	Members []string // bridge members
}

var interfaceHeader = regexp.MustCompile(`^([^\s:]+): flags=`)

// Interfaces parses `ifconfig` output.
func Interfaces(text string) map[string]*Interface {
	found := map[string]*Interface{}
	var current *Interface
	for _, line := range strings.Split(text, "\n") {
		if match := interfaceHeader.FindStringSubmatch(line); match != nil {
			current = &Interface{V4: []string{}, V6: []string{}, Members: []string{}}
			found[match[1]] = current
			continue
		}
		words := strings.Fields(line)
		if current == nil || len(words) < 2 {
			continue
		}
		switch words[0] {
		case "ether":
			current.MAC = NormalizeMAC(words[1])
		case "member:":
			current.Members = append(current.Members, words[1])
		case "inet":
			if IPv4(words[1]) == "" {
				continue
			}
			bits := 32
			if mask, ok := option(words, "netmask"); ok {
				if value, err := strconv.ParseUint(strings.TrimPrefix(mask, "0x"), 16, 32); err == nil {
					bits = popcount(value)
				}
			}
			current.V4 = append(current.V4, fmt.Sprintf("%s/%d", words[1], bits))
		case "inet6":
			address, err := netip.ParseAddr(strings.SplitN(words[1], "%", 2)[0])
			if err != nil || !address.Is6() || address.Is4In6() {
				continue
			}
			bits := 128
			if length, ok := option(words, "prefixlen"); ok {
				if bits, err = strconv.Atoi(length); err != nil || bits < 0 || bits > 128 {
					continue // not an address ifconfig would print: skip it rather than guess
				}
			}
			current.V6 = append(current.V6, netip.PrefixFrom(address, bits).String())
		}
	}
	return found
}

// option is the word after name in an ifconfig line.
func option(words []string, name string) (string, bool) {
	for i, word := range words[:len(words)-1] {
		if word == name {
			return words[i+1], true
		}
	}
	return "", false
}

func popcount(value uint64) int {
	count := 0
	for ; value != 0; value &= value - 1 {
		count++
	}
	return count
}

var arpLine = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+) on (\S+)`)

// ARP is the MAC address of ip in the ARP cache of iface, or "" if there is none.
func ARP(ip, iface string, run Runner) (string, error) {
	result, err := answer(run, "arp", "-n", ip)
	if err != nil {
		return "", err
	}
	for _, match := range arpLine.FindAllStringSubmatch(result.Stdout, -1) {
		if match[1] == ip && match[3] == iface {
			return NormalizeMAC(match[2]), nil
		}
	}
	if result.Code != 0 && !strings.Contains(result.Stdout+result.Stderr, "no entry") {
		return "", fmt.Errorf("arp -n %s: %s", ip, result.Error())
	}
	return "", nil
}

// Link is one uplink as observed. Empty strings are unknown or absent.
type Link struct {
	Router  string
	MAC     string // the router's MAC address
	Trusted bool
	Network string // the trusted network it matches
	Pin     string
	V4, V6  []string
	Bridged string // the bridge it is a member of
	Silent  bool   // its probe got no answer: nothing about it was checked
}

// untrusted is the link with no trust.
func (l Link) untrusted() Link {
	l.Trusted, l.Network, l.Pin = false, "", ""
	return l
}

// Distrust is the same uplinks with none of them trusted.
func Distrust(uplinks map[string]Link) map[string]Link {
	result := make(map[string]Link, len(uplinks))
	for name, link := range uplinks {
		result[name] = link.untrusted()
	}
	return result
}

// TrustedBy is the first trusted network this uplink matches, or nil.
func TrustedBy(networks []Network, name, router, mac string) *Network {
	for i, network := range networks {
		if network.Interface != "" && network.Interface != name {
			continue
		}
		if network.RouterMAC != "" && (router == "" || (network.Router != "" && network.Router != router) ||
			network.RouterMAC != mac) {
			continue
		}
		return &networks[i]
	}
	return nil
}

// Observe looks at every uplink now: addresses, router, the router's MAC, and the
// trusted network it matches. The MAC is looked up even when no trusted network
// needs it (macs), so the menu bar app can offer to trust the current network.
// refresh deletes the cached ARP entry first: a cached entry may still name the
// previous network's router. Uplinks are probed in parallel, so one silent
// router does not delay the others.
//
// The uplinks are nil only if ifconfig did not answer. An uplink whose own probe
// got no answer is returned untrusted, and the error names it.
func Observe(config Config, refresh bool, run Runner, macs bool) (map[string]Link, error) {
	result, err := answer(run, "ifconfig")
	if err != nil {
		return nil, err
	}
	found := Interfaces(result.Stdout)
	if len(found) == 0 {
		return nil, &Unanswered{Command: "ifconfig (no interfaces listed)"}
	}
	wantMAC := macs || slices.ContainsFunc(config.TrustedNetworks, func(n Network) bool { return n.RouterMAC != "" })
	bridged := map[string]string{}
	var names []string
	for name, info := range found {
		for _, member := range info.Members {
			bridged[member] = name
		}
		if !IsInternal(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	links := make([]Link, len(names))
	failures := make([]error, len(names))
	var wait sync.WaitGroup
	slots := make(chan struct{}, 8)
	for i, name := range names {
		wait.Add(1)
		go func() {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			links[i], failures[i] = probe(config, name, found[name], bridged[name], refresh, wantMAC, run)
		}()
	}
	wait.Wait()
	uplinks := make(map[string]Link, len(names))
	var unanswered []error
	for i, name := range names {
		if failures[i] != nil {
			unanswered = append(unanswered, fmt.Errorf("%s: %w", name, failures[i]))
			links[i] = Link{V4: found[name].V4, V6: found[name].V6, Bridged: bridged[name], Silent: true}
		}
		uplinks[name] = links[i]
	}
	return uplinks, errors.Join(unanswered...)
}

// probe observes one uplink.
func probe(config Config, name string, addresses *Interface, bridge string, refresh, wantMAC bool, run Runner) (Link, error) {
	link := Link{V4: addresses.V4, V6: addresses.V6, Bridged: bridge}
	if len(addresses.V4) > 0 {
		result, err := answer(run, "ipconfig", "getoption", name, "router")
		if err != nil {
			return Link{}, err
		}
		link.Router = IPv4(result.Stdout)
	}
	if link.Router != "" && wantMAC {
		if refresh {
			// If the cached entry cannot be deleted, nothing read afterwards proves anything.
			deleted := run([]string{"arp", "-d", link.Router, "ifscope", name}, "", 0)
			if deleted.Err != nil || (deleted.Code != 0 && !strings.Contains(deleted.Stdout+deleted.Stderr, "cannot locate")) {
				return link, nil
			}
		}
		for attempt := range 4 {
			if attempt > 0 { // nothing cached: a ping makes the router answer ARP
				// The ping itself may well go unanswered; only a ping that cannot run is a failure.
				ping := run([]string{"ping", "-c", "1", "-t", "1", "-b", name, link.Router}, "", 3*time.Second)
				if ping.Err != nil {
					return Link{}, &Unanswered{Command: "ping " + link.Router, Err: ping.Err}
				}
			}
			mac, err := ARP(link.Router, name, run)
			if err != nil {
				return Link{}, err
			}
			if link.MAC = mac; mac != "" {
				break
			}
		}
	}
	if network := TrustedBy(config.TrustedNetworks, name, link.Router, link.MAC); network != nil {
		link.Trusted, link.Network, link.Pin = true, network.Name, network.Pin
	}
	return link, nil
}

// Pins are the source addresses a trusted uplink may send from: IPv4 entries and IPv6 entries.
func Pins(link Link) (v4, v6 []string) {
	v4Set := map[string]bool{"0.0.0.0": true}
	v6Set := map[string]bool{"::": true, "fe80::/10": true}
	for _, item := range link.V4 {
		if prefix, err := netip.ParsePrefix(item); err == nil {
			if link.Pin == "subnet" {
				v4Set[prefix.Masked().String()] = true
			} else {
				v4Set[prefix.Addr().String()] = true
			}
		}
	}
	for _, item := range link.V6 {
		if prefix, err := netip.ParsePrefix(item); err == nil && !prefix.Addr().IsLinkLocalUnicast() {
			v6Set[prefix.Masked().String()] = true
		}
	}
	return sortedKeys(v4Set), sortedKeys(v6Set)
}

// StateSources are where pf states of an uplink's own traffic start: its IPv4
// addresses and IPv6 prefixes.
func StateSources(link Link) []string {
	var sources []string
	for _, item := range link.V4 {
		if prefix, err := netip.ParsePrefix(item); err == nil {
			sources = append(sources, prefix.Addr().String())
		}
	}
	for _, item := range link.V6 {
		if prefix, err := netip.ParsePrefix(item); err == nil && !prefix.Addr().IsLinkLocalUnicast() {
			sources = append(sources, prefix.Masked().String())
		}
	}
	return sources
}

// TunnelState is the tunnel interface that carries traffic to the internet, and the
// VPN services connected now.
type TunnelState struct {
	Interface string   `json:"interface"`
	Services  []string `json:"services"`
}

var routeInterface = regexp.MustCompile(`interface: (\S+)`)

// TunnelStatus is the tunnel the internet route goes through now, or nil. No route
// at all (offline) is no tunnel. If the connected VPN services cannot be listed,
// the tunnel comes without their names, with the error.
func TunnelStatus(run Runner) (*TunnelState, error) {
	route, err := answer(run, "route", "-n", "get", "1.1.1.1")
	if err != nil {
		return nil, err
	}
	match := routeInterface.FindStringSubmatch(route.Stdout)
	if match == nil || !IsInternal(match[1]) || strings.HasPrefix(match[1], "lo") {
		return nil, nil
	}
	tunnel := &TunnelState{Interface: match[1], Services: []string{}}
	services, err := VPNServices(run)
	if err != nil {
		return tunnel, fmt.Errorf("the VPN services of %s: %w", tunnel.Interface, err)
	}
	for _, service := range services {
		if service.Connected {
			tunnel.Services = append(tunnel.Services, service.Name)
		}
	}
	return tunnel, nil
}

var (
	serviceKey    = regexp.MustCompile(`subKey \[\d+\] = (State:/Network/Service/[^/\s]+/IPv4)`)
	interfaceName = regexp.MustCompile(`(?m)^\s*InterfaceName : (\S+)`)
	signatureLine = regexp.MustCompile(`(?m)^\s*NetworkSignature : IPv4\.Router=([0-9.]+);IPv4\.RouterHardwareAddress=([0-9A-Fa-f:]+)`)
)

// RouterSignatures are the router and its MAC address per interface as configd
// identifies networks (NetworkSignature). macOS hides the ARP table from command
// line tools that are not Apple's unless they may use the local network; configd
// still knows the router. Only for proposing a network to trust: the daemon checks
// the MAC itself.
func RouterSignatures(run Runner) (map[string]RouterSignature, error) {
	scutil := func(command string) (string, error) {
		result := run([]string{"scutil"}, command+"\n", 0)
		if result.Failed() {
			return "", &Unanswered{Command: "scutil " + command, Err: errors.New(result.Error())}
		}
		return result.Stdout, nil
	}
	list, err := scutil("list State:/Network/Service/[^/]+/IPv4")
	if err != nil {
		return nil, err
	}
	found := map[string]RouterSignature{}
	for _, key := range serviceKey.FindAllStringSubmatch(list, -1) {
		out, err := scutil("show " + key[1])
		if err != nil {
			return nil, err
		}
		name, signature := interfaceName.FindStringSubmatch(out), signatureLine.FindStringSubmatch(out)
		if name != nil && signature != nil && IPv4(signature[1]) != "" {
			found[name[1]] = RouterSignature{Router: IPv4(signature[1]), MAC: NormalizeMAC(signature[2])}
		}
	}
	return found, nil
}

// RouterSignature is a network as configd recorded it.
type RouterSignature struct{ Router, MAC string }

// naturalCompare orders interface names with numbers by value: en2 before en10.
func naturalCompare(a, b string) int {
	pa, na := splitNumber(a)
	pb, nb := splitNumber(b)
	return cmp.Or(strings.Compare(pa, pb), cmp.Compare(na, nb), strings.Compare(a, b))
}

var trailingNumber = regexp.MustCompile(`^(\D+)(\d+)$`)

func splitNumber(name string) (string, int) {
	if match := trailingNumber.FindStringSubmatch(name); match != nil {
		if number, err := strconv.Atoi(match[2]); err == nil {
			return match[1], number
		}
	}
	return name, -1 // no number, or too long for one: ordered by name alone
}

func sortedKeys[V any](set map[string]V) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
