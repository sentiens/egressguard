package guard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Service is a VPN configuration macOS knows.
type Service struct {
	ID, Name, Kind string
	Connected      bool
}

var (
	serviceLine  = regexp.MustCompile(`^\*?\s*\(([^)]*)\)\s+([0-9A-Fa-f-]{36})\s+(.*)$`)
	quotedName   = regexp.MustCompile(`"([^"]*)"`)
	bracketKind  = regexp.MustCompile(`\[([^\]]+)\]\s*$`)
	remoteLine   = regexp.MustCompile(`(?m)^\s*RemoteAddress : (.+?)\s*$`)
	providerLine = regexp.MustCompile(`(?m)^\s*NEProviderBundleIdentifier : (\S+)`)
)

// VPNServices lists the VPN configurations macOS knows (scutil --nc list).
func VPNServices(run Runner) ([]Service, error) {
	result := run([]string{"scutil", "--nc", "list"}, "", 0)
	if result.Failed() {
		return nil, &Unanswered{Command: "scutil --nc list", Err: errors.New(result.Error())}
	}
	var found []Service
	for _, line := range strings.Split(result.Stdout, "\n") {
		match := serviceLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		rest := match[3]
		service := Service{ID: match[2], Name: match[2], Connected: strings.TrimSpace(match[1]) == "Connected"}
		if name := quotedName.FindStringSubmatch(rest); name != nil {
			service.Name = name[1]
		}
		if kind := bracketKind.FindStringSubmatch(rest); kind != nil {
			service.Kind = kind[1]
		} else if words := strings.Fields(rest); len(words) > 0 {
			service.Kind = words[0]
		}
		found = append(found, service)
	}
	return found, nil
}

// ServiceDetails is the server address and the provider bundle of a VPN configuration.
func ServiceDetails(id string, run Runner) (remote, provider string, err error) {
	result := run([]string{"scutil", "--nc", "show", id}, "", 0)
	if result.Failed() {
		return "", "", &Unanswered{Command: "scutil --nc show " + id, Err: errors.New(result.Error())}
	}
	if match := remoteLine.FindStringSubmatch(result.Stdout); match != nil {
		remote = match[1]
	}
	if match := providerLine.FindStringSubmatch(result.Stdout); match != nil {
		provider = match[1]
	}
	return remote, provider, nil
}

// udpProviders are VPN providers whose server address is a UDP endpoint (the WireGuard family).
var udpProviders = []string{"com.wireguard."}

var (
	bracketedRemote = regexp.MustCompile(`^\[([0-9A-Fa-f:.]+)\](?::(\d+))?$`)
	hostPortRemote  = regexp.MustCompile(`^([^:\[\]]+):(\d+)$`)
	hostName        = regexp.MustCompile(`^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
)

// ServiceEndpoints are the endpoint texts a VPN configuration needs, from its
// server address. resolve turns a host name into addresses; nil gives nothing.
func ServiceEndpoints(kind, remote, provider string, resolve func(string) []string) []string {
	if remote == "" || strings.Contains(remote, " ") {
		return nil
	}
	host, port := remote, ""
	if match := bracketedRemote.FindStringSubmatch(remote); match != nil {
		host, port = match[1], match[2]
	} else if match := hostPortRemote.FindStringSubmatch(remote); match != nil {
		host, port = match[1], match[2]
	}
	var addresses []string
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" {
		addresses = []string{address.String()}
	} else if hostName.MatchString(host) && resolve != nil {
		addresses = resolve(host)
	}
	ident := strings.ToLower(kind + " " + provider)
	var texts []string
	for _, address := range addresses {
		shown := address
		if strings.Contains(address, ":") {
			shown = "[" + address + "]"
		}
		switch {
		case strings.Contains(ident, "ikev2") || strings.Contains(ident, "ipsec"):
			texts = append(texts, shown+":500/udp", shown+":4500/udp", address+"/esp")
		case slices.ContainsFunc(udpProviders, func(p string) bool { return strings.Contains(ident, p) }):
			if port != "" {
				texts = append(texts, shown+":"+port+"/udp")
			}
		case port != "":
			texts = append(texts, shown+":"+port+"/udp", shown+":"+port+"/tcp")
		}
	}
	return texts
}

// ResolveHost is the sorted addresses of a host name, or nothing after a few seconds.
func ResolveHost(host string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	found, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	unique := map[string]bool{}
	for _, address := range found {
		if parsed, ok := netip.AddrFromSlice(address.IP); ok {
			unique[parsed.Unmap().String()] = true
		}
	}
	return sortedKeys(unique)
}
