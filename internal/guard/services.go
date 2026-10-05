package guard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

// Connection is one row of `lsof -F pcPnT` with a remote end.
type Connection struct {
	PID           int
	Command       string
	Proto         string // TCP or UDP
	Local, Remote string // host:port
	State         string // TCP state
}

// LsofConnections parses `lsof -F pcPnT` output.
func LsofConnections(text string) []Connection {
	var rows []Connection
	var current Connection
	var name string
	flush := func() {
		if local, remote, found := strings.Cut(name, "->"); found {
			current.Local, current.Remote = local, remote
			rows = append(rows, current)
		}
		name = ""
		current = Connection{PID: current.PID, Command: current.Command}
	}
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		tag, value := line[0], line[1:]
		switch tag {
		case 'p':
			flush()
			current.PID, _ = strconv.Atoi(value)
			current.Command = ""
		case 'f':
			flush()
		case 'c':
			current.Command = value
		case 'P':
			current.Proto = value
		case 'n':
			name = value
		case 'T':
			if state, found := strings.CutPrefix(value, "ST="); found {
				current.State = state
			}
		}
	}
	flush()
	return rows
}

var (
	bracketedHostPort = regexp.MustCompile(`^\[([^\]]+)\]:(\d+)$`)
	plainHostPort     = regexp.MustCompile(`^([^:]+):(\d+)$`)
)

// SplitHostPort reads "1.2.3.4:5" or "[::1]:5" (a zone is dropped).
func SplitHostPort(text string) (host string, port int, ok bool) {
	match := bracketedHostPort.FindStringSubmatch(text)
	if match == nil {
		match = plainHostPort.FindStringSubmatch(text)
	}
	if match == nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(match[2])
	host, _, _ = strings.Cut(match[1], "%")
	return host, port, err == nil
}

// BundleID is the CFBundleIdentifier of the app extension or system extension a
// process runs from, or "".
func BundleID(path string) string {
	for _, marker := range []string{".appex/", ".systemextension/"} {
		if i := strings.Index(path, marker); i >= 0 {
			info := filepath.Join(path[:i+len(marker)], "Contents", "Info.plist")
			result := Run([]string{"plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", info}, "", 0)
			if result.Failed() {
				return ""
			}
			return strings.TrimSpace(result.Stdout)
		}
	}
	return ""
}

// notGlobal are special-purpose ranges (RFC 6890 and the IANA registries), like
// Python's is_global, multicast included.
var notGlobal = func() []netip.Prefix {
	var nets []netip.Prefix
	for _, text := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "::ffff:0:0/96",
		"64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"} {
		nets = append(nets, netip.MustParsePrefix(text))
	}
	return nets
}()

func isGlobal(address netip.Addr) bool {
	return !slices.ContainsFunc(notGlobal, func(net netip.Prefix) bool { return net.Contains(address) })
}
