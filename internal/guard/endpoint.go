package guard

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Endpoint is where a tunnel may connect to from an untrusted network.
type Endpoint struct {
	Address string // canonical IP address
	Family  string // "inet" or "inet6", as pf names them
	Port    int    // 0 means any port
	Proto   string // "udp", "tcp" or "esp"
}

// String is the endpoint in the form ParseEndpoint reads.
func (e Endpoint) String() string {
	if e.Port == 0 {
		return e.Address + "/" + e.Proto
	}
	host := e.Address
	if e.Family == "inet6" {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d/%s", host, e.Port, e.Proto)
}

// ParseEndpoint reads "1.2.3.4:51820/udp", "1.2.3.4/tcp" (any port),
// "[2001:db8::1]:443/tcp", "2001:db8::1/udp" or "1.2.3.4/esp". value comes from
// JSON, so anything but a string is refused; where names it in errors.
func ParseEndpoint(value any, where string) (Endpoint, error) {
	text, ok := value.(string)
	if !ok {
		return Endpoint{}, configErrorf("%s: endpoints are strings", where)
	}
	spec, proto, found := cutLast(text, "/")
	if !found || (proto != "udp" && proto != "tcp" && proto != "esp") {
		return Endpoint{}, configErrorf("%s: %q must end with /udp, /tcp or /esp", where, text)
	}
	host, port, hasPort := spec, "", false
	switch {
	case strings.HasPrefix(spec, "["):
		closing := strings.Index(spec, "]")
		if closing < 0 {
			return Endpoint{}, configErrorf("%s: %q is not [address]:port/proto", where, text)
		}
		rest := spec[closing+1:]
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return Endpoint{}, configErrorf("%s: %q is not [address]:port/proto", where, text)
		}
		host, port, hasPort = spec[1:closing], strings.TrimPrefix(rest, ":"), rest != ""
	case strings.Count(spec, ":") == 1:
		host, port, _ = strings.Cut(spec, ":")
		hasPort = true
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return Endpoint{}, configErrorf("%s: %q is not an IP address (a host name cannot be resolved "+
			"while the network is closed)", where, host)
	}
	if address.IsUnspecified() || address.IsMulticast() {
		return Endpoint{}, configErrorf("%s: %q is not a unicast address", where, text)
	}
	endpoint := Endpoint{Address: address.String(), Family: family(address), Proto: proto}
	if hasPort {
		number, err := strconv.Atoi(port)
		if proto == "esp" || err != nil || !isDigits(port) || number < 1 || number > 65535 {
			return Endpoint{}, configErrorf("%s: %q has a bad port", where, text)
		}
		endpoint.Port = number
	}
	return endpoint, nil
}

// MustEndpoint parses an endpoint known to be valid.
func MustEndpoint(text string) Endpoint {
	endpoint, err := ParseEndpoint(text, "endpoint")
	if err != nil {
		panic(err)
	}
	return endpoint
}

func validEndpoint(text string) bool {
	_, err := ParseEndpoint(text, "endpoint")
	return err == nil
}

func family(address netip.Addr) string {
	if address.Is4() {
		return "inet"
	}
	return "inet6"
}

func cutLast(text, separator string) (before, after string, found bool) {
	if i := strings.LastIndex(text, separator); i >= 0 {
		return text[:i], text[i+len(separator):], true
	}
	return text, "", false
}

func isDigits(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
