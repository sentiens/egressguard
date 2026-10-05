package guard

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

const ncList = `Available network connection services in the current set (*=enabled):
* (Disconnected)   F866AE22-4EC1-4524-8769-86A290A0C582 VPN (com.wireguard.macos) "office-wg"           [VPN:com.wireguard.macos]
* (Connected)      9B33EDB3-7576-4A9C-AB78-BC8C08E05BE4 VPN (com.wireguard.macos) "home-wg"       [VPN:com.wireguard.macos]
* (Disconnected)   4E4CABCA-9235-47FD-BB9D-77AFD8737CCA VPN (io.tailscale.ipn.macsys) "Tailscale"  [VPN:io.tailscale.ipn.macsys]
  (Disconnected)   11111111-2222-3333-4444-555555555555 IPSec "Office"                              [IPSec]
* (Connected)      66666666-7777-8888-9999-AAAAAAAAAAAA VPN (com.example.vpn) "ExampleVPN"                  [VPN:com.example.vpn]
`

// vpnServer is what scutil --nc show says about a configuration.
type vpnServer struct{ remote, provider string }

func ncShow() map[string]vpnServer {
	return map[string]vpnServer{
		"F866AE22-4EC1-4524-8769-86A290A0C582": {"198.51.100.185:51820", "com.wireguard.macos.network-extension"},
		"9B33EDB3-7576-4A9C-AB78-BC8C08E05BE4": {"198.51.100.61:51820", "com.wireguard.macos.network-extension"},
		"4E4CABCA-9235-47FD-BB9D-77AFD8737CCA": {"Tailscale Mesh", "io.tailscale.ipn.macsys.network-extension"},
		"11111111-2222-3333-4444-555555555555": {"vpn.example.org", ""},
		"66666666-7777-8888-9999-AAAAAAAAAAAA": {"ExampleVPN", "com.example.vpn.tunnel"},
	}
}

// scutilRunner answers scutil --nc from show, and anything else from extra.
func scutilRunner(t *testing.T, show map[string]vpnServer, extra func([]string) Result) Runner {
	return func(args []string, input string, timeout time.Duration) Result {
		switch {
		case len(args) >= 3 && args[0] == "scutil" && args[2] == "list":
			return done(ncList, 0)
		case len(args) >= 4 && args[0] == "scutil" && args[2] == "show":
			server := show[args[3]]
			text := fmt.Sprintf("* (x) %s\nVPN <dictionary> {\n", args[3])
			if server.provider != "" {
				text += "  NEProviderBundleIdentifier : " + server.provider + "\n"
			}
			return done(text+"  RemoteAddress : "+server.remote+"\n}\n", 0)
		case extra != nil:
			return extra(args)
		}
		t.Fatalf("unexpected command %v", args)
		return Result{}
	}
}

func TestServicesList(t *testing.T) {
	found, err := VPNServices(scutilRunner(t, ncShow(), nil))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var connected []bool
	for _, service := range found {
		got = append(got, service.Name)
		connected = append(connected, service.Connected)
	}
	if !reflect.DeepEqual(got, []string{"office-wg", "home-wg", "Tailscale", "Office", "ExampleVPN"}) ||
		!reflect.DeepEqual(connected, []bool{false, true, false, false, true}) || found[3].Kind != "IPSec" {
		t.Fatalf("%+v", found)
	}
}

func TestServiceEndpointsByKind(t *testing.T) {
	resolve := func(string) []string { return []string{"198.51.100.7"} }
	for _, c := range []struct {
		kind, remote, provider string
		resolve                func(string) []string
		want                   []string
	}{
		{"VPN:com.wireguard.macos", "198.51.100.61:51820", "com.wireguard.macos.network-extension", nil, []string{"198.51.100.61:51820/udp"}},
		{"VPN:com.wireguard.macos", "[2001:db8::1]:51820", "com.wireguard.macos.ne", nil, []string{"[2001:db8::1]:51820/udp"}},
		{"VPN:io.tailscale.ipn.macsys", "Tailscale Mesh", "x", nil, nil},
		{"VPN:com.example.vpn", "ExampleVPN", "com.example.vpn.tunnel", nil, nil},
		{"IPSec", "198.51.100.5", "", nil, []string{"198.51.100.5:500/udp", "198.51.100.5:4500/udp", "198.51.100.5/esp"}},
		{"VPN:com.example", "203.0.113.9:8443", "com.example.ne", nil, []string{"203.0.113.9:8443/udp", "203.0.113.9:8443/tcp"}},
		{"VPN:com.example", "203.0.113.9", "com.example.ne", nil, nil},
		{"IPSec", "vpn.example.org", "", nil, nil},
		{"IPSec", "vpn.example.org", "", resolve, []string{"198.51.100.7:500/udp", "198.51.100.7:4500/udp", "198.51.100.7/esp"}},
	} {
		if got := ServiceEndpoints(c.kind, c.remote, c.provider, c.resolve); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s: %v", c.kind, c.remote, got)
		}
	}
}

func TestLsofParse(t *testing.T) {
	text := "p1001\ncrapportd\nf11\nPTCP\nn*:54882\nTST=LISTEN\nf19\nPTCP\nn[fe80:e::1]:54882->[fe80:e::2]:49966\nTST=ESTABLISHED\n" +
		"p2002\ncPacketTunnel\nf5\nPUDP\nn192.168.1.108:61000->198.51.100.61:51820\nf6\nPTCP\nn192.168.1.108:50000->203.0.113.20:443\nTST=ESTABLISHED\n"
	want := []Connection{
		{1001, "rapportd", "TCP", "[fe80:e::1]:54882", "[fe80:e::2]:49966", "ESTABLISHED"},
		{2002, "PacketTunnel", "UDP", "192.168.1.108:61000", "198.51.100.61:51820", ""},
		{2002, "PacketTunnel", "TCP", "192.168.1.108:50000", "203.0.113.20:443", "ESTABLISHED"},
	}
	if got := LsofConnections(text); !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}

func TestIsGlobal(t *testing.T) {
	for address, want := range map[string]bool{"45.67.89.20": true, "2a01:4f8::30": true, "8.8.8.8": true,
		"192.168.1.1": false, "10.8.0.3": false, "100.64.0.1": false, "fd00::1": false, "fe80::1": false,
		"198.51.100.61": false, "224.0.0.251": false} {
		if got := isGlobal(netip.MustParseAddr(address)); got != want {
			t.Errorf("%s: %v", address, got)
		}
	}
}

// learning is a learner over fake scutil, ps and lsof, with its own clock.
type learning struct {
	t        *testing.T
	dir      string
	now      float64
	show     map[string]vpnServer
	lsofPIDs string
}

func newLearning(t *testing.T) *learning {
	return &learning{t: t, dir: t.TempDir(), now: 2_000_000_000, show: ncShow()}
}

func (l *learning) learner(extra func([]string) Result, bundle func(string) string) *Learner {
	if bundle == nil {
		bundle = func(string) string { return "" }
	}
	return NewLearner(filepath.Join(l.dir, "learned.json"), scutilRunner(l.t, l.show, extra),
		func(string) []string { return []string{"198.51.100.7"} }, bundle)
}

func texts(items []Sourced) []string {
	var result []string
	for _, item := range items {
		result = append(result, item.Endpoint.String())
	}
	slices.Sort(result)
	return result
}

func sources(items []Sourced) map[string]string {
	result := map[string]string{}
	for _, item := range items {
		result[item.Endpoint.String()] = item.Source
	}
	return result
}

func TestServicesAreALiveView(t *testing.T) {
	l := newLearning(t)
	learner := l.learner(nil, nil)
	learner.ScanServices(false)
	if got := texts(learner.Endpoints(l.now)); !reflect.DeepEqual(got, []string{"198.51.100.185:51820/udp", "198.51.100.61:51820/udp"}) {
		t.Fatal(got)
	}
	learner.ScanServices(true)
	found := sources(learner.Endpoints(l.now))
	if found["198.51.100.7/esp"] != "vpn: Office" || found["198.51.100.61:51820/udp"] != "vpn: home-wg" {
		t.Fatal(found)
	}
	// A restart remembers the host name's last answer, not the configurations.
	again := l.learner(nil, nil)
	if len(again.Endpoints(l.now)) != 0 {
		t.Fatal("configurations remembered")
	}
	again.ScanServices(false)
	if !slices.Contains(texts(again.Endpoints(l.now)), "198.51.100.7/esp") {
		t.Fatal("the resolved address is forgotten")
	}
	// A deleted configuration takes its endpoint with it.
	l.show["F866AE22-4EC1-4524-8769-86A290A0C582"] = vpnServer{"Deleted Mesh", ""}
	again.ScanServices(false)
	if slices.Contains(texts(again.Endpoints(l.now)), "198.51.100.185:51820/udp") {
		t.Fatal("a deleted configuration is still allowed")
	}
}

func TestScanFailureKeepsTheServices(t *testing.T) {
	l := newLearning(t)
	learner := l.learner(nil, nil)
	learner.ScanServices(false)
	learner.run = func([]string, string, time.Duration) Result { return Result{Code: -1, Err: errTimeout} }
	if err := learner.ScanServices(false); err == nil {
		t.Fatal("no error")
	}
	if got := texts(learner.Endpoints(l.now)); len(got) != 2 {
		t.Fatal("endpoints lost when scutil did not answer:", got)
	}
}

func TestForgottenWhenUnseen(t *testing.T) {
	l := newLearning(t)
	learner := l.learner(nil, nil)
	learner.Remember([]string{"203.0.113.5:1194/udp"}, "test", l.now)
	l.now += learnKeep + 1
	if len(learner.Endpoints(l.now)) != 0 {
		t.Fatal("an old endpoint is kept")
	}
	learner.Remember([]string{"203.0.113.6:1194/udp"}, "test", l.now)
	data, _ := os.ReadFile(filepath.Join(l.dir, "learned.json"))
	var saved struct{ Endpoints map[string]any }
	json.Unmarshal(data, &saved)
	if _, kept := saved.Endpoints["203.0.113.5:1194/udp"]; kept {
		t.Fatal("an old endpoint is saved")
	}
}

func TestLearnedGarbageIgnored(t *testing.T) {
	l := newLearning(t)
	os.WriteFile(filepath.Join(l.dir, "learned.json"),
		[]byte(`{"endpoints": {"nonsense": {}, "1.2.3.4:5/udp": {"last": 2000000000}}}`), 0o644)
	learner := l.learner(nil, nil)
	if keys := sortedKeys(learner.entries); !reflect.DeepEqual(keys, []string{"1.2.3.4:5/udp"}) {
		t.Fatal(keys)
	}
	if learner.Remember([]string{"not an endpoint"}, "x", l.now) {
		t.Fatal("garbage remembered")
	}
}

func (l *learning) connections(args []string) Result {
	switch args[0] {
	case "ps":
		return done("  2002 /Applications/ExampleVPN.app/Contents/PlugIns/PacketTunnel.appex/Contents/MacOS/PacketTunnel\n"+
			"  3003 /System/Library/X.appex/Contents/MacOS/X\n"+
			"  4004 /usr/local/sbin/openvpn\n"+
			"  5005 /Applications/Other.app/Contents/PlugIns/Share.appex/Contents/MacOS/Share\n", 0)
	case "lsof":
		l.lsofPIDs = args[slices.Index(args, "-p")+1]
		return done("p2002\ncPacketTunnel\nf6\nPTCP\nn192.168.1.108:50000->45.67.89.20:443\nTST=ESTABLISHED\n"+
			"f7\nPTCP\nn192.168.1.108:50001->45.67.89.21:443\nTST=SYN_SENT\n"+
			"f8\nPTCP\nn10.8.0.3:50002->45.67.89.22:443\nTST=ESTABLISHED\n"+
			"f9\nPUDP\nn192.168.1.108:50003->192.168.1.1:53\n"+
			"p4004\ncopenvpn\nf3\nPUDP\nn[fd00:1:2:0:a:b:c:d]:5000->[2a01:4f8::30]:443\n", 0)
	}
	l.t.Fatalf("unexpected command %v", args)
	return Result{}
}

func TestConnectionsOfRunningProviders(t *testing.T) {
	l := newLearning(t)
	bundles := map[string]string{
		"/Applications/ExampleVPN.app/Contents/PlugIns/PacketTunnel.appex/Contents/MacOS/PacketTunnel": "com.example.vpn.tunnel",
		"/Applications/Other.app/Contents/PlugIns/Share.appex/Contents/MacOS/Share":                    "com.other.share",
		"/System/Library/X.appex/Contents/MacOS/X":                                                     "com.example.vpn.tunnel",
	}
	learner := l.learner(l.connections, func(path string) string { return bundles[path] })
	tunnel := &TunnelState{Interface: "utun5", Services: []string{"ExampleVPN"}}
	if err := learner.ScanConnections(home, tunnel, []string{"openvpn"}, l.now); err != nil {
		t.Fatal(err)
	}
	if l.lsofPIDs != "2002,4004" {
		t.Fatal(l.lsofPIDs)
	}
	// Global addresses only, over the trusted uplink, established TCP; not through the tunnel.
	want := map[string]string{"45.67.89.20:443/tcp": "connection: ExampleVPN", "[2a01:4f8::30]:443/udp": "connection: openvpn"}
	if got := sources(learner.Endpoints(l.now)); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestNoLearningWithoutTunnelOrTrust(t *testing.T) {
	l := newLearning(t)
	learner := l.learner(l.connections, func(string) string { return "com.example.vpn.tunnel" })
	learner.ScanConnections(home, nil, nil, l.now)
	learner.ScanConnections(cafe, &TunnelState{Interface: "utun5", Services: []string{}}, nil, l.now)
	if len(learner.Endpoints(l.now)) != 0 {
		t.Fatal("learned")
	}
}
