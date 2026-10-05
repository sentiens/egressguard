package guard

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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

// profilesOn is the VPN configurations of fake scutil --nc, in a temporary directory.
func profilesOn(t *testing.T, dir string, show map[string]vpnServer) *Profiles {
	return NewProfiles(filepath.Join(dir, "resolved.json"), scutilRunner(t, show, nil),
		func(string) []string { return []string{"198.51.100.7"} })
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

func TestProfilesAreALiveView(t *testing.T) {
	dir, show := t.TempDir(), ncShow()
	profiles := profilesOn(t, dir, show)
	must(t, profiles.Scan(false))
	if got := texts(profiles.Endpoints()); !reflect.DeepEqual(got, []string{"198.51.100.185:51820/udp", "198.51.100.61:51820/udp"}) {
		t.Fatal(got)
	}
	must(t, profiles.Scan(true))
	found := sources(profiles.Endpoints())
	if found["198.51.100.7/esp"] != "vpn: Office" || found["198.51.100.61:51820/udp"] != "vpn: home-wg" {
		t.Fatal(found)
	}
	// A restart remembers the host name's last answer, not the configurations.
	again := profilesOn(t, dir, show)
	if len(again.Endpoints()) != 0 {
		t.Fatal("configurations remembered")
	}
	must(t, again.Scan(false))
	if !slices.Contains(texts(again.Endpoints()), "198.51.100.7/esp") {
		t.Fatal("the resolved address is forgotten")
	}
	// A deleted configuration takes its endpoint with it.
	show["F866AE22-4EC1-4524-8769-86A290A0C582"] = vpnServer{"Deleted Mesh", ""}
	must(t, again.Scan(false))
	if slices.Contains(texts(again.Endpoints()), "198.51.100.185:51820/udp") {
		t.Fatal("a deleted configuration is still allowed")
	}
}

func TestScanFailureKeepsTheProfiles(t *testing.T) {
	profiles := profilesOn(t, t.TempDir(), ncShow())
	must(t, profiles.Scan(false))
	profiles.run = func([]string, string, time.Duration) Result { return Result{Code: -1, Err: errTimeout} }
	if err := profiles.Scan(false); err == nil {
		t.Fatal("no error")
	}
	if got := texts(profiles.Endpoints()); len(got) != 2 {
		t.Fatal("endpoints lost when scutil did not answer:", got)
	}
}

func TestUnusableServerLeftOut(t *testing.T) {
	show := ncShow()
	show["9B33EDB3-7576-4A9C-AB78-BC8C08E05BE4"] = vpnServer{"224.0.0.1:51820", "com.wireguard.macos.network-extension"}
	profiles := profilesOn(t, t.TempDir(), show)
	must(t, profiles.Scan(false)) // the others still count
	if got := texts(profiles.Endpoints()); !reflect.DeepEqual(got, []string{"198.51.100.185:51820/udp"}) {
		t.Fatal(got)
	}
	if !strings.Contains(profiles.refused, "home-wg") {
		t.Fatal("not reported:", profiles.refused)
	}
}

func TestResolvedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolved.json")
	writeFile(t, path, `{"version": 1, "resolved": {"vpn.example.org": ["198.51.100.9"]}}`)
	profiles := profilesOn(t, dir, ncShow())
	must(t, profiles.Scan(false))
	if !slices.Contains(texts(profiles.Endpoints()), "198.51.100.9/esp") {
		t.Fatal(texts(profiles.Endpoints()))
	}
	// A file that cannot be read is not used, and the next answer replaces it.
	writeFile(t, path, `{"resolved": {"vpn.example.org": [1]}}`)
	if _, err := loadResolved(path); err == nil {
		t.Fatal("garbage accepted")
	}
	profiles = profilesOn(t, dir, ncShow())
	must(t, profiles.Scan(true))
	var saved resolvedFile
	must(t, json.Unmarshal([]byte(readFile(t, path)), &saved))
	if !reflect.DeepEqual(saved.Resolved, map[string][]string{"vpn.example.org": {"198.51.100.7"}}) {
		t.Fatal(saved)
	}
}
