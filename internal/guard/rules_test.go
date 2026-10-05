package guard

import (
	"fmt"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func parseAll(texts ...string) []Endpoint {
	var endpoints []Endpoint
	for _, text := range texts {
		endpoints = append(endpoints, MustEndpoint(text))
	}
	return endpoints
}

func TestTrustedUplinkIsOnlyPinned(t *testing.T) {
	text := Render(home, vpnEndpoints, true)
	if slices.Contains(closedSet(text), "en0") {
		t.Fatal("en0 is closed")
	}
	var onEn0 []string
	for _, line := range lines(text) {
		if strings.Contains(line, " on en0 ") {
			onEn0 = append(onEn0, line)
		}
	}
	want := []string{"block drop out quick on en0 inet from ! <ks_en0_v4>", "block drop out quick on en0 inet6 from ! <ks_en0_v6>"}
	if !reflect.DeepEqual(onEn0, want) {
		t.Fatal(onEn0)
	}
	for _, table := range []string{"table <ks_en0_v4> const { 0.0.0.0, 192.168.1.108 }",
		"table <ks_en0_v6> const { ::, fd00:1:2::/64, fe80::/10 }"} {
		if !strings.Contains(text, table) {
			t.Error(table)
		}
	}
}

func TestPinModes(t *testing.T) {
	subnet := withLink(home, "en0", func(l *Link) { l.Pin = "subnet" })
	if !strings.Contains(Render(subnet, vpnEndpoints, true), "table <ks_en0_v4> const { 0.0.0.0, 192.168.1.0/24 }") {
		t.Error("subnet pin")
	}
	none := withLink(home, "en0", func(l *Link) { l.Pin = "none" })
	for _, line := range lines(Render(none, vpnEndpoints, true)) {
		if strings.Contains(line, "en0") && !strings.HasPrefix(line, "closed") {
			t.Error(line)
		}
	}
}

func TestUntrustedClosesEverything(t *testing.T) {
	for _, c := range []struct {
		uplinks map[string]Link
		trust   bool
	}{{home, false}, {cafe, true}, {map[string]Link{}, true}} {
		text := Render(c.uplinks, vpnEndpoints, c.trust)
		if !slices.Contains(closedSet(text), "en0") || strings.Contains(text, "<ks_en0") {
			t.Errorf("%v, trust %v", c.uplinks, c.trust)
		}
	}
	closed := closedSet(Render(map[string]Link{}, vpnEndpoints, true))
	for i := range 10 {
		if closed[i] != fmt.Sprintf("en%d", i) {
			t.Fatal(closed[:10])
		}
	}
	if !slices.Contains(closedSet(Render(map[string]Link{"p2p0": {}, "en12": {}}, vpnEndpoints, true)), "p2p0") {
		t.Error("an observed uplink is not closed")
	}
}

func TestOnlyScopedQuickRules(t *testing.T) {
	for _, c := range []struct {
		uplinks map[string]Link
		trust   bool
	}{{home, true}, {home, false}, {cafe, true}, {map[string]Link{}, true}} {
		var rules []string
		for _, line := range lines(Render(c.uplinks, vpnEndpoints, c.trust)) {
			if strings.HasPrefix(line, "pass") || strings.HasPrefix(line, "block") {
				rules = append(rules, line)
			}
		}
		for _, line := range rules {
			pass := strings.HasPrefix(line, "pass")
			switch {
			case !strings.Contains(line, " quick on "):
				t.Error("not quick and scoped:", line)
			case pass && !strings.Contains(line, "no state"):
				t.Error("keeps state:", line)
			case pass && strings.Contains(line, " on en0 ") && !strings.Contains(line, "icmp"):
				t.Error("passes on en0:", line)
			}
		}
		if last := rules[len(rules)-1]; last != "block drop quick on $closed all" {
			t.Error(last)
		}
	}
}

func TestEndpointsAndRouterPing(t *testing.T) {
	all := slices.Concat(vpnEndpoints, parseAll("[2001:db8::10]:51820/udp", "198.51.100.5/esp", "203.0.113.20/tcp",
		"198.51.100.61:51820/udp"))
	text := Render(cafe, all, true)
	if strings.Count(text, "to 198.51.100.61 port 51820") != 1 {
		t.Error("a duplicate endpoint is rendered twice")
	}
	for _, rule := range []string{
		"pass out quick on $closed inet6 proto udp to 2001:db8::10 port 51820 no state",
		"pass in quick on $closed inet proto esp from 198.51.100.5 no state",
		"pass in quick on $closed inet proto udp from 198.51.100.61 port 51820 to any port 1024:65535 no state",
		"pass in quick on $closed inet proto tcp from 203.0.113.20 to any port 1024:65535 no state",
		"pass out quick on $closed inet proto tcp to 203.0.113.20 no state",
		"pass out quick on $closed inet proto icmp to $local icmp-type echoreq no state",
	} {
		if !strings.Contains(text, rule) {
			t.Error(rule)
		}
	}
	public := map[string]Link{"en0": {Router: "203.0.113.1", V4: []string{"203.0.113.7/24"}}}
	if !strings.Contains(Render(public, vpnEndpoints, true),
		"pass out quick on en0 inet proto icmp to 203.0.113.1 icmp-type echoreq no state") {
		t.Error("a public router is not pinged")
	}
	for _, line := range lines(text) {
		if strings.Contains(line, "icmp6") && !strings.Contains(line, "toobig") &&
			!strings.Contains(line, "icmp6-type { 133 134 135 136 137 143 }") {
			t.Error(line)
		}
	}
}

func TestIKEAndPathMTU(t *testing.T) {
	text := Render(cafe, parseAll("198.51.100.5:500/udp", "198.51.100.5:4500/udp", "[2001:db8::10]:51820/udp",
		"198.51.100.61:51820/udp"), true)
	for _, rule := range []string{
		"pass in quick on $closed inet proto udp from 198.51.100.5 port 500 no state",
		"pass in quick on $closed inet proto udp from 198.51.100.5 port 4500 no state",
		"pass in quick on $closed inet proto icmp from 198.51.100.5 icmp-type unreach no state",
		"pass in quick on $closed inet6 proto icmp6 from 2001:db8::10 icmp6-type toobig no state",
	} {
		if !strings.Contains(text, rule) {
			t.Error(rule)
		}
	}
	if strings.Count(text, "from 198.51.100.5 icmp-type unreach") != 1 {
		t.Error("unreach repeated")
	}
}

func TestTablesComeBeforeRules(t *testing.T) {
	text := lines(Render(home, vpnEndpoints, true))
	firstRule := slices.IndexFunc(text, func(line string) bool { return strings.HasPrefix(line, "block") || strings.HasPrefix(line, "pass") })
	lastTable := slices.IndexFunc(text, func(line string) bool { return strings.HasPrefix(line, "table <ks_en0_v6>") })
	if lastTable < 0 || lastTable > firstRule || !strings.HasPrefix(text[1], "closed = ") {
		t.Fatal(text[:6])
	}
}

func TestPfctlAccepts(t *testing.T) {
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skip("needs pfctl")
	}
	all := slices.Concat(vpnEndpoints, parseAll("[2001:db8::10]:51820/udp", "198.51.100.5/esp", "203.0.113.20/tcp"))
	mixed := map[string]Link{"en0": withLink(home, "en0", func(l *Link) { l.Pin = "subnet" })["en0"],
		"en7": {Router: "203.0.113.1", V4: []string{"203.0.113.7/24"}}}
	for _, c := range []struct {
		uplinks map[string]Link
		trust   bool
	}{{home, true}, {home, false}, {cafe, true}, {map[string]Link{}, true}, {mixed, true}} {
		if result := Run([]string{"pfctl", "-n", "-f", "-"}, Render(c.uplinks, all, c.trust), 0); result.Failed() {
			t.Errorf("%v: %s", c.uplinks, result.Error())
		}
	}
}
