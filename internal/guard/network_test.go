package guard

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func observe(t *testing.T, config Config, refresh bool, net *fakeNet) map[string]Link {
	t.Helper()
	uplinks, err := Observe(config, refresh, net.run, true)
	if err != nil {
		t.Fatal(err)
	}
	return uplinks
}

func TestInterfacesParse(t *testing.T) {
	found := Interfaces(ifconfigOutput)
	en0 := found["en0"]
	if en0.MAC != "02:00:5e:00:00:05" || !reflect.DeepEqual(en0.V4, []string{"192.168.1.108/24"}) ||
		!reflect.DeepEqual(en0.V6, []string{"fe80::1:2:3:4/64", "fd00:1:2:0:a:b:c:d/64"}) {
		t.Fatalf("%+v", en0)
	}
	if !reflect.DeepEqual(found["utun3"].V4, []string{"10.8.0.3/32"}) {
		t.Fatalf("%+v", found["utun3"])
	}
	if gif := found["gif0"]; len(gif.V4)+len(gif.V6)+len(gif.Members) != 0 {
		t.Fatalf("%+v", gif)
	}
	bridged := Interfaces(ifconfigOutput + "bridge100: flags=8863<UP> mtu 1500\n\tmember: en0 flags=3<LEARNING,DISCOVER>\n")
	if !reflect.DeepEqual(bridged["bridge100"].Members, []string{"en0"}) {
		t.Fatalf("%+v", bridged["bridge100"])
	}
}

func TestTrustNeedsRouterAndMAC(t *testing.T) {
	if en0 := observe(t, baseConfig, false, newNet())["en0"]; !en0.Trusted || en0.Network != "Home 1" {
		t.Fatalf("%+v", en0)
	}
	other := newNet()
	other.mac = "aa:bb:cc:00:11:22"
	other.cache = map[string]string{"192.168.1.1": other.mac}
	if observe(t, baseConfig, false, other)["en0"].Trusted {
		t.Error("another router MAC is trusted")
	}
	moved := newNet()
	moved.router = "10.0.0.1"
	moved.cache = map[string]string{"10.0.0.1": homeMAC}
	if observe(t, baseConfig, false, moved)["en0"].Trusted {
		t.Error("another router address is trusted")
	}
}

func TestMACOnlyAndInterfaceOnly(t *testing.T) {
	config := baseConfig
	config.TrustedNetworks = []Network{{Name: "any ip", RouterMAC: homeMAC, Pin: "address"}}
	net := newNet()
	net.router = "10.9.9.9"
	net.cache = map[string]string{"10.9.9.9": homeMAC}
	if !observe(t, config, false, net)["en0"].Trusted {
		t.Error("a MAC-only network is not trusted")
	}

	config.TrustedNetworks = []Network{{Name: "cable", Interface: "en1", Pin: "none"}}
	net = newNet()
	uplinks, err := Observe(config, false, net.run, false)
	must(t, err)
	if !uplinks["en1"].Trusted || uplinks["en0"].Trusted {
		t.Fatalf("%+v", uplinks)
	}
	if net.count("arp")+net.count("ping") != 0 {
		t.Error("looked up a MAC nobody needs")
	}
	if observe(t, config, false, newNet())["en0"].MAC != homeMAC {
		t.Error("the MAC is not known for the menu")
	}

	config.TrustedNetworks = []Network{{Name: "x", Interface: "en1", RouterMAC: homeMAC, Pin: "address"}}
	if observe(t, config, false, newNet())["en0"].Trusted {
		t.Error("an interface-bound network is trusted on another interface")
	}
}

func TestInternalSkippedAndRoutersOnlyForAddressed(t *testing.T) {
	net := newNet()
	if got := sortedKeys(observe(t, baseConfig, false, net)); !reflect.DeepEqual(got, []string{"en0", "en1", "gif0"}) {
		t.Fatal(got)
	}
	var asked []string
	for _, call := range net.calls {
		if call[0] == "ipconfig" {
			asked = append(asked, call[2])
		}
	}
	if !reflect.DeepEqual(asked, []string{"en0"}) {
		t.Fatal(asked)
	}
}

func TestRefreshDropsAStaleCache(t *testing.T) {
	net := newNet()
	net.mac = "aa:bb:cc:00:11:22" // the router now; the cache still names the old one
	if !observe(t, baseConfig, false, net)["en0"].Trusted {
		t.Fatal("the cached entry is not used")
	}
	if observe(t, baseConfig, true, net)["en0"].Trusted {
		t.Fatal("a stale cache trusted after a refresh")
	}
}

func TestSilentRouterIsNotTrusted(t *testing.T) {
	net := newNet()
	net.cache, net.answers = map[string]string{}, false
	en0 := observe(t, baseConfig, false, net)["en0"]
	if en0.MAC != "" || en0.Trusted || net.count("ping") != 3 {
		t.Fatalf("%+v, %d pings", en0, net.count("ping"))
	}
}

func TestARPEntryMustBeOnTheInterface(t *testing.T) {
	for _, out := range []string{"? (192.168.1.1) at (incomplete) on en0 ifscope [ethernet]\n",
		"? (192.168.1.1) at " + homeMAC + " on en7 ifscope [ethernet]\n"} {
		run := func([]string, string, time.Duration) Result { return done(out, 0) }
		if mac, err := ARP("192.168.1.1", "en0", run); mac != "" || err != nil {
			t.Errorf("%q: %s %v", out, mac, err)
		}
	}
}

func TestUndeletableARPEntryProvesNothing(t *testing.T) {
	stuck := newNet()
	stuck.arpDelete = func([]string) Result { return Result{Stderr: "delete: Operation not permitted", Code: 1} }
	if observe(t, baseConfig, true, stuck)["en0"].Trusted {
		t.Fatal("trusted although the old entry stayed")
	}
	scoped := []string{"arp", "-d", "192.168.1.1", "ifscope", "en0"}
	if !slices.ContainsFunc(stuck.calls, func(call []string) bool { return slices.Equal(call, scoped) }) {
		t.Fatal("no scoped delete")
	}

	missing := newNet()
	missing.arpDelete = func(args []string) Result {
		delete(missing.cache, args[2])
		return Result{Stderr: "cannot locate 192.168.1.1", Code: 1}
	}
	if !observe(t, baseConfig, true, missing)["en0"].Trusted {
		t.Fatal("an absent entry blocks trust")
	}
}

func TestSilentTools(t *testing.T) {
	empty := func([]string, string, time.Duration) Result { return done("", 0) }
	if _, err := Observe(baseConfig, false, empty, true); err == nil {
		t.Error("an empty ifconfig accepted")
	}
	net := newNet()
	run := func(args []string, input string, timeout time.Duration) Result {
		if args[0] == "arp" {
			return Result{Code: -1, Err: errTimeout}
		}
		return net.run(args, input, timeout)
	}
	uplinks, err := Observe(baseConfig, false, run, true)
	if !isUnanswered(err) || !strings.Contains(err.Error(), "en0: arp -n 192.168.1.1") {
		t.Fatalf("not Unanswered: %v", err)
	}
	if en0 := uplinks["en0"]; en0.Trusted || len(en0.V4) == 0 || uplinks["en1"].V4 == nil {
		t.Fatalf("%+v", uplinks) // the silent uplink is untrusted, the others are kept
	}
}

func TestPins(t *testing.T) {
	v4, v6 := Pins(home["en0"])
	if !reflect.DeepEqual(v4, []string{"0.0.0.0", "192.168.1.108"}) || !reflect.DeepEqual(v6, []string{"::", "fd00:1:2::/64", "fe80::/10"}) {
		t.Fatal(v4, v6)
	}
	if sources := StateSources(home["en0"]); !reflect.DeepEqual(sources, []string{"192.168.1.108", "fd00:1:2::/64"}) {
		t.Fatal(sources)
	}
}

func TestRouterSignatures(t *testing.T) {
	run := func(args []string, input string, timeout time.Duration) Result {
		switch {
		case strings.HasPrefix(input, "list"):
			return done("  subKey [0] = State:/Network/Service/2D71CDD4-FAAC-4AF8-B8DC-AD69AB58B054/IPv4\n"+
				"  subKey [1] = State:/Network/Service/AAAA/IPv4\n", 0)
		case strings.Contains(input, "2D71CDD4"):
			return done("<dictionary> {\n  InterfaceName : en0\n"+
				"  NetworkSignature : IPv4.Router=192.168.1.1;IPv4.RouterHardwareAddress=2:0:5e:10:0:1\n}\n", 0)
		}
		return done("<dictionary> {\n  InterfaceName : utun4\n}\n", 0)
	}
	want := map[string]RouterSignature{"en0": {Router: "192.168.1.1", MAC: homeMAC}}
	if got, err := RouterSignatures(run); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
}

func TestRouterSignaturesUnanswered(t *testing.T) {
	run := func(args []string, input string, timeout time.Duration) Result { return done("", 1) }
	if got, err := RouterSignatures(run); err == nil || got != nil {
		t.Fatal(got, err)
	}
}

func TestToolPathIgnoresTheCallersPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	path, err := ToolPath("ifconfig")
	if err != nil || path != "/sbin/ifconfig" {
		t.Fatal(path, err)
	}
	if _, err := ToolPath("no-such-tool"); err == nil {
		t.Fatal("found a missing tool")
	}
}

func TestARPAbsenceAndFailure(t *testing.T) {
	answer := func(result Result) Runner { return func([]string, string, time.Duration) Result { return result } }
	mac, err := ARP("192.168.1.1", "en0", answer(Result{Stdout: "192.168.1.1 (192.168.1.1) -- no entry\n", Code: 1}))
	if mac != "" || err != nil {
		t.Fatal("no entry is not a failure:", mac, err)
	}
	if _, err := ARP("192.168.1.1", "en0", answer(Result{Stderr: "arp: sysctl: Operation not permitted", Code: 1})); err == nil {
		t.Fatal("a failing arp passed as no entry")
	}
	if _, err := ARP("192.168.1.1", "en0", answer(Result{Code: -1, Err: errTimeout})); !isUnanswered(err) || !errors.Is(err, errTimeout) {
		t.Fatal("the cause is lost:", err)
	}
}
