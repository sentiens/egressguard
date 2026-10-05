package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	logger.SetOutput(io.Discard)
	os.Exit(m.Run())
}

const homeMAC = "02:00:5e:10:00:01"

// must fails the test on an error from its setup.
func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// writeFile writes a test file.
func writeFile(t testing.TB, path, data string) {
	t.Helper()
	must(t, os.WriteFile(path, []byte(data), 0o644))
}

// readFile is a test file's content.
func readFile(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	must(t, err)
	return string(data)
}

// marshal is value as JSON.
func marshal(t testing.TB, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	must(t, err)
	return data
}

var (
	networks = []Network{
		{Name: "Home 1", Router: "192.168.1.1", RouterMAC: homeMAC, Pin: "address"},
		{Name: "Home 2", Router: "192.168.2.1", RouterMAC: "02:00:5e:10:00:02", Pin: "address"},
	}
	vpnEndpoints = []Endpoint{MustEndpoint("198.51.100.61:51820/udp"), MustEndpoint("198.51.100.164:51820/udp")}
	baseConfig   = Config{TrustedNetworks: networks, Tunnels: []Tunnel{{Name: "VPN", Endpoints: vpnEndpoints}},
		Control: "/nonexistent/control.json", Learn: Learn{VPNServices: true, Connections: true, Processes: []string{}}}

	home = map[string]Link{
		"en0": {Router: "192.168.1.1", MAC: homeMAC, Trusted: true, Network: "Home 1", Pin: "address",
			V4: []string{"192.168.1.108/24"}, V6: []string{"fe80::1:2:3:4/64", "fd00:1:2:0:a:b:c:d/64"}},
		"en1": {},
	}
	cafe  = map[string]Link{"en0": {Router: "192.168.1.1", MAC: "aa:bb:cc:00:11:22", V4: []string{"192.168.1.57/24"}}}
	home2 = map[string]Link{"en0": {Router: "192.168.2.1", MAC: "02:00:5e:10:00:02", Trusted: true, Network: "Home 2",
		Pin: "address", V4: []string{"192.168.2.20/24"}}}
)

// withLink is uplinks with one link changed.
func withLink(uplinks map[string]Link, name string, change func(*Link)) map[string]Link {
	result := map[string]Link{}
	for key, value := range uplinks {
		result[key] = value
	}
	link := result[name]
	change(&link)
	result[name] = link
	return result
}

func names(list ...string) map[string]bool {
	set := map[string]bool{}
	for _, name := range list {
		set[name] = true
	}
	return set
}

func ptr[T any](value T) *T { return &value }

func done(stdout string, code int) Result { return Result{Stdout: stdout, Code: code} }

var errTimeout = errors.New("no answer within 5s")

func isUnanswered(err error) bool {
	var unanswered *Unanswered
	return errors.As(err, &unanswered)
}

const ifconfigOutput = `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
	media: autoselect <full-duplex>
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 02:00:5e:00:00:05
	inet6 fe80::1:2:3:4%en0 prefixlen 64 secured scopeid 0xe
	inet6 fd00:1:2:0:a:b:c:d prefixlen 64 autoconf secured
	inet 192.168.1.108 netmask 0xffffff00 broadcast 192.168.1.255
awdl0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
	inet 10.8.0.3 --> 10.8.0.3 netmask 0xffffffff
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
`

// fakeNet answers ifconfig, ipconfig, arp and ping, with an ARP cache that ping fills.
type fakeNet struct {
	router, mac string
	answers     bool
	cache       map[string]string
	calls       [][]string
	arpDelete   func(args []string) Result
}

func newNet() *fakeNet {
	return &fakeNet{router: "192.168.1.1", mac: homeMAC, answers: true, cache: map[string]string{"192.168.1.1": homeMAC}}
}

func (n *fakeNet) run(args []string, input string, timeout time.Duration) Result {
	n.calls = append(n.calls, args)
	switch {
	case args[0] == "ifconfig":
		return done(ifconfigOutput, 0)
	case args[0] == "ipconfig":
		if args[2] == "en0" && n.router != "" {
			return done(n.router+"\n", 0)
		}
		return done("", 0)
	case args[0] == "arp" && args[1] == "-d":
		if n.arpDelete != nil {
			return n.arpDelete(args)
		}
		delete(n.cache, args[2])
		return done("", 0)
	case args[0] == "arp" && args[1] == "-n":
		mac := n.cache[args[2]]
		if mac == "" {
			mac = "(incomplete)"
		}
		return done(fmt.Sprintf("? (%s) at %s on en0 ifscope [ethernet]\n", args[2], mac), 0)
	case args[0] == "ping":
		if !n.answers {
			return done("", 2)
		}
		n.cache[args[len(args)-1]] = n.mac
		return done("", 0)
	}
	panic(fmt.Sprintf("unexpected command %v", args))
}

func (n *fakeNet) count(tool string) int {
	return len(slices.DeleteFunc(slices.Clone(n.calls), func(call []string) bool { return call[0] != tool }))
}

// fakePF is a packet filter that remembers what it was asked to do.
type fakePF struct {
	loads    []string
	current  string
	on, main bool
	enables  int
	failLoad bool
	failKill bool
	killed   []string
	journal  []string // loads and kills in order
}

func newPF() *fakePF { return &fakePF{on: true, main: true} }

func (p *fakePF) Enabled() (bool, error)  { return p.on, nil }
func (p *fakePF) Enable() error           { p.on = true; p.enables++; return nil }
func (p *fakePF) Attached() (bool, error) { return p.main, nil }
func (p *fakePF) ReloadMain() error       { p.main = true; return nil }
func (p *fakePF) Loaded() (bool, error)   { return p.current != "", nil }

func (p *fakePF) Load(rules string) error {
	p.loads = append(p.loads, rules)
	p.journal = append(p.journal, fmt.Sprintf("load en0 open=%v", en0Open(rules)))
	if p.failLoad {
		return errors.New("pfctl refused the rules")
	}
	p.current = rules
	return nil
}

func (p *fakePF) KillStates(source string) error {
	if p.failKill {
		return errors.New("pfctl did not answer")
	}
	p.journal = append(p.journal, "kill "+source)
	p.killed = append(p.killed, source)
	return nil
}

// closedSet is the $closed macro of rules.
func closedSet(rules string) []string {
	for _, line := range strings.Split(rules, "\n") {
		if rest, found := strings.CutPrefix(line, "closed = "); found {
			inner := rest[strings.Index(rest, "{")+1 : strings.Index(rest, "}")]
			return strings.Fields(inner)
		}
	}
	return nil
}

// en0Open reports whether rules trust en0 (it is not in the closed set).
func en0Open(rules string) bool { return rules != "" && !slices.Contains(closedSet(rules), "en0") }

// killedSet is what the fake pf dropped states for, sorted.
func (p *fakePF) killedSet() []string { return slices.Sorted(slices.Values(p.killed)) }

func lines(text string) []string { return strings.Split(strings.TrimRight(text, "\n"), "\n") }
