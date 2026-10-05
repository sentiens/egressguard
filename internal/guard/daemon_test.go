package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// clocks: the wall clock, the awake clock, the time asleep and the input idle time.
// sleep advances the wall clock and the time asleep only.
type clocks struct{ wall, awake, asleep, idle float64 }

func (c *clocks) advance(seconds float64) { c.wall += seconds; c.awake += seconds; c.idle += seconds }
func (c *clocks) sleep(seconds float64)   { c.wall += seconds; c.asleep += seconds }
func (c *clocks) touch()                  { c.idle = 0 }

// harness drives a daemon over a fake Mac.
type harness struct {
	t        *testing.T
	dir      string
	control  string
	uplinks  map[string]Link // what the next observation sees
	statuses []Status
	clocks   *clocks
	pf       *fakePF
	observed []observation
	daemon   *Daemon
}

// observation is what an observation was asked for, and whether en0 was open then.
type observation struct{ refresh, en0Open bool }

var (
	fresh   = observation{refresh: true, en0Open: false} // a fresh check, with en0 closed
	routine = observation{refresh: false, en0Open: true} // a routine look, en0 open
)

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, dir: t.TempDir(), uplinks: home, clocks: &clocks{1_000_000, 5_000, 0, 10_000}, pf: newPF()}
	h.control = filepath.Join(h.dir, "control.json")
	h.daemon = h.make(h.config(), nil)
	return h
}

func (h *harness) config() Config {
	config := baseConfig
	config.Control = h.control
	return config
}

// make builds a daemon on the fake Mac; change adjusts its System.
func (h *harness) make(config Config, change func(*System)) *Daemon {
	c := h.clocks
	sys := System{
		Filter:     h.pf,
		Observe:    h.observe,
		Tunnel:     func() (*TunnelState, error) { return nil, nil },
		Wall:       func() float64 { return c.wall },
		Awake:      func() float64 { return c.awake },
		Asleep:     func() float64 { return c.asleep },
		Idle:       func() (float64, error) { return c.idle, nil },
		Publish:    func(status Status) { h.statuses = append(h.statuses, status) },
		LoadConfig: LoadConfig,
	}
	if change != nil {
		change(&sys)
	}
	return NewDaemon(config, sys)
}

func (h *harness) observe(config Config, refresh bool) (map[string]Link, error) {
	h.observed = append(h.observed, observation{refresh, en0Open(h.pf.current)})
	h.pf.journal = append(h.pf.journal, "observe")
	if len(config.TrustedNetworks) == 0 {
		return Distrust(h.uplinks), nil
	}
	return h.uplinks, nil
}

func (h *harness) mode(value string) { writeFile(h.t, h.control, value) }

func (h *harness) settings(value any) {
	writeFile(h.t, filepath.Join(h.dir, "settings.json"), string(marshal(h.t, value)))
}

func (h *harness) last() Status { return h.statuses[len(h.statuses)-1] }

func (h *harness) lastObserved() observation { return h.observed[len(h.observed)-1] }

func (h *harness) expect(events []*Event, want string) {
	h.t.Helper()
	if got := h.daemon.Step(events); got != want {
		h.t.Fatalf("state %s, want %s (errors %v)", got, want, h.last().Errors)
	}
}

func (h *harness) hasError(part string) bool {
	return slices.ContainsFunc(h.last().Errors, func(err string) bool { return strings.Contains(err, part) })
}

func join() []*Event     { return []*Event{{Kind: EventJoin, Names: names()}} }
func leaveEn0() []*Event { return []*Event{{Kind: EventLeave, Names: names("en0")}} }
func wakeUp() []*Event   { return []*Event{{Kind: EventWake, Names: names()}} }

func TestStartClosesBeforeLooking(t *testing.T) {
	h := newHarness(t)
	h.expect(nil, StateTrusted)
	if en0Open(h.pf.loads[0]) || h.observed[0] != fresh || !en0Open(h.pf.current) {
		t.Fatal(h.observed, h.pf.loads[0])
	}
}

func TestHomeThenCafe(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.uplinks = cafe
	h.expect(leaveEn0(), StateBlocked)
	if h.lastObserved() != fresh || en0Open(h.pf.current) {
		t.Fatal(h.observed)
	}
	// pf states that started from the home addresses are dropped, and from the new
	// address too: the daemon does not know where its states came from.
	if !reflect.DeepEqual(h.pf.killedSet(), []string{"192.168.1.108", "192.168.1.57", "fd00:1:2::/64"}) {
		t.Fatal(h.pf.killed)
	}
}

func TestLeaveAtHomeReturns(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.expect(leaveEn0(), StateTrusted)
	if h.lastObserved() != fresh || !en0Open(h.pf.current) {
		t.Fatal(h.observed)
	}
}

func TestUnrelatedEventsKeepTrust(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	loads := len(h.pf.loads)
	for _, event := range []*Event{{Kind: EventLeave, Names: names("en5")}, {Kind: EventLeave, Names: names(), Gateway: "10.8.0.2"},
		{Kind: EventLeave, Names: names()}} {
		h.expect([]*Event{event}, StateTrusted)
		if h.lastObserved() != routine {
			t.Fatal(event, h.observed)
		}
	}
	if len(h.pf.loads) != loads {
		t.Fatal("rules reloaded")
	}
	h.daemon.Step([]*Event{{Kind: EventLeave, Names: names(), Gateway: "192.168.1.1"}})
	if h.lastObserved() != fresh {
		t.Fatal("the router's default route went away unnoticed")
	}
}

func TestFollowUpEverySecond(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Step(leaveEn0())
	count := len(h.observed)
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if len(h.observed) != count+1 {
		t.Fatal("no follow-up")
	}
	h.clocks.advance(follow)
	h.daemon.Step(nil)
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if len(h.observed) != count+2 {
		t.Fatal("followed too long:", len(h.observed)-count)
	}
}

func TestObservationOvertakenByABreakProvesNothing(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.sys.Observe = func(Config, bool) (map[string]Link, error) {
		h.daemon.mu.Lock()
		h.daemon.breakTrust("meanwhile")
		h.daemon.mu.Unlock()
		return home, nil
	}
	h.clocks.advance(tick)
	h.expect(nil, StateBlocked)
	if en0Open(h.pf.current) || h.last().Uplinks["en0"].Trusted {
		t.Fatal("open, or reported trusted")
	}
	if uplinks, _ := h.daemon.Snapshot(); uplinks["en0"].Trusted {
		t.Fatal("the learner sees en0 trusted")
	}
	if h.daemon.uplinks["en0"].Trusted {
		t.Fatal("the overtaken observation was kept as trusted")
	}
	h.daemon.sys.Observe = h.observe
	h.clocks.advance(1)
	h.expect(nil, StateTrusted)
}

func TestOffFlushesAndOnRestores(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.mode(`{"mode": "off"}`)
	h.expect(nil, StateOff)
	if h.pf.current != "" {
		t.Fatal("rules stay while off")
	}
	h.uplinks = cafe
	h.expect(leaveEn0(), StateOff)
	if h.pf.current != "" {
		t.Fatal("rules loaded while off")
	}
	h.mode(`{"mode": "on"}`)
	h.expect(nil, StateBlocked)
	if en0Open(h.pf.current) {
		t.Fatal("open")
	}
}

func TestTimedOffExpires(t *testing.T) {
	h := newHarness(t)
	h.mode(fmt.Sprintf(`{"mode": "off", "until": %d}`, int64(h.clocks.wall)+60))
	h.expect(nil, StateOff)
	h.clocks.advance(61)
	h.expect(nil, StateTrusted)
}

func TestLockIgnoresTrust(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.mode(fmt.Sprintf(`{"mode": "lock", "until": %d}`, int64(h.clocks.wall)+20))
	h.expect(nil, StateBlocked)
	if en0Open(h.pf.current) || h.last().Uplinks["en0"].Trusted || len(h.last().Trusted) != 0 {
		t.Fatal("en0 open or reported trusted during the lock")
	}
	if uplinks, _ := h.daemon.Snapshot(); uplinks["en0"].Trusted {
		t.Fatal("the learner sees en0 trusted during the lock")
	}
	h.clocks.advance(21)
	h.expect(nil, StateTrusted)
	if !en0Open(h.pf.current) {
		t.Fatal("closed after the lock")
	}
}

func TestReloadWhenAnchorVanishes(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.pf.current, h.pf.main = "", false
	h.clocks.advance(verifyEvery)
	h.daemon.Step(nil)
	if !h.pf.main || !en0Open(h.pf.current) {
		t.Fatal("not restored")
	}
}

type detachedPF struct{ *fakePF }

func (detachedPF) Attached() (bool, error) { return false, nil }

func TestDetachedAnchorIsNotEnforced(t *testing.T) {
	h := newHarness(t)
	h.daemon = h.make(h.config(), func(sys *System) { sys.Filter = detachedPF{h.pf} })
	h.daemon.Step(nil)
	for range 3 { // the problem stands, between checks too
		if h.last().Enforced || !h.hasError("does not evaluate com.apple/*") {
			t.Fatalf("%+v", h.last())
		}
		h.clocks.advance(0.5)
		h.daemon.Step(nil)
	}
	h.daemon.sys.Filter = h.pf // the main ruleset is back: checked at once, not at the next routine check
	h.clocks.advance(0.25)
	h.daemon.Step(nil)
	if !h.last().Enforced {
		t.Fatal("not checked again", h.last().Errors)
	}
}

func TestOneSilentUplinkDoesNotHideTheOthers(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.sys.Observe = func(Config, bool) (map[string]Link, error) {
		silent := Link{V4: []string{"10.0.0.5/24"}, Silent: true}
		return map[string]Link{"en0": cafe["en0"], "en5": silent}, &Unanswered{Command: "ipconfig getoption en5 router"}
	}
	h.clocks.advance(tick)
	h.expect(nil, StateBlocked) // en5 did not answer, but en0 did: it is somewhere else now
	if !h.hasError("no answer from ipconfig getoption en5 router") || en0Open(h.pf.current) {
		t.Fatal(h.last().Errors)
	}
}

func TestPfDisabledIsReenabledWithinASecond(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	enables := h.pf.enables
	h.pf.on = false
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if !h.pf.on || h.pf.enables != enables+1 {
		t.Fatal(h.pf.enables)
	}
}

func TestTokenTakenOnce(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Step(leaveEn0())
	if h.pf.enables != 1 {
		t.Fatal(h.pf.enables)
	}
}

func TestLoadFailureReportedAndRetried(t *testing.T) {
	h := newHarness(t)
	h.pf.failLoad = true
	h.daemon.Step(nil)
	if !h.hasError("pf anchor load failed") || h.last().Enforced {
		t.Fatal(h.last().Errors)
	}
	h.pf.failLoad = false
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if !en0Open(h.pf.current) || !h.last().Enforced {
		t.Fatal("not retried")
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	status := h.last()
	if status.State != StateTrusted || !reflect.DeepEqual(status.Trusted, []TrustedEntry{{"en0", "Home 1"}}) ||
		status.Sealed || status.Version != 2 || status.Release != Release || !status.Enforced {
		t.Fatalf("%+v", status)
	}
	if status.Endpoints[0] != (EndpointEntry{"198.51.100.61:51820/udp", "config: VPN"}) {
		t.Fatal(status.Endpoints)
	}
	h.daemon.Step(nil)
	if len(h.statuses) != 1 {
		t.Fatal("an unchanged status was written again")
	}
	h.clocks.advance(tick)
	h.daemon.Step(nil)
	if len(h.statuses) != 2 {
		t.Fatal("no heartbeat")
	}
}

func TestStatusJSONForTheMenuApp(t *testing.T) {
	h := newHarness(t)
	h.uplinks = map[string]Link{"en0": home["en0"], "en5": {Router: "10.0.0.1", V4: []string{"10.0.0.5/24"}}}
	h.daemon.Step(nil)
	var value map[string]any
	must(t, json.Unmarshal(marshal(t, h.last()), &value))
	var uplinks struct{ En5 map[string]any }
	must(t, json.Unmarshal(marshal(t, value["uplinks"]), &uplinks))
	en5 := uplinks.En5
	if en5["mac"] != nil || en5["network"] != nil || en5["router"] != "10.0.0.1" || en5["trusted"] != false {
		t.Fatal(en5)
	}
	for _, key := range []string{"errors", "trusted", "endpoints", "networks"} {
		if _, ok := value[key].([]any); !ok {
			t.Errorf("%s is not a list: %v", key, value[key])
		}
	}
	if value["tunnel"] != nil || value["note"] != nil || value["until"] != nil {
		t.Fatal(value)
	}
}

func TestUnansweredKeepsRulesAndRetries(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.sys.Observe = func(Config, bool) (map[string]Link, error) { return nil, &Unanswered{Command: "ipconfig"} }
	h.clocks.advance(tick)
	h.expect(nil, StateTrusted)
	if !en0Open(h.pf.current) || !h.hasError("no answer from ipconfig") {
		t.Fatal(h.last().Errors)
	}
	h.expect(leaveEn0(), StateBlocked) // a revoked trust stays revoked
	h.daemon.sys.Observe = h.observe
	h.clocks.advance(1)
	h.expect(nil, StateTrusted)
}

func TestSilentToolsRevokeTrustAfterAWhile(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.sys.Observe = func(Config, bool) (map[string]Link, error) { return nil, &Unanswered{Command: "ifconfig"} }
	for range 3 {
		h.clocks.advance(tick)
		h.daemon.Step(nil)
	}
	h.expect(nil, StateBlocked)
	if en0Open(h.pf.current) {
		t.Fatal("trust kept without an answer for 30 s")
	}
}

type fixedLearner []Sourced

func (f fixedLearner) Endpoints(float64) []Sourced { return f }

func TestLearnedEndpointsAreRendered(t *testing.T) {
	h := newHarness(t)
	learned := fixedLearner{{MustEndpoint("203.0.113.20:443/tcp"), "connection: ExampleVPN"}}
	h.daemon = h.make(h.config(), func(sys *System) { sys.Learner = learned })
	h.uplinks = cafe
	h.daemon.Step(nil)
	if !strings.Contains(h.pf.current, "to 203.0.113.20 port 443") {
		t.Fatal(h.pf.current)
	}
	if !slices.Contains(h.last().Endpoints, EndpointEntry{"203.0.113.20:443/tcp", "connection: ExampleVPN"}) {
		t.Fatal(h.last().Endpoints)
	}
}

func TestEndpointSourcesMerged(t *testing.T) {
	h := newHarness(t)
	learned := fixedLearner{{MustEndpoint("198.51.100.61:51820/udp"), "vpn: home-wg"}}
	h.daemon = h.make(h.config(), func(sys *System) { sys.Learner = learned })
	h.daemon.Step(nil)
	if h.last().Endpoints[0] != (EndpointEntry{"198.51.100.61:51820/udp", "config: VPN, vpn: home-wg"}) {
		t.Fatal(h.last().Endpoints)
	}
}

func TestLearningOffDropsLearned(t *testing.T) {
	h := newHarness(t)
	config := h.config()
	config.Learn = Learn{Processes: []string{}}
	learned := fixedLearner{{MustEndpoint("45.67.89.20:443/tcp"), "connection: ExampleVPN"}, {MustEndpoint("9.9.9.9:51820/udp"), "vpn: x"}}
	d := h.make(config, func(sys *System) { sys.Learner = learned })
	if got := texts(d.endpoints()); slices.Contains(got, "45.67.89.20:443/tcp") || slices.Contains(got, "9.9.9.9:51820/udp") {
		t.Fatal(got)
	}
	d.config.Learn = Learn{VPNServices: true, Connections: true, Processes: []string{}}
	if got := texts(d.endpoints()); !slices.Contains(got, "45.67.89.20:443/tcp") || !slices.Contains(got, "9.9.9.9:51820/udp") {
		t.Fatal(got)
	}
}

func TestTurningOnRechecks(t *testing.T) {
	h := newHarness(t)
	h.mode(`{"mode": "off"}`)
	h.daemon.Step(nil)
	epoch := h.daemon.epoch
	h.mode(`{"mode": "on"}`)
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if h.daemon.epoch <= epoch || h.lastObserved() != fresh {
		t.Fatal(h.daemon.epoch, h.observed)
	}
}

func TestEnforcedInStatus(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	if !h.last().Enforced {
		t.Fatal("not enforced")
	}
	h.pf.failLoad = true
	h.uplinks = cafe
	h.daemon.Step(leaveEn0())
	if h.last().Enforced {
		t.Fatal("enforced after a failed load")
	}
}

func TestBridgedUplinkReported(t *testing.T) {
	h := newHarness(t)
	h.uplinks = withLink(home, "en0", func(l *Link) { l.Bridged = "bridge100" })
	h.daemon.Step(nil)
	if !h.hasError("en0 is a member of bridge100: bridged VMs bypass the switch") || h.last().Bridged["en0"] != "bridge100" {
		t.Fatal(h.last().Errors)
	}
}

func TestIdleThunderboltBridgeNotReported(t *testing.T) {
	h := newHarness(t)
	h.uplinks = withLink(home, "en1", func(l *Link) { l.Bridged = "bridge0" })
	h.daemon.Step(nil)
	if len(h.last().Errors) != 0 || len(h.last().Bridged) != 0 {
		t.Fatal(h.last().Errors, h.last().Bridged)
	}
}

func TestUnreadableRouterMACReported(t *testing.T) {
	h := newHarness(t)
	h.uplinks = map[string]Link{"en0": {Router: "192.168.1.1", V4: []string{"192.168.1.108/24"}},
		"en5": {Router: "10.0.0.1", V4: []string{"10.0.0.5/24"}}}
	h.expect(nil, StateBlocked)
	want := []string{"en0: the MAC of router 192.168.1.1 cannot be read, so its network cannot be verified"}
	if !reflect.DeepEqual(h.last().Errors, want) {
		t.Fatal(h.last().Errors)
	}
}

func TestErrorsLoggedOnce(t *testing.T) {
	var logged bytes.Buffer
	logger.SetOutput(&logged)
	defer logger.SetOutput(io.Discard)
	h := newHarness(t)
	h.uplinks = withLink(home, "en0", func(l *Link) { l.Bridged = "bridge100" })
	for range 3 {
		h.clocks.advance(1)
		h.daemon.Step(nil)
	}
	count := strings.Count(logged.String(), "bridge100")
	if count != 1 {
		t.Fatal(count)
	}
}

func TestSilentUplinkIsCheckedFreshAgain(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.uplinks = withLink(home, "en0", func(l *Link) { *l = Link{V4: l.V4, V6: l.V6, Silent: true} })
	h.daemon.Step(leaveEn0()) // the fresh check of en0 gets no answer
	h.uplinks = home
	h.clocks.advance(1)
	h.expect(nil, StateTrusted)
	if h.lastObserved() != fresh {
		t.Fatal("the next look reused the ARP cache:", h.observed)
	}
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if h.lastObserved().refresh {
		t.Fatal("still refreshing after en0 answered")
	}
}

func TestFailedCloseIsRetriedBeforeLooking(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.pf.failLoad = true
	h.daemon.Urgent(leaveEn0()[0])
	h.pf.failLoad = false
	h.pf.journal = nil
	h.uplinks = cafe
	h.clocks.advance(1)
	h.expect(nil, StateBlocked)
	if len(h.pf.journal) < 2 || h.pf.journal[0] != "load en0 open=false" || !slices.Contains(h.pf.journal, "observe") ||
		slices.Index(h.pf.journal, "observe") < 1 {
		t.Fatal(h.pf.journal)
	}
}

func TestUncheckedTunnelReportedAndClosed(t *testing.T) {
	h := newHarness(t)
	h.uplinks = cafe
	h.daemon = h.make(h.config(), func(sys *System) {
		sys.Tunnel = func() (*TunnelState, error) { return nil, errors.New("netstat: no answer") }
	})
	h.expect(nil, StateBlocked)
	if !h.hasError("the tunnel was not checked: netstat: no answer") {
		t.Fatal(h.last().Errors)
	}
}
