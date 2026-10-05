package guard

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// pf matches states before rules: whenever an uplink stops being open, the states
// that started from its addresses must go, after the closing rules are loaded.

func TestStatesDroppedAfterTheClose(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.pf.journal = nil
	h.uplinks = cafe
	h.daemon.Step(leaveEn0())
	if len(h.pf.journal) < 2 || h.pf.journal[0] != "load en0 open=false" || !strings.HasPrefix(h.pf.journal[1], "kill ") {
		t.Fatal(h.pf.journal)
	}
}

func TestStatesDroppedWhenARoutineLookLosesTrust(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.uplinks = cafe // no routing event: only the routine look notices
	h.clocks.advance(tick)
	h.expect(nil, StateBlocked)
	if !reflect.DeepEqual(h.pf.killedSet(), []string{"192.168.1.108", "192.168.1.57", "fd00:1:2::/64"}) {
		t.Fatal(h.pf.killed)
	}
}

func TestStatesDroppedForASelfTest(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.mode(fmt.Sprintf(`{"mode": "lock", "until": %d}`, int64(h.clocks.wall)+20))
	h.daemon.Step(nil)
	if !slices.Contains(h.pf.killed, "192.168.1.108") {
		t.Fatal(h.pf.killed)
	}
}

func TestStatesFromWhileOffDroppedWhenTurnedOn(t *testing.T) {
	h := newHarness(t)
	h.mode(`{"mode": "off"}`)
	h.uplinks = cafe
	h.daemon.Step(nil)
	if len(h.pf.killed) != 0 {
		t.Fatal("dropped while off:", h.pf.killed)
	}
	h.mode(`{"mode": "on"}`)
	h.clocks.advance(1)
	h.expect(nil, StateBlocked)
	if !reflect.DeepEqual(h.pf.killed, []string{"192.168.1.57"}) {
		t.Fatal(h.pf.killed)
	}
}

func TestStatesFromBeforeTheStartDropped(t *testing.T) {
	h := newHarness(t)
	h.uplinks = cafe
	h.expect(nil, StateBlocked)
	if !reflect.DeepEqual(h.pf.killed, []string{"192.168.1.57"}) {
		t.Fatal(h.pf.killed)
	}
	h.clocks.advance(tick)
	h.daemon.Step(nil)
	if len(h.pf.killed) != 1 {
		t.Fatal("dropped again:", h.pf.killed)
	}
}

func TestNothingDroppedWhileOpen(t *testing.T) {
	h := newHarness(t)
	for range 3 {
		h.clocks.advance(tick)
		h.daemon.Step(nil)
	}
	if len(h.pf.killed) != 0 {
		t.Fatal(h.pf.killed)
	}
}

func TestFailedDropRetriedAndReported(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.pf.failKill = true
	h.uplinks = cafe
	h.daemon.Step(leaveEn0())
	if h.last().Enforced || !h.hasError("pf states from 192.168.1.108 not dropped") {
		t.Fatalf("%+v", h.last())
	}
	h.pf.failKill = false
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if !h.last().Enforced || !reflect.DeepEqual(h.pf.killedSet(), []string{"192.168.1.108", "192.168.1.57", "fd00:1:2::/64"}) {
		t.Fatal(h.pf.killed, h.last().Errors)
	}
}

func TestAddressChangeOnATrustedUplinkDropsTheOldAddress(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.uplinks = withLink(home, "en0", func(l *Link) { l.V4 = []string{"192.168.1.109/24"} })
	h.clocks.advance(tick)
	h.expect(nil, StateTrusted)
	if !reflect.DeepEqual(h.pf.killed, []string{"192.168.1.108"}) {
		t.Fatal(h.pf.killed)
	}
}

func TestNewAddressAfterTurningOnIsDropped(t *testing.T) {
	h := newHarness(t)
	h.uplinks = cafe
	h.mode(`{"mode": "off"}`)
	h.daemon.Step(nil)
	h.uplinks = withLink(cafe, "en0", func(l *Link) { l.V4 = []string{"192.168.1.58/24"} }) // a new address while off…
	h.mode(`{"mode": "on"}`)                                                                // …first seen after turning on
	h.clocks.advance(1)
	h.expect(nil, StateBlocked)
	if !slices.Contains(h.pf.killed, "192.168.1.58") {
		t.Fatal(h.pf.killed)
	}
}
