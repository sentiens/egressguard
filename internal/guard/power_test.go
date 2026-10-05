package guard

import (
	"errors"
	"slices"
	"testing"
)

func TestSealClosesBeforeSleep(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Seal()
	if en0Open(h.pf.current) || !slices.Contains(h.pf.killed, "192.168.1.108") {
		t.Fatal("not sealed")
	}
	h.clocks.advance(1)
	h.expect(nil, StateBlocked) // still awake, same network, but sealed
	h.clocks.advance(5)
	h.expect(nil, StateBlocked)
}

func TestDarkWakeElsewhereStaysClosedUntilAFullWake(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Seal()
	h.clocks.advance(1)
	h.daemon.Step(nil) // an observation at home right after the seal must not survive the night
	h.clocks.sleep(3600)
	h.uplinks = cafe
	h.clocks.advance(1)
	h.expect(nil, StateBlocked)
	h.uplinks = home2
	h.clocks.advance(1)
	h.expect(nil, StateBlocked) // trusted, but not the network of the seal
	if !h.last().Sealed {
		t.Fatal("not sealed")
	}
	h.clocks.advance(1)
	h.expect(wakeUp(), StateTrusted)
	if h.lastObserved() != fresh {
		t.Fatal(h.observed)
	}
}

func TestDarkWakeOnTheSameNetwork(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Seal()
	h.clocks.sleep(3600)
	h.clocks.advance(1)
	h.expect(nil, StateTrusted) // Wake on Demand at home works…
	if h.lastObserved() != fresh || !h.last().Sealed {
		t.Fatal(h.observed) // …after a fresh check
	}
}

func TestWakeElsewhereStaysClosed(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Seal()
	h.clocks.advance(1)
	h.daemon.Step(nil)
	h.clocks.sleep(3600)
	h.uplinks = cafe
	h.clocks.advance(1)
	h.expect(wakeUp(), StateBlocked)
	if en0Open(h.pf.current) {
		t.Fatal("open")
	}
}

func TestInputAfterTheSealUnseals(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Seal()
	h.clocks.sleep(600)
	h.uplinks = home2
	h.clocks.advance(2)
	h.expect(nil, StateBlocked)
	h.clocks.touch()
	h.clocks.advance(0.5)
	h.expect(nil, StateTrusted)
}

func TestInputBeforeTheSealDoesNotUnseal(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.clocks.touch()
	h.clocks.advance(5)
	h.daemon.Seal()
	h.clocks.sleep(600)
	h.clocks.advance(1)
	h.uplinks = home2
	h.expect(nil, StateBlocked) // the last input was before the seal
}

func TestSleepSeenOnTheClocksWithoutANotice(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.clocks.sleep(1800)
	h.uplinks = home2
	h.clocks.advance(1)
	h.expect(nil, StateBlocked)
	if !h.last().Sealed {
		t.Fatal("not sealed")
	}
	h.clocks.advance(1)
	h.clocks.touch()
	h.clocks.advance(0.5)
	h.expect(nil, StateTrusted)
}

func TestSealLimit(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.Seal()
	h.clocks.advance(sealLimit + 1)
	h.expect(nil, StateTrusted)
	if !h.hasError("no full wake") {
		t.Fatal(h.last().Errors)
	}
	h.clocks.advance(1)
	h.daemon.Step(wakeUp())
	if h.hasError("no full wake") {
		t.Fatal("the note outlives a full wake")
	}
}

func TestWakeWithoutASealStillRechecks(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.clocks.advance(1)
	h.daemon.Step(wakeUp())
	if h.lastObserved() != fresh {
		t.Fatal(h.observed)
	}
}

func TestUnreadableInputStaysSealedUntilAWake(t *testing.T) {
	h := newHarness(t)
	h.daemon = h.make(h.config(), func(sys *System) {
		sys.Idle = func() (float64, error) { return 0, errors.New("ioreg: no answer") }
	})
	h.daemon.Step(nil)
	h.daemon.Seal()
	h.clocks.sleep(600)
	h.uplinks = home2
	h.clocks.touch()
	h.clocks.advance(1)
	h.expect(nil, StateBlocked)
	if !h.hasError("keyboard and mouse input not read, so only a wake notice unseals: ioreg: no answer") {
		t.Fatal(h.last().Errors)
	}
	h.clocks.advance(1)
	h.expect(wakeUp(), StateTrusted)
	if h.hasError("keyboard and mouse input") {
		t.Fatal("the problem outlived the seal")
	}
}
