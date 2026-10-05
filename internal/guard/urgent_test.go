package guard

import (
	"sync"
	"testing"
)

func TestLeaveClosesAtOnceAndIsNotRepeated(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	event := leaveEn0()[0]
	epoch := h.daemon.epoch
	h.daemon.Urgent(event)
	if en0Open(h.pf.current) || h.daemon.epoch != epoch+1 {
		t.Fatal("not closed at once")
	}
	h.uplinks = cafe
	h.expect([]*Event{event}, StateBlocked)
	if h.daemon.epoch != epoch+1 {
		t.Fatal("trust broken twice")
	}
}

func TestUrgentIgnoresUnrelatedEvents(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	loads := len(h.pf.loads)
	h.daemon.Urgent(&Event{Kind: EventLeave, Names: names("en5")})
	h.daemon.Urgent(join()[0])
	if len(h.pf.loads) != loads {
		t.Fatal("rules reloaded")
	}
}

func TestObservationDuringAnUrgentLeaveIsDiscarded(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.sys.Observe = func(Config, bool) (map[string]Link, error) {
		h.daemon.Urgent(leaveEn0()[0]) // the Wi-Fi changes while the step observes
		return home, nil
	}
	h.clocks.advance(tick)
	h.expect(nil, StateBlocked)
}

func TestStoppingDaemonLoadsNothing(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	loads := len(h.pf.loads)
	h.daemon.Stop()
	h.uplinks = cafe
	h.daemon.Step(leaveEn0())
	if len(h.pf.loads) != loads {
		t.Fatal("loaded while stopping")
	}
}

// TestConcurrentStepUrgentAndSeal runs the daemon's three entry points at once, as
// the main goroutine, the route monitor and the IOKit thread do; with -race it
// checks the locking.
func TestConcurrentStepUrgentAndSeal(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.daemon.sys.Observe = func(Config, bool) (map[string]Link, error) { return home, nil }
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		for range 200 {
			h.daemon.Step(nil)
		}
	}()
	go func() {
		defer wait.Done()
		for range 200 {
			h.daemon.Urgent(leaveEn0()[0])
		}
	}()
	go func() {
		defer wait.Done()
		for range 50 {
			h.daemon.Seal()
		}
	}()
	wait.Wait()
	if !h.daemon.isSealed() {
		t.Fatal("the seal was lost")
	}
}
