package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/sentiens/egressguard/internal/guard"
)

// probeTargets answer a plain HTTPS request; any answer means the request got out.
var probeTargets = []string{"https://1.1.1.1/cdn-cgi/trace", "https://www.apple.com/library/test/success.html"}

// reachable reports whether any target answers, bypassing proxies, through iface if
// set. A request that fails is an answer; curl that cannot run is an error.
func reachable(iface string, targets []string, timeout time.Duration) (bool, error) {
	for _, url := range targets {
		args := []string{"--noproxy", "*", "-sS", "-o", "/dev/null", "-m", strconv.Itoa(int(timeout.Seconds())), url}
		if iface != "" {
			args = append([]string{"--interface", iface}, args...)
		}
		failed, err := attempt(exec.Command("/usr/bin/curl", args...))
		if err != nil {
			return false, err
		}
		if !failed {
			return true, nil
		}
	}
	return false, nil
}

// attempt runs a probe that may well fail: it reports whether the probe exited
// non-zero, and errs only if it could not run.
func attempt(cmd *exec.Cmd) (failed bool, err error) {
	var exit *exec.ExitError
	if err := cmd.Run(); errors.As(err, &exit) {
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("%s: %w", cmd.Path, err)
	}
	return false, nil
}

// daemonAnswers is the current status, or an error if the daemon is not running.
func (a *app) daemonAnswers() (*statusFile, error) {
	status, err := a.readStatus()
	if err != nil {
		return nil, err
	}
	if status.Age > 30*time.Second {
		return nil, fmt.Errorf("the daemon has not reported for %.0f s; nothing to test", status.Age.Seconds())
	}
	return status, nil
}

// lock makes the daemon trust no network until the returned restore runs.
func (a *app) lock(seconds int64) (restore func() error, err error) {
	path, err := a.controlPath()
	if err != nil {
		return nil, err
	}
	previous, err := readUserJSON(path)
	if err != nil {
		return nil, err
	}
	if err := a.writeControl(map[string]any{"mode": guard.ModeLock, "until": time.Now().Unix() + seconds}); err != nil {
		return nil, err
	}
	return func() error { return a.restoreControl(previous) }, nil
}

// selfTest pretends no network is trusted for a few seconds and proves that a direct
// request fails.
func (a *app) selfTest() error {
	before, err := a.daemonAnswers()
	if err != nil {
		return err
	}
	uplink := firstUplink(before)
	a.printf("now: %s\n", describe(before))
	if before.State == guard.StateTrusted || before.State == guard.StateOff {
		direct := false
		if uplink != "" {
			if direct, err = reachable(uplink, probeTargets, 4*time.Second); err != nil {
				return err
			}
		}
		if !direct {
			a.printf("a direct request fails even without the block: the test would prove nothing\n")
			return exitStatus(1)
		}
	}
	restore, err := a.lock(30)
	if err != nil {
		return err
	}
	ok, probeErr := a.probeLocked(uplink)
	if err := errors.Join(probeErr, restore()); err != nil {
		return err
	}
	after, err := a.waitFor(10*time.Second, func(s *statusFile) bool { return s.Mode != guard.ModeLock })
	if err != nil {
		a.printf("after the test: the daemon did not leave the self-test: %v\n", err)
		ok = false
	} else {
		a.printf("after the test: %s\n", describe(after))
		if after.State == guard.StateTrusted || after.State == guard.StateOff {
			back, err := reachable("", probeTargets, 4*time.Second)
			if err != nil {
				return err
			}
			a.printf("internet again: %s\n", map[bool]string{true: "yes", false: "NO"}[back])
			ok = ok && back
		}
	}
	if !ok {
		a.printf("RESULT: something is wrong, see above\n")
		return exitStatus(1)
	}
	a.printf("RESULT: the switch works\n")
	return nil
}

// probeLocked checks, during a lock, that a direct request fails and the tunnel works.
func (a *app) probeLocked(uplink string) (bool, error) {
	locked, err := a.waitFor(10*time.Second, func(s *statusFile) bool { return s.Mode == guard.ModeLock })
	if err != nil {
		a.printf("FAIL: the daemon did not enter the self-test within 10 s: %v\n", err)
		return false, nil
	}
	time.Sleep(time.Second)
	direct := false
	if uplink != "" {
		if direct, err = reachable(uplink, probeTargets, 4*time.Second); err != nil {
			return false, err
		}
	}
	a.printf("direct request through %s: %s\n", orDefault(uplink, "?"),
		map[bool]string{true: "GOT THROUGH: a leak", false: "blocked"}[direct])
	if locked.Tunnel == nil {
		return !direct, nil
	}
	through, err := reachable("", probeTargets, 4*time.Second)
	if err != nil {
		return false, err
	}
	a.printf("request through the tunnel (%s): %s\n", locked.Tunnel.Interface,
		map[bool]string{true: "works", false: "failed"}[through])
	return !direct && through, nil
}

// firstUplink is a trusted uplink if there is one, else the first with a router.
func firstUplink(status *statusFile) string {
	for _, entry := range status.Trusted {
		return entry.Interface
	}
	if names := sortedKeys(status.Uplinks); len(names) > 0 {
		return names[0]
	}
	return ""
}
