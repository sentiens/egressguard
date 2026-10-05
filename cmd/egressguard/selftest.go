package main

import (
	"errors"
	"os/exec"
	"strconv"
	"time"

	"github.com/sentiens/egressguard/internal/guard"
)

// probeTargets answer a plain HTTPS request; any answer means the request got out.
var probeTargets = []string{"https://1.1.1.1/cdn-cgi/trace", "https://www.apple.com/library/test/success.html"}

// reachable reports whether any target answers, bypassing proxies, through iface if set.
func reachable(iface string, targets []string, timeout time.Duration) bool {
	for _, url := range targets {
		args := []string{"--noproxy", "*", "-sS", "-o", "/dev/null", "-m", strconv.Itoa(int(timeout.Seconds())), url}
		if iface != "" {
			args = append([]string{"--interface", iface}, args...)
		}
		if exec.Command("/usr/bin/curl", args...).Run() == nil {
			return true
		}
	}
	return false
}

// daemonAnswers is the current status, or an error if the daemon is not running.
func (a *app) daemonAnswers() (*statusFile, error) {
	status := a.readStatus()
	if status == nil || status.Age > 30*time.Second {
		return nil, errors.New("the daemon does not answer; nothing to test")
	}
	return status, nil
}

// lock makes the daemon trust no network until the returned restore runs.
func (a *app) lock(seconds int64) (restore func() error, err error) {
	previous := readUserJSON(a.controlPath())
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
	if (before.State == guard.StateTrusted || before.State == guard.StateOff) && (uplink == "" || !reachable(uplink, probeTargets, 4*time.Second)) {
		a.printf("a direct request fails even without the block: the test would prove nothing\n")
		return exitStatus(1)
	}
	restore, err := a.lock(30)
	if err != nil {
		return err
	}
	ok := a.probeLocked(uplink)
	if err := restore(); err != nil {
		return err
	}
	after := a.waitFor(10*time.Second, func(s *statusFile) bool { return s.Mode != guard.ModeLock })
	a.printf("after the test: %s\n", describe(after))
	if after != nil && (after.State == guard.StateTrusted || after.State == guard.StateOff) {
		back := reachable("", probeTargets, 4*time.Second)
		a.printf("internet again: %s\n", map[bool]string{true: "yes", false: "NO"}[back])
		ok = ok && back
	}
	if !ok {
		a.printf("RESULT: something is wrong, see above\n")
		return exitStatus(1)
	}
	a.printf("RESULT: the switch works\n")
	return nil
}

// probeLocked checks, during a lock, that a direct request fails and the tunnel works.
func (a *app) probeLocked(uplink string) bool {
	locked := a.waitFor(10*time.Second, func(s *statusFile) bool { return s.Mode == guard.ModeLock })
	if locked == nil {
		a.printf("FAIL: the daemon did not enter the self-test within 10 s\n")
		return false
	}
	time.Sleep(time.Second)
	direct := uplink != "" && reachable(uplink, probeTargets, 4*time.Second)
	a.printf("direct request through %s: %s\n", orDefault(uplink, "?"),
		map[bool]string{true: "GOT THROUGH: a leak", false: "blocked"}[direct])
	if locked.Tunnel == nil {
		return !direct
	}
	through := reachable("", probeTargets, 4*time.Second)
	a.printf("request through the tunnel (%s): %s\n", locked.Tunnel.Interface,
		map[bool]string{true: "works", false: "failed"}[through])
	return !direct && through
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
