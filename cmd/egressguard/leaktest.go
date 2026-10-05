package main

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sentiens/egressguard/internal/guard"
	"github.com/sentiens/egressguard/internal/leak"
)

// leakTargets are what the leak test tries to reach.
var leakTargets = append(slices.Clone(probeTargets), "https://example.com/")

// probeTimeout is how long each probe of the leak test may take.
const probeTimeout = 3 * time.Second

// leakTest captures every packet leaving the uplinks while no network is trusted,
// makes requests, and fails on any packet that got past the rules: on a closed
// uplink pf drops everything else before the capture sees it.
func (a *app) leakTest(args []string) error {
	seconds, safari, err := parseLeakArgs(args)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("leaktest captures packets: run it with sudo")
	}
	before, err := a.daemonAnswers()
	if err != nil {
		return err
	}
	uplinks, err := captureUplinks()
	if err != nil {
		return err
	}
	// The lock must outlast the probes, which run one after another, and the window.
	lockSeconds := int64(seconds) + int64(probeBudget(len(uplinks)).Seconds()) + 20
	if lockSeconds > 590 {
		return fmt.Errorf("a %d s test on %d uplinks needs a lock longer than 10 minutes", seconds, len(uplinks))
	}
	work, err := os.MkdirTemp("", "egressguard-leaktest.")
	if err != nil {
		return err
	}
	captures, err := startCaptures(work, uplinks, tcpdump)
	if err != nil {
		return err
	}
	defer captures.kill() // never leave a capture running, whatever happened
	time.Sleep(1500 * time.Millisecond)
	if err := captures.running(); err != nil {
		return err
	}

	a.printf("capturing on %s; nothing trusted for %d s\n", strings.Join(sortedKeys(uplinks), ", "), seconds)
	restore, err := a.lock(lockSeconds)
	if err != nil {
		return err
	}
	from, to, probeErr := a.probe(seconds, safari, uplinks)
	if err := restore(); err != nil {
		return err
	}
	time.Sleep(time.Second)
	if err := captures.stop(5 * time.Second); err != nil {
		return fmt.Errorf("inconclusive: %w", err)
	}
	if probeErr != nil {
		return fmt.Errorf("inconclusive: %w", probeErr)
	}

	data := map[string][]byte{}
	for name := range uplinks {
		if data[name], err = os.ReadFile(captures[name].file); err != nil {
			return fmt.Errorf("inconclusive: %s: %w", name, err)
		}
	}
	report, err := judge(data, uplinks, from, to, leakEndpoints(before), routersOf(before))
	if err != nil {
		return fmt.Errorf("inconclusive: %w", err)
	}
	after := a.waitFor(10*time.Second, func(s *statusFile) bool { return s.Mode != guard.ModeLock })
	a.printReport(report, to.Sub(from))
	a.printf("after the test: %s\n", describe(after))
	a.printf("the capture is kept in %s\n", work)
	if !report.clean() {
		return exitStatus(1)
	}
	return nil
}

func parseLeakArgs(args []string) (seconds int, safari bool, err error) {
	seconds = 20
	for _, arg := range args {
		if arg == "--safari" {
			safari = true
		} else if seconds, err = strconv.Atoi(arg); err != nil {
			return 0, false, usageError("usage: sudo egressguard leaktest [seconds] [--safari]")
		}
	}
	if seconds < 5 || seconds > 300 {
		return 0, false, usageError("leaktest runs for 5 to 300 seconds")
	}
	return seconds, safari, nil
}

// probeBudget is the most the probes of a leak test can take on this many uplinks.
func probeBudget(uplinks int) time.Duration {
	return time.Duration(uplinks+1)*time.Duration(len(leakTargets))*probeTimeout + 10*time.Second
}

// probe waits for the lock, makes requests for the given seconds, and checks the
// lock held to the end. It returns the window to judge.
func (a *app) probe(seconds int, safari bool, uplinks map[string]string) (from, to time.Time, err error) {
	locked := a.waitFor(10*time.Second, func(s *statusFile) bool { return s.Mode == guard.ModeLock })
	if locked == nil {
		return from, to, errors.New("the daemon did not enter the self-test")
	}
	if !locked.Enforced {
		return from, to, errors.New("the rules are not in force: " + strings.Join(locked.Errors, "; "))
	}
	time.Sleep(time.Second)
	watch := a.watchLock()
	from = time.Now()
	if uid := os.Getenv("SUDO_UID"); safari && uid != "" {
		exec.Command("/bin/launchctl", "asuser", uid, "/usr/bin/sudo", "-u", "#"+uid, "/usr/bin/open", "-g", "-a",
			"Safari", "https://example.com/?egressguard-leaktest").Run()
	}
	for _, name := range sortedKeys(uplinks) {
		reachable(name, leakTargets, probeTimeout)
	}
	reachable("", leakTargets, probeTimeout)
	exec.Command("/sbin/ping", "-c", "2", "-t", "3", "8.8.8.8").Run()
	exec.Command("/usr/bin/dig", "+time=2", "+tries=1", "@1.1.1.1", "example.com").Run()
	time.Sleep(time.Until(from.Add(time.Duration(seconds) * time.Second)))
	to = time.Now()
	return from, to, watch()
}

// watchLock checks the status every half second until the returned function is
// called, which says whether the lock held, with the rules in force, all along.
func (a *app) watchLock() (stop func() error) {
	done, result := make(chan struct{}), make(chan error, 1)
	go func() {
		var problem error
		for {
			switch status := a.readStatus(); {
			case problem != nil:
			case status == nil || status.Mode != guard.ModeLock || status.Age > 15*time.Second:
				problem = errors.New("the self-test ended before the capture window did")
			case !status.Enforced:
				problem = errors.New("the rules were not in force during the test")
			}
			select {
			case <-done:
				result <- problem
				return
			case <-time.After(a.pollEvery):
			}
		}
	}()
	return func() error {
		close(done)
		return <-result
	}
}

// captureUplinks are the uplinks with an address to capture on, by name, with their own MAC.
func captureUplinks() (map[string]string, error) {
	result := guard.Run([]string{"ifconfig"}, "", 0)
	if result.Failed() {
		return nil, fmt.Errorf("ifconfig: %s", result.Error())
	}
	uplinks := map[string]string{}
	for name, iface := range guard.Interfaces(result.Stdout) {
		if !guard.IsInternal(name) && iface.MAC != "" && (len(iface.V4) > 0 || hasGlobalV6(iface.V6)) {
			uplinks[name] = iface.MAC
		}
	}
	if len(uplinks) == 0 {
		return nil, errors.New("no uplink has an address")
	}
	return uplinks, nil
}

func hasGlobalV6(prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(text string) bool {
		prefix, err := netip.ParsePrefix(text)
		return err == nil && !prefix.Addr().IsLinkLocalUnicast()
	})
}

// --- captures --------------------------------------------------------------------------

// capture is one packet capture writing to file.
type capture struct {
	cmd    *exec.Cmd
	file   string
	exited chan struct{} // closed when the capture exits…
	err    error         // …with this
}

type captures map[string]*capture

// tcpdump captures every IP packet on an interface into file.
func tcpdump(iface, file string) *exec.Cmd {
	return exec.Command("/usr/sbin/tcpdump", "-n", "-U", "-i", iface, "-w", file, "ip or ip6")
}

// startCaptures starts a capture on every uplink, writing to dir.
func startCaptures(dir string, uplinks map[string]string, command func(iface, file string) *exec.Cmd) (captures, error) {
	started := captures{}
	for name := range uplinks {
		file := filepath.Join(dir, name+".pcap")
		c := &capture{cmd: command(name, file), file: file, exited: make(chan struct{})}
		if err := c.cmd.Start(); err != nil {
			started.kill()
			return nil, fmt.Errorf("capture on %s: %w", name, err)
		}
		go func() {
			c.err = c.cmd.Wait()
			close(c.exited)
		}()
		started[name] = c
	}
	return started, nil
}

// running fails if any capture has already stopped.
func (c captures) running() error {
	for _, name := range sortedKeys(c) {
		select {
		case <-c[name].exited:
			return fmt.Errorf("the capture on %s stopped early: %v", name, c[name].err)
		default:
		}
	}
	return nil
}

// stop asks every capture to finish and write out what it has. One that did not
// run to the end, or does not finish within timeout, makes the capture incomplete.
func (c captures) stop(timeout time.Duration) error {
	if err := c.running(); err != nil {
		return err
	}
	for _, capture := range c {
		capture.cmd.Process.Signal(syscall.SIGINT)
	}
	deadline := time.After(timeout)
	var problems []error
	for _, name := range sortedKeys(c) {
		capture := c[name]
		select {
		case <-capture.exited:
			if capture.err != nil {
				problems = append(problems, fmt.Errorf("the capture on %s failed: %w", name, capture.err))
			}
		case <-deadline:
			c.kill()
			return fmt.Errorf("the captures did not finish within %s", timeout)
		}
	}
	return errors.Join(problems...)
}

// kill ends every capture still running, and waits for it.
func (c captures) kill() {
	for _, capture := range c {
		select {
		case <-capture.exited:
		default:
			capture.cmd.Process.Kill()
			<-capture.exited
		}
	}
}

// --- judging -----------------------------------------------------------------------------

// leakKey groups the packets that got past the rules.
type leakKey struct {
	verdict, uplink, family, proto, destination string
	port                                        int
}

// leakReport counts the outgoing packets of a leak test by verdict.
type leakReport struct {
	counts map[string]int  // allowed, local, internet
	leaks  map[leakKey]int // everything not allowed
}

func (r leakReport) clean() bool { return r.counts["local"] == 0 && r.counts["internet"] == 0 }

// judge reads the captures (by uplink) and judges each packet the uplink sent
// (by its own MAC) between from and to.
func judge(data map[string][]byte, macs map[string]string, from, to time.Time, endpoints []leak.Endpoint,
	routers map[string]bool) (leakReport, error) {
	report := leakReport{counts: map[string]int{}, leaks: map[leakKey]int{}}
	start, end := float64(from.UnixNano())/1e9, float64(to.UnixNano())/1e9
	for _, name := range sortedKeys(data) {
		frames, err := leak.Frames(data[name])
		if err != nil {
			return report, fmt.Errorf("%s: %w", name, err)
		}
		for _, frame := range frames {
			packet := leak.ParseFrame(frame.Data)
			if packet == nil || packet.SrcMAC != macs[name] || frame.Time < start || frame.Time > end {
				continue
			}
			verdict := leak.Verdict(packet, endpoints, routers)
			report.counts[verdict]++
			if verdict != "allowed" {
				port := 0
				if packet.HasPorts {
					port = packet.Dport
				}
				report.leaks[leakKey{verdict, name, packet.Family, leak.ProtoName(packet.Proto), packet.Dst, port}]++
			}
		}
	}
	return report, nil
}

func (a *app) printReport(report leakReport, window time.Duration) {
	a.printf("outgoing packets in %.0f s: allowed %d, local %d, internet %d\n", window.Seconds(),
		report.counts["allowed"], report.counts["local"], report.counts["internet"])
	var keys []leakKey
	for key := range report.leaks {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(x, y leakKey) int {
		return cmp.Or(cmp.Compare(report.leaks[y], report.leaks[x]), cmp.Compare(fmt.Sprint(x), fmt.Sprint(y)))
	})
	for _, key := range keys[:min(len(keys), 15)] {
		where := "local, past the rules"
		if key.verdict == "internet" {
			where = "LEAK to the internet"
		}
		port := ""
		if key.port != 0 {
			port = ":" + strconv.Itoa(key.port)
		}
		a.printf("  %s: %s %s %s%s x%d\n", where, key.uplink, key.proto, key.destination, port, report.leaks[key])
	}
	switch {
	case report.clean():
		a.printf("RESULT: not a single packet got past the rules\n")
	case report.counts["internet"] > 0:
		a.printf("RESULT: LEAKS TO THE INTERNET, see above\n")
	default:
		a.printf("RESULT: nothing reached the internet, but local packets got past pf, see above\n")
	}
}

// leakEndpoints are the endpoints in force, as the leak verdict wants them.
func leakEndpoints(status *statusFile) []leak.Endpoint {
	var endpoints []leak.Endpoint
	for _, item := range status.Endpoints {
		if e, err := guard.ParseEndpoint(item.Endpoint, "endpoint"); err == nil {
			endpoints = append(endpoints, leak.Endpoint{Address: e.Address, Family: e.Family, Proto: e.Proto, Port: e.Port})
		}
	}
	return endpoints
}

func routersOf(status *statusFile) map[string]bool {
	routers := map[string]bool{}
	for _, link := range status.Uplinks {
		if link.Router != nil {
			routers[*link.Router] = true
		}
	}
	return routers
}
