package guard

import (
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

// StateDir is where the daemon keeps its files.
const StateDir = "/Library/Application Support/EgressGuard"

// StatePath is a file in StateDir.
func StatePath(name string) string { return StateDir + "/" + name }

const (
	scanProfilesEvery = 60.0                   // seconds between scans of the VPN configurations
	debounce          = 300 * time.Millisecond // lets a burst of joins settle
)

// NewSystem is the real Mac, with the daemon's files in StateDir.
func NewSystem(profiles EndpointSource) System {
	return System{
		Filter:   NewPF(Run, StatePath("pf-tokens")),
		Observe:  func(config Config, refresh bool) (map[string]Link, error) { return Observe(config, refresh, Run, true) },
		Tunnel:   func() (*TunnelState, error) { return TunnelStatus(Run) },
		Profiles: profiles,
		Wall:     wallClock,
		Awake:    Uptime,
		Asleep:   AsleepSeconds,
		Idle:     func() (float64, error) { return HIDIdle(Run) },
		Publish: func(status Status) {
			if err := WriteStatus(StatePath("status.json"), status); err != nil {
				logf("status not written: %v", err)
			}
		},
		LoadConfig:   LoadConfig,
		ConfigPath:   StatePath("config.json"),
		LastGoodPath: StatePath("settings.last-good.json"),
	}
}

func wallClock() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// RunDaemon is the root daemon. It returns when stopped by SIGTERM or SIGINT, or
// with an error when a step fails: launchd then starts it again, and a new daemon
// closes every uplink before anything else. Rules are never flushed on the way out.
func RunDaemon() error {
	syscall.Umask(0o022)
	if err := os.MkdirAll(StateDir, 0o755); err != nil {
		return err
	}
	config, err := LoadConfig(StatePath("config.json"))
	if err != nil {
		return err
	}
	profiles := NewProfiles(StatePath("resolved.json"), Run, ResolveHost)
	d := NewDaemon(config, NewSystem(profiles))
	events := newQueue(d)
	stop := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		d.Stop()
		close(stop)
	}()

	logf("started egressguard %s, anchor %s", Release, Anchor)
	var batch []*Event
	for first := true; ; first = false {
		if err := step(d, batch); err != nil {
			return err
		}
		if first { // the first step closed every uplink; now watch
			go watchRoutes(events.add, stop)
			WatchPower(d.Seal, func() { events.add(&Event{Kind: EventWake}) }, d.SetPowerWatch)
			go scanProfiles(d, profiles, stop)
		}
		select {
		case <-stop:
			logf("stopping; the rules stay loaded")
			return nil
		default:
		}
		batch = events.next(stop)
	}
}

// step runs one Step; a panic is logged with its stack and returned as an error.
func step(d *Daemon, events []*Event) (err error) {
	defer func() {
		if failure := recover(); failure != nil {
			logf("step failed: %v\n%s", failure, debug.Stack())
			func() {
				defer func() {
					if again := recover(); again != nil {
						logf("off fallback failed too: %v", again)
					}
				}()
				d.FallbackOff()
			}()
			err = fmt.Errorf("step failed: %v", failure)
		}
	}()
	d.Step(events)
	return nil
}

// queue collects events from the route monitor and the power watch for the next step.
type queue struct {
	daemon *Daemon
	mu     sync.Mutex
	events []*Event
	wake   chan struct{}
}

func newQueue(d *Daemon) *queue { return &queue{daemon: d, wake: make(chan struct{}, 1)} }

// add closes the network at once for a leave of a trusted uplink, then queues the event.
func (q *queue) add(event *Event) {
	if event == nil {
		return
	}
	q.daemon.Urgent(event)
	q.mu.Lock()
	q.events = append(q.events, event)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// next waits up to a second for events and returns them; a burst of joins is
// given a moment to settle, a leave is not delayed.
func (q *queue) next(stop <-chan struct{}) []*Event {
	if q.length() == 0 {
		select {
		case <-q.wake:
		case <-stop:
		case <-time.After(time.Second):
		}
	}
	if q.onlyJoins() {
		time.Sleep(debounce)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	events := q.events
	q.events = nil
	select {
	case <-q.wake:
	default:
	}
	return events
}

func (q *queue) length() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.events)
}

func (q *queue) onlyJoins() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, event := range q.events {
		if event.Kind != EventJoin {
			return false
		}
	}
	return len(q.events) > 0
}

// scanProfiles reads the VPN configurations macOS has every minute, while the
// policy takes their servers; one that macOS did not answer is retried next tick.
func scanProfiles(d *Daemon, profiles *Profiles, stop <-chan struct{}) {
	last := -scanProfilesEvery
	for {
		if now := wallClock(); d.Config().VPNConfigurations && now-last >= scanProfilesEvery {
			uplinks, tunnel := d.Snapshot()
			// Host names resolve only where DNS works: a trusted network or a tunnel.
			if err := profiles.Scan(len(trustedNames(uplinks)) > 0 || tunnel != nil); err != nil {
				logf("vpn configurations not read: %v", err)
			} else {
				last = now
			}
		}
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(tick * float64(time.Second))):
		}
	}
}

// CheckResult is the installer's dry run.
type CheckResult struct {
	State       string                `json:"state"`
	Tunnel      *TunnelState          `json:"tunnel"`
	Uplinks     map[string]StatusLink `json:"uplinks"`
	SyntaxOK    bool                  `json:"syntax_ok"`
	SyntaxError string                `json:"syntax_error"`
}

// Check is what the switch would decide here and now with the config at path, and
// whether pfctl accepts the rules. It loads nothing.
func Check(path string) (CheckResult, error) {
	config, err := LoadConfig(path)
	if err != nil {
		return CheckResult{}, err
	}
	if settings, err := LoadSettings(SettingsPath(config)); err == nil {
		config = Effective(config, settings)
	}
	uplinks, err := Observe(config, false, Run, true)
	if err != nil {
		return CheckResult{}, err
	}
	var endpoints []Endpoint
	for _, tunnel := range config.Tunnels {
		endpoints = append(endpoints, tunnel.Endpoints...)
	}
	syntax := Run([]string{"pfctl", "-n", "-f", "-"}, Render(uplinks, endpoints, true), 0)
	message := strings.TrimSpace(syntax.Stderr)
	if len(message) > 500 {
		message = message[len(message)-500:]
	}
	tunnel, err := TunnelStatus(Run)
	if err != nil {
		return CheckResult{}, err
	}
	result := CheckResult{State: StateOf(Control{Mode: ModeOn}, uplinks, tunnel, true),
		Tunnel: tunnel, Uplinks: map[string]StatusLink{}, SyntaxOK: !syntax.Failed(), SyntaxError: message}
	for name, link := range uplinks {
		result.Uplinks[name] = StatusLink{optional(link.Router), optional(link.MAC), link.Trusted, optional(link.Network)}
	}
	return result, nil
}
