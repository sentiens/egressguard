package guard

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Timing of the decision loop, in seconds.
const (
	tick         = 10.0  // between routine observations
	follow       = 15.0  // after a change, observations every second for this long
	verifyEvery  = 2.0   // pf's anchor is checked this often
	sleptAtLeast = 1.0   // seconds asleep on the clocks that count as a sleep
	sealLimit    = 600.0 // awake seconds a seal may last without any sign of a full wake
	silentLimit  = 15.0  // seconds the network tools may stay silent before trust goes
)

// System is what the daemon needs from the Mac. Production code uses
// NewSystem; tests pass fakes.
type System struct {
	Filter     Filter
	Observe    func(config Config, refresh bool) (map[string]Link, error)
	Tunnel     func() (*TunnelState, error)
	Learner    EndpointSource          // nil: nothing is learned
	Wall       func() float64          // seconds since the epoch
	Awake      func() float64          // seconds awake since boot; stops while the Mac sleeps
	Asleep     func() float64          // seconds asleep since boot
	Idle       func() (float64, error) // seconds since the last keyboard or mouse input
	Publish    func(Status)            // writes status.json
	LoadConfig func(path string) (Config, error)

	ConfigPath   string // the administrator's config, re-read when it changes; "" for none
	LastGoodPath string // a copy of the last good user settings; "" for none
}

type sealedNetwork struct{ network, mac string }

// Daemon is the decision loop. Step runs about once a second on one goroutine;
// Urgent runs on the route-monitor goroutine and Seal on the IOKit run-loop
// thread. Every decision that loads rules holds mu, so a sealed network is never
// reopened by an observation made before the seal; nothing slow (observing,
// writing the status) happens while mu is held.
type Daemon struct {
	sys      System
	stopping atomic.Bool

	mu sync.Mutex // guards the fields below, except those marked as Step's own

	// The policy.
	admin, config Config // the administrator's config; the policy in force
	settings      *Settings
	configError   string
	settingsError string
	mode          string // the switch's mode at the last step

	// What was seen.
	uplinks     map[string]Link
	tunnel      *TunnelState
	lastObserve float64 // awake seconds
	silent      bool    // the network tools stopped answering…
	silentSince float64 // …at this time

	// Trust: each break starts a new epoch, and trust needs an observation made
	// in the current one.
	epoch, closedEpoch int
	closePending       bool            // the last close did not load: try again first thing
	needRefresh        bool            // every uplink needs a fresh check
	recheck            map[string]bool // uplinks whose fresh check got no answer
	followUntil        float64

	// Sleep.
	sealed         bool
	sealedAt       float64
	sealNetworks   map[string]sealedNetwork // the networks trusted when the seal began
	sleptSinceSeal bool
	sealNote       string
	idleProblem    string // why input could not be read while sealed
	clocksRead     bool
	sleptSeen      float64 // asleep seconds at the last step
	lastStep       float64 // awake seconds at the last step
	powerWatch     *bool

	// pf.
	token         bool    // we hold a pf reference
	applied       *string // the anchor's rules ("" for none); nil when unknown
	lastVerify    float64
	lastEnabled   float64
	enableProblem string          // what the last check of pf being on found
	attachProblem string          // what the last check of the main ruleset found
	open          map[string]bool // state sources pf lets through directly
	known         map[string]bool // state sources the daemon has seen
	revoke        map[string]bool // state sources whose pf states must still be dropped

	// Step's own: only the goroutine running Step uses these.
	configStamp, settingsStamp string
	lastConfigCheck            float64
	lastState                  string
	lastErrors                 []string
	lastStatus                 *Status
}

// NewDaemon makes a daemon for the administrator's config.
func NewDaemon(config Config, sys System) *Daemon {
	d := &Daemon{
		sys:     sys,
		admin:   config,
		config:  Effective(config, DefaultSettings()),
		uplinks: map[string]Link{},
		epoch:   1, needRefresh: true,
		lastObserve: -1e9, lastVerify: -1e9, lastEnabled: -1e9, lastConfigCheck: -1e9,
		recheck:    map[string]bool{},
		revoke:     map[string]bool{},
		lastErrors: []string{},
	}
	if sys.ConfigPath != "" {
		d.configStamp = fileStamp(sys.ConfigPath)
	}
	return d
}

// Stop makes the daemon load no more rules: the uninstaller is about to flush them.
func (d *Daemon) Stop() { d.stopping.Store(true) }

// SetPowerWatch records whether sleep notifications work.
func (d *Daemon) SetPowerWatch(ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.powerWatch = &ok
}

// Config is the policy in force.
func (d *Daemon) Config() Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.config
}

// Step is one pass over the routing and power events since the last one. It
// returns the state: off, trusted, tunnel or blocked.
func (d *Daemon) Step(events []*Event) string {
	now := d.sys.Awake()
	if now-d.lastConfigCheck >= tick {
		d.lastConfigCheck = now
		d.reloadConfig()
	}
	d.reloadSettings()
	control := ReadControl(d.Config().Control, d.sys.Wall())
	errs := d.react(control, events, now)
	errs = append(errs, d.look(len(events) > 0, now)...)
	status := d.enforce(control, errs)
	d.publish(status)
	return status.State
}

// react follows the switch, power events and leaves, and closes the network at
// once if any of them broke trust.
func (d *Daemon) react(control Control, events []*Event, now float64) []string {
	idle, idleKnown, idleProblem := 0.0, false, ""
	if d.isSealed() {
		var err error // ioreg, outside the lock
		if idle, err = d.sys.Idle(); err != nil {
			idleProblem = "keyboard and mouse input not read, so only a wake notice unseals: " + err.Error()
		} else {
			idleKnown = true
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mode == ModeOff && control.Mode != ModeOff {
		d.breakTrust("switch turned on")
	}
	d.mode = control.Mode
	d.checkPower(events, now, idle, idleKnown)
	d.idleProblem = ""
	if d.sealed { // the input matters only while sealed
		d.idleProblem = idleProblem
	}
	for _, event := range events {
		if event.Kind == EventLeave && !event.Handled && d.affectsTrust(event) {
			d.breakTrust(event.String() + " changed")
			break
		}
	}
	return d.closeNow(control)
}

// look observes the uplinks when something happened, when trust needs a fresh
// check, or when it is time. An observation overtaken by a trust break proves nothing.
func (d *Daemon) look(happened bool, now float64) []string {
	d.mu.Lock()
	epoch, config, had := d.epoch, d.config, trustedNames(d.uplinks)
	refresh := d.needRefresh || len(d.recheck) > 0
	interval := tick
	if now < d.followUntil {
		interval = 1
	}
	due := happened || refresh || now-d.lastObserve >= interval
	d.mu.Unlock()
	if !due {
		return nil
	}

	uplinks, err := d.sys.Observe(config, refresh)
	var tunnel *TunnelState
	var tunnelErr error
	if uplinks != nil {
		tunnel, tunnelErr = d.sys.Tunnel()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if uplinks == nil {
		return d.unanswered(err, now)
	}
	var problems []string
	if err != nil { // some uplinks did not answer: they stay closed until they do
		problems = append(problems, fmt.Sprintf("no answer from %v", err))
		d.followUntil = max(d.followUntil, d.sys.Awake()+follow)
	}
	if tunnelErr != nil {
		problems = append(problems, "the tunnel was not checked: "+tunnelErr.Error())
	}
	d.silent = false
	if epoch != d.epoch {
		uplinks = Distrust(uplinks)
	} else if refresh {
		// The check was fresh for the uplinks that answered; one that did not
		// still needs one, however later observations go.
		d.needRefresh = false
		for name, link := range uplinks {
			if link.Silent {
				d.recheck[name] = true
			} else {
				delete(d.recheck, name)
			}
		}
	}
	d.uplinks, d.tunnel, d.lastObserve = uplinks, tunnel, d.sys.Awake()
	trusted := trustedNames(uplinks)
	if slices.ContainsFunc(had, func(name string) bool { return !slices.Contains(trusted, name) }) {
		d.followUntil = max(d.followUntil, d.sys.Awake()+follow)
	}
	return problems
}

// unanswered keeps the last observation when the network tools do not answer,
// but not for long: after silentLimit seconds nothing is trusted. Hold d.mu.
func (d *Daemon) unanswered(err error, now float64) []string {
	d.followUntil = max(d.followUntil, d.sys.Awake()+follow)
	if !d.silent {
		d.silent, d.silentSince = true, now
	}
	if now-d.silentSince > silentLimit && !d.needRefresh && len(trustedNames(d.uplinks)) > 0 {
		d.breakTrust(fmt.Sprintf("the network tools have not answered for %.0f s", now-d.silentSince))
	}
	return []string{fmt.Sprintf("no answer from %v; keeping the last observation", err)}
}

// enforce loads the rules for what is known now and describes the result.
func (d *Daemon) enforce(control Control, errs []string) Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	trust := control.Mode != ModeLock && !d.needRefresh
	view := d.view()
	endpoints := d.endpoints()
	rules := ""
	if control.Mode != ModeOff {
		rules = Render(view, endpointsOnly(endpoints), trust)
	}
	failures := d.apply(rules, view, trust, false)
	enforced := len(failures) == 0 && same(d.applied, rules)
	errs = slices.Concat(errs, failures, d.notes())
	return d.status(control, view, trust, endpoints, errs, enforced)
}

// Urgent runs on the route-monitor goroutine: a trusted uplink changed, so the
// network closes now, not after the step in progress.
func (d *Daemon) Urgent(event *Event) {
	if event.Kind != EventLeave {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.affectsTrust(event) {
		return
	}
	event.Handled = true
	d.breakTrust(event.String() + " changed")
	logAll(d.closeNow(ReadControl(d.config.Control, d.sys.Wall())))
}

// Seal runs on the power thread before the system sleeps: every uplink closes
// until a full wake.
func (d *Daemon) Seal() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seal(d.sys.Awake())
	d.breakTrust("system going to sleep")
	logAll(d.closeNow(ReadControl(d.config.Control, d.sys.Wall())))
}

// Snapshot is the uplinks as far as they are trusted now, and the tunnel.
func (d *Daemon) Snapshot() (map[string]Link, *TunnelState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sealed || d.needRefresh || d.mode == ModeLock {
		return Distrust(d.uplinks), d.tunnel
	}
	return maps.Clone(d.uplinks), d.tunnel
}

// FallbackOff flushes the rules if the switch is off: a failing daemon must never
// strand an off switch.
func (d *Daemon) FallbackOff() {
	if ReadControl(d.Config().Control, d.sys.Wall()).Mode != ModeOff {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.sys.Filter.Load(""); err == nil {
		empty := ""
		d.applied = &empty
	}
}

func (d *Daemon) isSealed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sealed
}

func logAll(messages []string) {
	for _, message := range messages {
		logf("%s", message)
	}
}

// --- trust ------------------------------------------------------------------------

// breakTrust: no uplink is trusted until an observation that starts now says so. Hold d.mu.
func (d *Daemon) breakTrust(reason string) {
	d.epoch++
	d.needRefresh = true
	d.followUntil = d.sys.Awake() + follow
	logf("trust revoked: %s", reason)
}

// affectsTrust reports whether an event concerns a trusted uplink. Hold d.mu.
func (d *Daemon) affectsTrust(event *Event) bool {
	for name, link := range d.uplinks {
		// An interface that cannot be named any more (a tunnel just destroyed) is not
		// a trusted uplink; the follow-up observation still sees every change.
		if link.Trusted && (event.Names[name] || (event.Gateway != "" && event.Gateway == link.Router)) {
			return true
		}
	}
	return false
}

// closeNow closes every uplink if trust was broken since the last close, or the
// last close did not load. The closing rules are loaded before anything is
// checked, so they are in place after one pfctl call. Hold d.mu.
func (d *Daemon) closeNow(control Control) []string {
	if d.closedEpoch == d.epoch && !d.closePending {
		return nil
	}
	d.closedEpoch, d.closePending = d.epoch, false
	if control.Mode == ModeOff || d.stopping.Load() {
		return nil
	}
	rules := Render(d.uplinks, endpointsOnly(d.endpoints()), false)
	if !same(d.applied, rules) {
		if err := d.sys.Filter.Load(rules); err != nil {
			d.applied, d.closePending = nil, true
			return []string{"pf anchor load failed: " + err.Error()}
		}
		d.applied = &rules
	}
	return d.apply(rules, d.uplinks, false, true)
}

// view is the uplinks as far as they may be trusted now. Sealed (asleep or in a
// dark wake), only a network trusted when the seal began counts, and only after a
// sleep: Wake on Demand and Bonjour Sleep Proxy keep working at home. Hold d.mu.
func (d *Daemon) view() map[string]Link {
	if !d.sealed {
		return d.uplinks
	}
	view := make(map[string]Link, len(d.uplinks))
	for name, link := range d.uplinks {
		before, known := d.sealNetworks[name]
		if !d.sleptSinceSeal || !link.Trusted || !known || before != (sealedNetwork{link.Network, link.MAC}) {
			link = link.untrusted()
		}
		view[name] = link
	}
	return view
}

// endpoints are the configured tunnels first, then the learned endpoints the
// policy allows, one entry per endpoint with all its sources. Hold d.mu.
func (d *Daemon) endpoints() []Sourced {
	var found []Sourced
	for _, tunnel := range d.config.Tunnels {
		for _, endpoint := range tunnel.Endpoints {
			found = append(found, Sourced{endpoint, "config: " + tunnel.Name})
		}
	}
	if d.sys.Learner != nil {
		learn := d.config.Learn
		for _, item := range d.sys.Learner.Endpoints(d.sys.Wall()) {
			if (strings.HasPrefix(item.Source, "vpn: ") && learn.VPNServices) ||
				(strings.HasPrefix(item.Source, "connection: ") && learn.Connections) {
				found = append(found, item)
			}
		}
	}
	var unique []Sourced
	index := map[string]int{}
	for _, item := range found {
		key := item.Endpoint.String()
		i, seen := index[key]
		switch {
		case !seen:
			index[key] = len(unique)
			unique = append(unique, item)
		case !slices.Contains(strings.Split(unique[i].Source, ", "), item.Source):
			unique[i].Source += ", " + item.Source
		}
	}
	return unique
}

// --- helpers ------------------------------------------------------------------------

func trustedNames(uplinks map[string]Link) []string {
	var names []string
	for name, link := range uplinks {
		if link.Trusted {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func endpointsOnly(items []Sourced) []Endpoint {
	endpoints := make([]Endpoint, len(items))
	for i, item := range items {
		endpoints[i] = item.Endpoint
	}
	return endpoints
}
