package guard

import "fmt"

// apply loads rules if they changed or pf lost them, then drops the pf states of
// whatever the rules no longer leave open. view and trust are what the rules were
// made from; verify checks pf even if nothing changed. Hold d.mu.
func (d *Daemon) apply(rules string, view map[string]Link, trust, verify bool) []string {
	if d.stopping.Load() {
		return nil // the uninstaller is about to flush; do not race it
	}
	problems := d.load(rules, verify)
	if same(d.applied, rules) {
		d.noteOpen(rules, view, trust)
	}
	return append(problems, d.dropStates()...)
}

// load puts rules into the anchor and keeps pf enabled and the anchor attached.
// A problem a check finds stands, and is checked again every step, until a check
// finds none. Hold d.mu.
func (d *Daemon) load(rules string, verify bool) []string {
	now, changed := d.sys.Awake(), !same(d.applied, rules)
	switch {
	case rules == "":
		d.enableProblem, d.attachProblem = "", ""
	case verify || changed || d.enableProblem != "" || now-d.lastEnabled >= 1:
		d.lastEnabled = now
		d.enableProblem = ""
		if err := d.ensureEnabled(); err != nil {
			d.enableProblem = "pf could not be enabled: " + err.Error()
		}
	}
	var problems []string
	if verify || changed || d.attachProblem != "" || now-d.lastVerify >= verifyEvery {
		d.lastVerify = now
		if rules != "" {
			d.attachProblem = d.ensureAttached()
		}
		if err := d.ensureLoaded(rules, changed); err != nil {
			problems = append(problems, err.Error())
		}
	}
	for _, problem := range []string{d.enableProblem, d.attachProblem} {
		if problem != "" {
			problems = append(problems, problem)
		}
	}
	return problems
}

// ensureEnabled keeps pf on with a reference of our own. Hold d.mu.
func (d *Daemon) ensureEnabled() error {
	if d.token {
		if on, err := d.sys.Filter.Enabled(); err == nil && on {
			return nil
		}
	}
	if err := d.sys.Filter.Enable(); err != nil {
		return err
	}
	d.token = true
	return nil
}

// ensureAttached makes sure the main ruleset evaluates the anchor; it returns
// what is wrong, or "". Hold d.mu.
func (d *Daemon) ensureAttached() string {
	filter := d.sys.Filter
	attached, err := filter.Attached()
	if err == nil && !attached {
		// Something replaced the main ruleset; the stock file brings com.apple/* back.
		logf("main ruleset lacks com.apple/*; reloading /etc/pf.conf")
		if err = filter.ReloadMain(); err == nil {
			attached, err = filter.Attached()
		}
	}
	switch {
	case err != nil:
		return "pf main ruleset not checked: " + err.Error()
	case !attached:
		return "the pf main ruleset does not evaluate com.apple/*, so the rules are not in force"
	}
	return ""
}

// ensureLoaded loads rules into the anchor if they changed or the anchor lost them.
// A failed load leaves the rules unknown, so the next step loads them again. Hold d.mu.
func (d *Daemon) ensureLoaded(rules string, changed bool) error {
	loaded, err := d.sys.Filter.Loaded()
	if !changed && err == nil && loaded == (rules != "") {
		return nil
	}
	if err := d.sys.Filter.Load(rules); err != nil {
		d.applied = nil
		return fmt.Errorf("pf anchor load failed: %w", err)
	}
	d.applied = &rules
	return nil
}

// noteOpen records which state sources the rules in force leave open, and queues
// for dropping every source they close that was open, or that is new to the
// daemon (its states may come from anywhere: before the daemon started, or while
// the switch was off). Hold d.mu.
func (d *Daemon) noteOpen(rules string, view map[string]Link, trust bool) {
	open, seen := map[string]bool{}, map[string]bool{}
	for _, link := range view {
		for _, source := range StateSources(link) {
			seen[source] = true
			if rules == "" || (link.Trusted && trust) {
				open[source] = true
			}
		}
	}
	for source := range d.open {
		if !open[source] {
			d.revoke[source] = true
		}
	}
	for source := range seen {
		if !open[source] && !d.known[source] {
			d.revoke[source] = true
		}
	}
	for source := range open {
		delete(d.revoke, source) // open again, after a fresh check: nothing to drop
	}
	d.open, d.known = open, seen
}

// dropStates drops the pf states queued for dropping; failures stay queued. Hold d.mu.
func (d *Daemon) dropStates() []string {
	var problems []string
	for _, source := range sortedKeys(d.revoke) {
		if err := d.sys.Filter.KillStates(source); err != nil {
			problems = append(problems, fmt.Sprintf("pf states from %s not dropped: %v", source, err))
			continue
		}
		delete(d.revoke, source)
	}
	return problems
}

func same(applied *string, rules string) bool { return applied != nil && *applied == rules }
