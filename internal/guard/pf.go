package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Anchor is the pf anchor the daemon owns. com.apple/* anchors run in name order,
// so 050 comes before Apple's 200.AirDrop and 250.ApplicationFirewall.
const Anchor = "com.apple/050.EgressGuard"

// Filter is the packet filter as the daemon uses it.
type Filter interface {
	// Enabled reports whether pf is on.
	Enabled() (bool, error)
	// Enable turns pf on, holding exactly one reference token of our own.
	Enable() error
	// Attached reports whether the main ruleset evaluates the com.apple/* anchors.
	Attached() (bool, error)
	// ReloadMain loads the stock main ruleset, /etc/pf.conf.
	ReloadMain() error
	// Loaded reports whether the anchor holds rules.
	Loaded() (bool, error)
	// Load replaces the anchor's rules; "" flushes them.
	Load(rules string) error
	// KillStates drops the pf states that started from source (an address or prefix).
	KillStates(source string) error
}

// PF drives pfctl.
type PF struct {
	run    Runner
	tokens string // the file holding our reference token
}

// NewPF drives pfctl through run, keeping its reference token in the file tokens.
func NewPF(run Runner, tokens string) *PF { return &PF{run: run, tokens: tokens} }

func (pf *PF) pfctl(input string, args ...string) (string, error) {
	result := pf.run(append([]string{"pfctl"}, args...), input, 0)
	if result.Failed() {
		return result.Stdout, fmt.Errorf("pfctl %s: %s", strings.Join(args, " "), result.Error())
	}
	return result.Stdout, nil
}

func (pf *PF) Enabled() (bool, error) {
	out, err := pf.pfctl("", "-s", "info")
	return strings.Contains(out, "Status: Enabled"), err
}

var tokenLine = regexp.MustCompile(`Token : (\d+)`)

// Enable takes a new reference and releases our older ones. Other holders (such as
// SelfControl) keep theirs; pf is never disabled here, the uninstaller releases
// ours. Every token stays in the token file until it is released, so none is lost.
func (pf *PF) Enable() error {
	result := pf.run([]string{"pfctl", "-E"}, "", 0)
	match := tokenLine.FindStringSubmatch(result.Stdout + result.Stderr)
	if match == nil {
		return fmt.Errorf("pfctl -E: no reference token (%s)", result.Error())
	}
	token := match[1]
	held, err := pf.heldTokens()
	if err == nil {
		err = pf.saveTokens(append(held, token))
	}
	if err != nil { // nothing would record the new token: give it back
		if _, releaseErr := pf.pfctl("", "-X", token); releaseErr != nil {
			logf("pf token %s neither recorded nor released: %v", token, releaseErr)
		}
		return fmt.Errorf("pf token file: %w", err)
	}
	kept := []string{token}
	for _, old := range held {
		if old == token {
			continue
		}
		if _, err := pf.pfctl("", "-X", old); err != nil {
			logf("old pf token %s not released: %v", old, err)
			kept = append(kept, old)
		}
	}
	if err := pf.saveTokens(kept); err != nil {
		logf("pf token file not updated: %v", err)
	}
	return nil
}

// heldTokens are the tokens in the token file; a missing file holds none.
func (pf *PF) heldTokens() ([]string, error) {
	data, err := os.ReadFile(pf.tokens)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tokens []string
	for _, token := range strings.Fields(string(data)) {
		if isDigits(token) && !slices.Contains(tokens, token) {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

func (pf *PF) saveTokens(tokens []string) error {
	return writeAtomically(pf.tokens, []byte(strings.Join(tokens, "\n")+"\n"))
}

func (pf *PF) Attached() (bool, error) {
	out, err := pf.pfctl("", "-s", "rules")
	return strings.Contains(out, `anchor "com.apple/*"`), err
}

func (pf *PF) ReloadMain() error {
	_, err := pf.pfctl("", "-f", "/etc/pf.conf")
	return err
}

func (pf *PF) Loaded() (bool, error) {
	out, err := pf.pfctl("", "-a", Anchor, "-s", "rules")
	return strings.Contains(out, "block drop"), err
}

func (pf *PF) Load(rules string) error {
	if rules == "" {
		_, err := pf.pfctl("", "-a", Anchor, "-F", "all")
		return err
	}
	_, err := pf.pfctl(rules, "-a", Anchor, "-f", "-")
	return err
}

func (pf *PF) KillStates(source string) error {
	_, err := pf.pfctl("", "-k", source)
	return err
}
