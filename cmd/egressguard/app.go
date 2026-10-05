package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sentiens/egressguard/internal/guard"
)

// app is the CLI with everything it touches; tests point it elsewhere.
type app struct {
	stdin       io.Reader
	stdout      io.Writer
	configPath  string // the daemon's config.json: it names the control file
	statusPath  string // the daemon's status.json
	executable  string // this binary, symlinks resolved
	uplinks     func() (map[string]guard.Link, error)
	home        func() string // the invoking user's home, also under sudo
	pollEvery   time.Duration // how often a waiting command looks at the status
	interactive bool          // stdin is a terminal
}

func newApp() *app {
	return &app{
		stdin:       os.Stdin,
		stdout:      os.Stdout,
		configPath:  guard.StatePath("config.json"),
		statusPath:  guard.StatePath("status.json"),
		executable:  executablePath(),
		uplinks:     detectUplinks,
		home:        userHome,
		pollEvery:   500 * time.Millisecond,
		interactive: isTerminal(os.Stdin),
	}
}

func (a *app) run(args []string) error {
	command := "status"
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}
	switch command {
	case "status":
		return a.status()
	case "on":
		return a.turn(guard.ModeOn, args)
	case "off":
		return a.turn(guard.ModeOff, args)
	case "test":
		return a.selfTest()
	case "leaktest":
		return a.leakTest(args)
	case "endpoints":
		return a.endpoints()
	case "detect":
		return a.detect()
	case "trust-current":
		return a.trustCurrent(strings.Join(args, " "), false)
	case "setup":
		return a.setup()
	case "uninstall":
		return a.uninstall()
	case "version", "--version":
		a.printf("egressguard %s\n", guard.Release)
		return nil
	case "daemon":
		return guard.RunDaemon()
	case "check-config":
		return a.checkConfig(args)
	case "help", "--help", "-h":
		a.printf("%s", usage)
		return nil
	}
	a.printf("%s", usage)
	return usageError("unknown command " + strconv.Quote(command))
}

func (a *app) printf(format string, args ...any) { fmt.Fprintf(a.stdout, format, args...) }

// --- the commands -----------------------------------------------------------------

func (a *app) status() error {
	status := a.readStatus()
	a.printf("egressguard: %s\n", describe(status))
	if status == nil {
		return exitStatus(1)
	}
	for _, name := range sortedKeys(status.Uplinks) {
		link := status.Uplinks[name]
		mark := "untrusted"
		if link.Trusted {
			mark = "trusted: " + deref(link.Network, "?")
		}
		a.printf("  %s: router %s (%s), %s\n", name, deref(link.Router, "?"), deref(link.MAC, "MAC unknown"), mark)
	}
	a.printf("  tunnel endpoints allowed: %d (egressguard endpoints)\n", len(status.Endpoints))
	return nil
}

// turn switches on, or off for good or for some minutes.
func (a *app) turn(mode string, args []string) error {
	control := map[string]any{"mode": mode}
	switch {
	case mode == guard.ModeOff && len(args) == 1:
		minutes, err := strconv.Atoi(args[0])
		if err != nil || minutes <= 0 {
			return usageError("minutes must be a whole number above zero")
		}
		control["until"] = time.Now().Unix() + int64(minutes)*60
	case len(args) > 0:
		return usageError("usage: egressguard on | egressguard off [minutes]")
	}
	if err := a.writeControl(control); err != nil {
		return err
	}
	status := a.waitFor(5*time.Second, func(s *statusFile) bool { return s.Mode == mode })
	a.printf("egressguard: %s\n", describe(status))
	return nil
}

func (a *app) endpoints() error {
	status := a.readStatus()
	if status == nil {
		return errors.New(describe(status))
	}
	for _, item := range status.Endpoints {
		a.printf("%-32s %s\n", item.Endpoint, item.Source)
	}
	a.printf("total: %d\n", len(status.Endpoints))
	return nil
}

func (a *app) detect() error {
	found, err := a.uplinks()
	if err != nil {
		return err
	}
	if len(found) == 0 {
		a.printf("no uplink has a router right now\n")
		return exitStatus(1)
	}
	for _, name := range sortedKeys(found) {
		link := found[name]
		a.printf("%s: router %s, MAC %s\n", name, link.Router, orDefault(link.MAC, "unknown"))
	}
	a.printf("to trust it: egressguard trust-current [name], or the menu bar shield, Settings…\n")
	return nil
}

// trustCurrent adds the network this Mac is on (router address and MAC) to the
// user's trusted networks; ask has the user confirm and name it.
func (a *app) trustCurrent(name string, ask bool) error {
	found, err := a.uplinks()
	if err != nil {
		return err
	}
	uplink := ""
	for _, candidate := range sortedKeys(found) {
		if found[candidate].MAC != "" {
			uplink = candidate
			break
		}
	}
	if uplink == "" {
		a.printf("no uplink with a known router MAC right now\n")
		return exitStatus(1)
	}
	link := found[uplink]
	if trusted(readUserJSON(a.settingsPath()), link) {
		a.printf("%s: router %s (%s) is already trusted\n", uplink, link.Router, link.MAC)
		return nil
	}
	if ask {
		answers := newPrompter(a.stdin, a.stdout)
		if !answers.yes(fmt.Sprintf("Trust the network on %s (router %s, MAC %s)? [y/N] ", uplink, link.Router, link.MAC)) {
			return nil
		}
		name = answers.line("Name for it [Home]: ", "Home")
	}
	if name == "" {
		name = "Network " + link.Router
	}
	network := map[string]any{"name": name, "router": link.Router, "router_mac": link.MAC}
	err = updateUserJSON(a.settingsPath(), map[string]any{"version": 1}, func(settings map[string]any) {
		if !trusted(settings, link) {
			networks, _ := settings["trusted_networks"].([]any)
			settings["trusted_networks"] = append(networks, network)
		}
	})
	if err != nil {
		return err
	}
	a.printf("trusted: %s (router %s, MAC %s); applied within a second\n", name, link.Router, link.MAC)
	return nil
}

// trusted reports whether settings already trust the network of link.
func trusted(settings map[string]any, link guard.Link) bool {
	networks, _ := settings["trusted_networks"].([]any)
	for _, item := range networks {
		network, _ := item.(map[string]any)
		router, hasRouter := network["router"]
		if network["router_mac"] == link.MAC && (!hasRouter || router == link.Router) {
			return true
		}
	}
	return false
}

func (a *app) checkConfig(args []string) error {
	if len(args) != 1 {
		return usageError("usage: egressguard check-config <config.json>")
	}
	result, err := guard.Check(args[0])
	if err != nil {
		return err
	}
	data, _ := json.Marshal(result)
	a.printf("%s\n", data)
	if !result.SyntaxOK {
		return exitStatus(1)
	}
	return nil
}

// --- the daemon's files ---------------------------------------------------------------

// statusFile is status.json with its age.
type statusFile struct {
	guard.Status
	Age time.Duration
}

func (a *app) readStatus() *statusFile {
	data, err := os.ReadFile(a.statusPath)
	if err != nil {
		return nil
	}
	var status statusFile
	if json.Unmarshal(data, &status.Status) != nil {
		return nil
	}
	status.Age = time.Since(time.Unix(status.Updated, 0))
	return &status
}

// waitFor is the first fresh status that satisfies want, or nil after timeout.
func (a *app) waitFor(timeout time.Duration, want func(*statusFile) bool) *statusFile {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(a.pollEvery) {
		if status := a.readStatus(); status != nil && status.Age < 5*time.Second && want(status) {
			return status
		}
	}
	return nil
}

// controlPath is the control file the daemon reads; under sudo, still the user's own.
func (a *app) controlPath() string {
	if data, err := os.ReadFile(a.configPath); err == nil {
		var config struct{ Control string }
		if json.Unmarshal(data, &config) == nil && filepath.IsAbs(config.Control) {
			return config.Control
		}
	}
	return filepath.Join(a.home(), "Library/Application Support/EgressGuard/control.json")
}

func (a *app) settingsPath() string {
	return filepath.Join(filepath.Dir(a.controlPath()), "settings.json")
}

func (a *app) writeControl(value map[string]any) error { return writeUserJSON(a.controlPath(), value) }

// restoreControl puts back the control file as it was before a test.
func (a *app) restoreControl(previous map[string]any) error {
	if previous == nil {
		return removeUserFile(a.controlPath())
	}
	return a.writeControl(previous)
}

// describe is a status in words.
func describe(status *statusFile) string {
	if status == nil {
		return "the daemon does not answer (no " + guard.StatePath("status.json") + "; run sudo egressguard setup)"
	}
	var text string
	switch status.State {
	case guard.StateTrusted:
		var networks []string
		for _, entry := range status.Trusted {
			if !slices.Contains(networks, entry.Network) {
				networks = append(networks, entry.Network)
			}
		}
		slices.Sort(networks)
		text = fmt.Sprintf("on, trusted network (%s): direct internet", strings.Join(networks, ", "))
	case guard.StateTunnel:
		name := "?"
		if tunnel := status.Tunnel; tunnel != nil && len(tunnel.Services) > 0 {
			name = strings.Join(tunnel.Services, ", ")
		} else if tunnel != nil && tunnel.Interface != "" {
			name = tunnel.Interface
		}
		text = fmt.Sprintf("on, untrusted network: internet only through the tunnel (%s)", name)
	case guard.StateBlocked:
		text = "on, untrusted network and no tunnel: no internet"
	case guard.StateOff:
		text = "off: any network, no protection"
	default:
		text = status.State
	}
	if status.Mode == guard.ModeOff && status.Until != nil {
		text += ", until " + time.Unix(*status.Until, 0).Format("15:04")
	}
	if status.Mode == guard.ModeLock {
		text += " (self-test running: no network counts as trusted)"
	}
	var warnings []string
	if status.Sealed && status.State != guard.StateOff {
		warnings = append(warnings, "closed since the Mac slept: opens on a full wake or any key press or mouse move")
	}
	if !status.Enforced {
		warnings = append(warnings, "the rules are not in force (see the errors below)")
	}
	if status.Age > 30*time.Second {
		warnings = append(warnings, fmt.Sprintf("the status is %.0f s old; the daemon may not be running", status.Age.Seconds()))
	}
	if status.PowerWatch != nil && !*status.PowerWatch {
		warnings = append(warnings, "sleep notifications are unavailable; sleep is seen on the clocks only")
	}
	if status.Release != "" && status.Release != guard.Release {
		warnings = append(warnings, fmt.Sprintf("the daemon is %s, this CLI is %s: run sudo egressguard setup",
			status.Release, guard.Release))
	}
	if status.Note != nil {
		warnings = append(warnings, *status.Note)
	}
	warnings = append(warnings, status.Errors...)
	for _, warning := range warnings {
		text += "\nwarning: " + warning
	}
	return text
}

// --- the system -------------------------------------------------------------------------

// detectUplinks is each uplink with a router. macOS may hide the ARP table from this
// process; then the router MAC configd recorded for the network fills in.
func detectUplinks() (map[string]guard.Link, error) {
	uplinks, err := guard.Observe(guard.Config{}, false, guard.Run, true)
	if err != nil {
		return nil, fmt.Errorf("detect failed: %w", err)
	}
	signatures := guard.RouterSignatures(guard.Run)
	found := map[string]guard.Link{}
	for name, link := range uplinks {
		if link.Router == "" {
			continue
		}
		if signature, ok := signatures[name]; ok && link.MAC == "" && signature.Router == link.Router {
			link.MAC = signature.MAC
		}
		found[name] = link
	}
	return found, nil
}

func executablePath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// sudoUser is the user who ran sudo, or "".
func sudoUser() string {
	if name := os.Getenv("SUDO_USER"); os.Geteuid() == 0 && name != "" && name != "root" {
		return name
	}
	return ""
}

func userHome() string {
	if name := sudoUser(); name != "" {
		if account, err := user.Lookup(name); err == nil {
			return account.HomeDir
		}
	}
	home, _ := os.UserHomeDir()
	return home
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func deref(text *string, fallback string) string {
	if text == nil {
		return fallback
	}
	return *text
}

func orDefault(text, fallback string) string {
	if text == "" {
		return fallback
	}
	return text
}
