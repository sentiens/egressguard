package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	daemonPath  string // the daemon's installed binary: there on an update, not on a first install
	executable  string // this binary, symlinks resolved
	uplinks     func() (map[string]guard.Link, error)
	home        func() (string, error) // the invoking user's home, also under sudo
	pollEvery   time.Duration          // how often a waiting command looks at the status
	confirm     time.Duration          // how long on and off wait for the daemon to follow
	interactive bool                   // stdin is a terminal
	outErr      error                  // the first failed write to stdout
	answers     *prompter              // reads stdin; one per run, so no answer is buffered away
}

// prompter asks the user, on stdin and stdout.
func (a *app) prompter() *prompter {
	if a.answers == nil {
		a.answers = newPrompter(a.stdin, a.stdout)
	}
	return a.answers
}

func newApp() (*app, error) {
	executable, err := executablePath()
	if err != nil {
		return nil, err
	}
	interactive, err := isTerminal(os.Stdin)
	if err != nil {
		return nil, err
	}
	return &app{
		stdin:       os.Stdin,
		stdout:      os.Stdout,
		configPath:  guard.StatePath("config.json"),
		statusPath:  guard.StatePath("status.json"),
		daemonPath:  guard.StatePath("egressguard"),
		executable:  executable,
		uplinks:     detectUplinks,
		home:        userHome,
		pollEvery:   500 * time.Millisecond,
		confirm:     5 * time.Second,
		interactive: interactive,
	}, nil
}

// run runs a command; output that could not be written fails it too.
func (a *app) run(args []string) error {
	err := a.command(args)
	if a.outErr != nil {
		return errors.Join(err, fmt.Errorf("the output could not be written: %w", a.outErr))
	}
	return err
}

func (a *app) command(args []string) error {
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

// printf writes to stdout; after a failed write it writes nothing more, and run
// reports the failure.
func (a *app) printf(format string, args ...any) {
	if a.outErr == nil {
		_, a.outErr = fmt.Fprintf(a.stdout, format, args...)
	}
}

// --- the commands -----------------------------------------------------------------

func (a *app) status() error {
	status, err := a.readStatus()
	if err != nil {
		a.printf("egressguard: %v\n", err)
		return exitStatus(1)
	}
	a.printf("egressguard: %s\n", describe(status))
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
	status, err := a.waitFor(a.confirm, func(s *statusFile) bool { return s.Mode == mode })
	if err != nil {
		return fmt.Errorf("the switch was set, but the daemon did not confirm it: %w", err)
	}
	a.printf("egressguard: %s\n", describe(status))
	return nil
}

func (a *app) endpoints() error {
	status, err := a.readStatus()
	if err != nil {
		return err
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
	path, err := a.settingsPath()
	if err != nil {
		return err
	}
	settings, err := readUserJSON(path)
	if err != nil {
		return err
	}
	if already, err := trusted(settings, link); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	} else if already {
		a.printf("%s: router %s (%s) is already trusted\n", uplink, link.Router, link.MAC)
		return nil
	}
	if ask {
		answers := a.prompter()
		question := fmt.Sprintf("Trust the network on %s (router %s, MAC %s)? [y/N] ", uplink, link.Router, link.MAC)
		if yes, err := answers.yes(question); err != nil || !yes {
			return err
		}
		if name, err = answers.line("Name for it [Home]: ", "Home"); err != nil {
			return err
		}
	}
	if name == "" {
		name = "Network " + link.Router
	}
	network := map[string]any{"name": name, "router": link.Router, "router_mac": link.MAC}
	err = updateUserJSON(path, map[string]any{"version": 1}, func(settings map[string]any) error {
		networks, err := trustedNetworks(settings)
		if err != nil {
			return err
		}
		if already, err := trusted(settings, link); err != nil || already {
			return err
		}
		settings["trusted_networks"] = append(networks, network)
		return nil
	})
	if err != nil {
		return err
	}
	a.printf("trusted: %s (router %s, MAC %s); applied within a second\n", name, link.Router, link.MAC)
	return nil
}

// trustedNetworks is the list of trusted networks in settings (nil for none);
// anything but a list is an error.
func trustedNetworks(settings map[string]any) ([]any, error) {
	value, present := settings["trusted_networks"]
	if !present {
		return nil, nil
	}
	networks, ok := value.([]any)
	if !ok {
		return nil, errors.New("trusted_networks is not a list")
	}
	return networks, nil
}

// trusted reports whether settings already trust the network of link.
func trusted(settings map[string]any, link guard.Link) (bool, error) {
	networks, err := trustedNetworks(settings)
	if err != nil {
		return false, err
	}
	for i, item := range networks {
		network, ok := item.(map[string]any)
		if !ok {
			return false, fmt.Errorf("trusted_networks[%d] is not an object", i)
		}
		router, hasRouter := network["router"]
		if network["router_mac"] == link.MAC && (!hasRouter || router == link.Router) {
			return true, nil
		}
	}
	return false, nil
}

func (a *app) checkConfig(args []string) error {
	if len(args) != 1 {
		return usageError("usage: egressguard check-config <config.json>")
	}
	result, err := guard.Check(args[0])
	if err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
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

// errNoStatus is a daemon that has never written its status.
var errNoStatus = errors.New("the daemon does not answer (no " + guard.StatePath("status.json") +
	"; run sudo egressguard setup)")

func (a *app) readStatus() (*statusFile, error) {
	data, err := os.ReadFile(a.statusPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoStatus
	}
	if err != nil {
		return nil, err
	}
	var status statusFile
	if err := json.Unmarshal(data, &status.Status); err != nil {
		return nil, fmt.Errorf("%s: %w", a.statusPath, err)
	}
	status.Age = time.Since(time.Unix(status.Updated, 0))
	return &status, nil
}

// waitFor is the first fresh status that satisfies want; after timeout, an error
// that says what the daemon reported last.
func (a *app) waitFor(timeout time.Duration, want func(*statusFile) bool) (*statusFile, error) {
	last := fmt.Errorf("no fresh status within %s", timeout)
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(a.pollEvery) {
		status, err := a.readStatus()
		switch {
		case err != nil:
			last = err
		case status.Age >= 5*time.Second:
			last = fmt.Errorf("the status is %.0f s old; the daemon may not be running", status.Age.Seconds())
		case want(status):
			return status, nil
		default:
			last = fmt.Errorf("after %s: %s", timeout, describe(status))
		}
	}
	return nil, last
}

// controlPath is the control file the daemon reads; under sudo, still the user's own.
// Before setup there is no daemon config, and the control file is the default one.
func (a *app) controlPath() (string, error) {
	data, err := os.ReadFile(a.configPath)
	if errors.Is(err, fs.ErrNotExist) {
		home, err := a.home()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library/Application Support/EgressGuard/control.json"), nil
	}
	if err != nil {
		return "", err
	}
	var config struct{ Control string }
	if err := json.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("%s: %w", a.configPath, err)
	}
	if !filepath.IsAbs(config.Control) {
		return "", fmt.Errorf("%s: control must be an absolute path", a.configPath)
	}
	return config.Control, nil
}

func (a *app) settingsPath() (string, error) {
	control, err := a.controlPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(control), "settings.json"), nil
}

func (a *app) writeControl(value map[string]any) error {
	path, err := a.controlPath()
	if err != nil {
		return err
	}
	return writeUserJSON(path, value)
}

// restoreControl puts back the control file as it was before a test.
func (a *app) restoreControl(previous map[string]any) error {
	if previous != nil {
		return a.writeControl(previous)
	}
	path, err := a.controlPath()
	if err != nil {
		return err
	}
	return removeUserFile(path)
}

// describe is a status in words.
func describe(status *statusFile) string {
	var text string
	switch status.State {
	case guard.StateOff:
		text = "off: any network, no protection"
		if status.SetupPending {
			text = "off: not set up yet. Finish the setup in the EgressGuard window (menu bar shield, Set up…),\n" +
				"or: egressguard trust-current [name], then egressguard on"
		}
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
	found := map[string]guard.Link{}
	for name, link := range uplinks {
		if link.Router != "" {
			found[name] = link
		}
	}
	hidden := false
	for _, link := range found {
		hidden = hidden || link.MAC == ""
	}
	if !hidden {
		return found, nil
	}
	signatures, err := guard.RouterSignatures(guard.Run)
	if err != nil {
		return nil, fmt.Errorf("the router MAC is hidden from this process, and configd did not answer: %w", err)
	}
	for name, link := range found {
		if signature, ok := signatures[name]; ok && link.MAC == "" && signature.Router == link.Router {
			link.MAC = signature.MAC
			found[name] = link
		}
	}
	return found, nil
}

// executablePath is this binary, symlinks resolved.
func executablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

// sudoUser is the user who ran sudo, or "".
func sudoUser() string {
	if name := os.Getenv("SUDO_USER"); os.Geteuid() == 0 && name != "" && name != "root" {
		return name
	}
	return ""
}

// userHome is the home of the invoking user: under sudo, the user who ran sudo,
// never root's.
func userHome() (string, error) {
	if name := sudoUser(); name != "" {
		account, err := user.Lookup(name)
		if err != nil {
			return "", fmt.Errorf("the home of %s: %w", name, err)
		}
		return account.HomeDir, nil
	}
	return os.UserHomeDir()
}

func isTerminal(file *os.File) (bool, error) {
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	return info.Mode()&os.ModeCharDevice != 0, nil
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
