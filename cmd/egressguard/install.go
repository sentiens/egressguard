package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sentiens/egressguard/internal/guard"
)

// resource is the first of candidates (paths relative to this binary) that exists:
// the Homebrew layout first, then a checkout. "" if none does.
func (a *app) resource(candidates ...string) (string, error) {
	here := filepath.Dir(a.executable)
	for _, candidate := range candidates {
		path := filepath.Clean(filepath.Join(here, candidate))
		if found, err := exists(path); err != nil || found {
			return path, err
		}
	}
	return "", nil
}

// exists reports whether path exists; only "it does not" is an answer, not a failure.
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// installFiles are setup.sh and the config template, next to this binary.
func (a *app) installFiles() (script, config string, err error) {
	if script, err = a.resource("../libexec/setup.sh", "../scripts/setup.sh"); err != nil {
		return "", "", err
	}
	if config, err = a.resource("../share/egressguard/config.json", "../config/config.json"); err != nil {
		return "", "", err
	}
	if script == "" || config == "" {
		return "", "", errors.New("egressguard is not installed completely: setup.sh or config.json is missing")
	}
	return script, config, nil
}

// menuApp is the menu bar app, or ""; for Homebrew, its stable opt path, so the
// login item survives upgrades.
func (a *app) menuApp() (string, error) {
	app, err := a.resource("../EgressGuard.app", "EgressGuard.app")
	if err != nil {
		return "", err
	}
	if prefix, _, found := strings.Cut(app, "/Cellar/egressguard/"); found {
		opt := filepath.Join(prefix, "opt/egressguard/EgressGuard.app")
		if found, err := exists(opt); err != nil || found {
			return opt, err
		}
	}
	return app, nil
}

// setup installs or updates the daemon. On a first install the switch stays off
// until the user decides about this network and turns it on: here, in the menu
// bar app's setup window, or with trust-current and on.
func (a *app) setup() error {
	if os.Geteuid() != 0 || sudoUser() == "" {
		return errors.New("run it as: sudo egressguard setup")
	}
	script, config, err := a.installFiles()
	if err != nil {
		return err
	}
	menu, err := a.menuApp()
	if err != nil {
		return err
	}
	installed, err := exists(a.daemonPath)
	if err != nil {
		return err
	}
	initial := "" // an update leaves the switch as the user set it
	if !installed {
		if initial, err = a.onboard(); err != nil {
			return err
		}
	} else if err := a.offerTrust(); err != nil {
		return err
	}
	return a.runScript(script, "EGRESSGUARD_DAEMON="+a.executable, "EGRESSGUARD_CONFIG="+config,
		"EGRESSGUARD_APP="+menu, "EGRESSGUARD_RELEASE="+guard.Release, "EGRESSGUARD_INITIAL="+initial)
}

// onboard asks, on a terminal, whether to trust this network and whether to turn
// the switch on now. It returns the switch to install with: "on", or "pending"
// (off until set up) when the user says no or no one is there to ask.
func (a *app) onboard() (string, error) {
	if !a.interactive {
		return "pending", nil
	}
	a.printf("EgressGuard lets this Mac reach the internet only on networks you trust,\n" +
		"or through a VPN tunnel. It stays off until you turn it on.\n\n")
	if err := a.trustCurrent("", true); err != nil && !errors.As(err, new(exitStatus)) {
		return "", err
	}
	on, err := a.prompter().yes("Turn EgressGuard on now? [y/N] ")
	if err != nil {
		return "", err
	}
	if !on {
		return "pending", nil
	}
	return "on", nil
}

// offerTrust offers, on an update with no trusted network, to trust this one.
func (a *app) offerTrust() error {
	if !a.interactive {
		return nil
	}
	path, err := a.settingsPath()
	if err != nil {
		return err
	}
	settings, err := readUserJSON(path)
	if err != nil {
		return err
	}
	networks, err := trustedNetworks(settings)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(networks) > 0 {
		return nil
	}
	a.printf("No trusted network yet: on every network the internet would only go through a VPN tunnel.\n")
	if err := a.trustCurrent("", true); err != nil && !errors.As(err, new(exitStatus)) {
		return err
	}
	return nil
}

func (a *app) uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("run it as: sudo egressguard uninstall")
	}
	script, err := a.resource("../libexec/uninstall.sh", "../scripts/uninstall.sh")
	if err != nil {
		return err
	}
	if script == "" {
		return errors.New("uninstall.sh is missing")
	}
	return a.runScript(script)
}

// runScript runs an install script as root with the system PATH: nothing from the
// user's environment but who they are.
func (a *app) runScript(script string, env ...string) error {
	cmd := exec.Command("/bin/bash", script)
	cmd.Env = append(guard.SystemEnv(), env...)
	for _, name := range []string{"SUDO_USER", "SUDO_UID", "SUDO_GID", "TERM"} {
		if value, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+value)
		}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.stdin, a.stdout, os.Stderr
	var exit *exec.ExitError
	if err := cmd.Run(); errors.As(err, &exit) {
		return exitStatus(exit.ExitCode())
	} else if err != nil {
		return err
	}
	return nil
}
