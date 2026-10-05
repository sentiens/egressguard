package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sentiens/egressguard/internal/guard"
)

// resource is the first of candidates (paths relative to this binary) that exists:
// the Homebrew layout first, then a checkout.
func (a *app) resource(candidates ...string) string {
	here := filepath.Dir(a.executable)
	for _, candidate := range candidates {
		path := filepath.Clean(filepath.Join(here, candidate))
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// installFiles are setup.sh and the config template, next to this binary.
func (a *app) installFiles() (script, config string, err error) {
	script = a.resource("../libexec/setup.sh", "../scripts/setup.sh")
	config = a.resource("../share/egressguard/config.json", "../config/config.json")
	if script == "" || config == "" {
		return "", "", errors.New("egressguard is not installed completely: setup.sh or config.json is missing")
	}
	return script, config, nil
}

// menuApp is the menu bar app; for Homebrew, its stable opt path, so the login item
// survives upgrades.
func (a *app) menuApp() string {
	app := a.resource("../EgressGuard.app", "EgressGuard.app")
	if prefix, _, found := strings.Cut(app, "/Cellar/egressguard/"); found {
		opt := filepath.Join(prefix, "opt/egressguard/EgressGuard.app")
		if _, err := os.Stat(opt); err == nil {
			return opt
		}
	}
	return app
}

func (a *app) setup() error {
	if os.Geteuid() != 0 || sudoUser() == "" {
		return errors.New("run it as: sudo egressguard setup")
	}
	script, config, err := a.installFiles()
	if err != nil {
		return err
	}
	networks, _ := readUserJSON(a.settingsPath())["trusted_networks"].([]any)
	if len(networks) == 0 && a.interactive {
		a.printf("No trusted network yet: on every network the internet would only go through a VPN tunnel.\n")
		if err := a.trustCurrent("", true); err != nil && !errors.As(err, new(exitStatus)) {
			return err
		}
	}
	return a.runScript(script, "EGRESSGUARD_DAEMON="+a.executable, "EGRESSGUARD_CONFIG="+config,
		"EGRESSGUARD_APP="+a.menuApp(), "EGRESSGUARD_RELEASE="+guard.Release)
}

func (a *app) uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("run it as: sudo egressguard uninstall")
	}
	script := a.resource("../libexec/uninstall.sh", "../scripts/uninstall.sh")
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
