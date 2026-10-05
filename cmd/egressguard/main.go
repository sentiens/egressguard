// Command egressguard is the EgressGuard CLI and, as `egressguard daemon`, the
// root daemon: trusted networks, VPN tunnels, or nothing.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const usage = `egressguard: trusted networks, VPN tunnels, or nothing.

Usage:
  egressguard [status]               what the switch is doing now
  egressguard on                     turn the switch on
  egressguard off [minutes]          turn it off, for good or for a while
  egressguard trust-current [name]   trust the network this Mac is on now
  egressguard endpoints              every endpoint a tunnel may reach, and why
  egressguard detect                 each uplink's router and MAC
  egressguard test                   a few seconds with nothing trusted: a direct request must fail
  sudo egressguard leaktest [seconds] [--safari]
                                     capture every packet leaving the uplinks while nothing
                                     is trusted, and count what got past the rules
  sudo egressguard setup             install or update the root daemon and the menu bar app
  sudo egressguard uninstall         remove the daemon, its pf rules and the menu bar app
  egressguard version

The CLI and the menu bar app write only the user's own files (control.json,
settings.json); the root daemon checks every entry. No password is needed to
turn the switch off: it protects against leaks, not against its own user.
`

// exitStatus ends the program with a status after the command said why.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// usageError is a command line the CLI does not understand.
type usageError string

func (e usageError) Error() string { return string(e) }

func main() {
	a, err := newApp()
	if err == nil {
		err = a.run(os.Args[1:])
	}
	os.Exit(exitCode(err, os.Stderr))
}

// exitCode reports err on stderr and turns it into the process's exit status.
func exitCode(err error, stderr io.Writer) int {
	var status exitStatus
	var badUsage usageError
	code := 1
	switch {
	case err == nil:
		return 0
	case errors.As(err, &status):
		return int(status) // the command has said why
	case errors.As(err, &badUsage):
		code = 2
	}
	// The last report there is: if stderr is gone, no one is left to tell, and the
	// status still says the command failed.
	_, _ = fmt.Fprintln(stderr, "egressguard:", err)
	return code
}
