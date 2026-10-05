package guard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// systemDirs is where system tools are looked up. A caller's PATH is never
// consulted: under sudo it may name a directory the user can write to.
var systemDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

const defaultTimeout = 5 * time.Second

// Result is what a system tool said. Err is set when the tool could not be run
// or did not finish in time; a tool that ran and failed has a non-zero Code.
type Result struct {
	Stdout, Stderr string
	Code           int
	Err            error
}

// Failed reports whether the tool did not run or did not succeed.
func (r Result) Failed() bool { return r.Err != nil || r.Code != 0 }

// Error describes a failed result, for messages.
func (r Result) Error() string {
	if r.Err != nil {
		return r.Err.Error()
	}
	if message := strings.TrimSpace(r.Stderr); message != "" {
		return message
	}
	return fmt.Sprintf("exit status %d", r.Code)
}

// Runner runs a system tool with an optional standard input and a timeout
// (zero means the default).
type Runner func(args []string, input string, timeout time.Duration) Result

// ToolPath is the system tool name in the system directories; a path is kept as is.
func ToolPath(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range systemDirs {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s: not found in %s", name, strings.Join(systemDirs, ":"))
}

// SystemEnv is the environment system tools and scripts run with.
func SystemEnv() []string {
	return []string{"PATH=" + strings.Join(systemDirs, ":"), "LC_ALL=C"}
}

// Run runs a system tool from the system directories with the C locale.
func Run(args []string, input string, timeout time.Duration) Result {
	path, err := ToolPath(args[0])
	if err != nil {
		return Result{Code: -1, Err: err}
	}
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args[1:]...)
	cmd.Env = SystemEnv()
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		result.Code, result.Err = -1, fmt.Errorf("%s: no answer within %s", args[0], timeout)
	case errors.As(err, &exit) && exit.Exited():
		result.Code = exit.ExitCode()
	case err != nil:
		result.Code, result.Err = -1, fmt.Errorf("%s: %w", args[0], err)
	}
	return result
}

// Unanswered means a system tool did not answer.
type Unanswered struct {
	Command string
	Err     error // why, if known
}

func (e *Unanswered) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s (%v)", e.Command, e.Err)
	}
	return e.Command
}

func (e *Unanswered) Unwrap() error { return e.Err }

// answer is the result of a tool that must run; its exit status is the caller's business.
func answer(run Runner, args ...string) (Result, error) {
	result := run(args, "", 0)
	if result.Err != nil {
		return result, &Unanswered{Command: strings.Join(args, " "), Err: result.Err}
	}
	return result, nil
}

// logger writes the daemon's log: stderr, which launchd sends to /Library/Logs/egressguard.log.
var logger = log.New(os.Stderr, "", log.LstdFlags)

func logf(format string, args ...any) { logger.Printf(format, args...) }
