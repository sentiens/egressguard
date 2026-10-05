package guard

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNewTokenThenOldReleased(t *testing.T) {
	var calls [][]string
	run := func(args []string, input string, timeout time.Duration) Result {
		calls = append(calls, args)
		if slices.Equal(args, []string{"pfctl", "-E"}) {
			return Result{Stderr: "pf enabled\nToken : 555\n"}
		}
		return done("", 0)
	}
	path := filepath.Join(t.TempDir(), "pf-tokens")
	os.WriteFile(path, []byte("111\n222\n"), 0o644)
	if err := NewPF(run, path).Enable(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "555\n" {
		t.Fatal(string(data))
	}
	if !reflect.DeepEqual(calls, [][]string{{"pfctl", "-E"}, {"pfctl", "-X", "111"}, {"pfctl", "-X", "222"}}) {
		t.Fatal(calls)
	}
}

func TestUnreleasedTokenIsKept(t *testing.T) {
	run := func(args []string, input string, timeout time.Duration) Result {
		if slices.Equal(args, []string{"pfctl", "-E"}) {
			return Result{Stderr: "Token : 555\n"}
		}
		return Result{Stderr: "pfctl: busy", Code: 1}
	}
	path := filepath.Join(t.TempDir(), "pf-tokens")
	os.WriteFile(path, []byte("111\n"), 0o644)
	if err := NewPF(run, path).Enable(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "555\n111\n" {
		t.Fatalf("%q", data)
	}
}

func TestEnableWithoutATokenFails(t *testing.T) {
	run := func([]string, string, time.Duration) Result {
		return Result{Stderr: "pfctl: permission denied", Code: 1}
	}
	if err := NewPF(run, filepath.Join(t.TempDir(), "tokens")).Enable(); err == nil {
		t.Fatal("enabled without a token")
	}
}

func TestAttached(t *testing.T) {
	answer := func(out string, code int) *PF {
		return NewPF(func([]string, string, time.Duration) Result { return done(out, code) }, "")
	}
	for _, c := range []struct {
		out      string
		code     int
		attached bool
		failed   bool
	}{
		{`anchor "com.apple/*" all` + "\n", 0, true, false},
		{"", 0, false, false}, // an empty ruleset never reaches the anchor
		{"scrub-anchor \"x\" all\n", 0, false, false},
		{"", 1, false, true}, // pfctl failed: unknown, not missing
	} {
		attached, err := answer(c.out, c.code).Attached()
		if attached != c.attached || (err != nil) != c.failed {
			t.Errorf("%q, %d: %v %v", c.out, c.code, attached, err)
		}
	}
}

func TestKillStatesReportsFailure(t *testing.T) {
	run := func(args []string, input string, timeout time.Duration) Result {
		return Result{Code: -1, Err: errTimeout}
	}
	if err := NewPF(run, "").KillStates("192.168.1.108"); err == nil || !strings.Contains(err.Error(), "-k 192.168.1.108") {
		t.Fatal(err)
	}
}

func TestAnchorSortsBeforeApple(t *testing.T) {
	if _, name, _ := strings.Cut(Anchor, "/"); name >= "200.AirDrop" {
		t.Fatal(Anchor)
	}
}

func TestUnreadableTokenFileGivesTheNewTokenBack(t *testing.T) {
	var calls [][]string
	run := func(args []string, input string, timeout time.Duration) Result {
		calls = append(calls, args)
		if slices.Equal(args, []string{"pfctl", "-E"}) {
			return Result{Stderr: "Token : 555\n"}
		}
		return done("", 0)
	}
	tokens := t.TempDir() // a directory: it cannot be read as a file
	if err := NewPF(run, tokens).Enable(); err == nil {
		t.Fatal("enabled without recording the token")
	}
	if !slices.ContainsFunc(calls, func(call []string) bool { return slices.Equal(call, []string{"pfctl", "-X", "555"}) }) {
		t.Fatal("the new token was not given back:", calls)
	}
}
