package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sentiens/egressguard/internal/guard"
	"github.com/sentiens/egressguard/internal/leak"
)

const homeMAC = "02:00:5e:10:00:01"

// testApp is the CLI over a temporary directory, on a network with a home router.
func testApp(t *testing.T) (*app, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	a := &app{
		stdin:      strings.NewReader(""),
		stdout:     &out,
		configPath: filepath.Join(dir, "daemon", "config.json"),
		statusPath: filepath.Join(dir, "daemon", "status.json"),
		executable: filepath.Join(dir, "bin", "egressguard"),
		uplinks: func() (map[string]guard.Link, error) {
			return map[string]guard.Link{"en0": {Router: "192.168.1.1", MAC: homeMAC}, "en7": {Router: "10.0.0.1"}}, nil
		},
		home:      func() string { return filepath.Join(dir, "home") },
		pollEvery: time.Millisecond,
	}
	return a, &out
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	value := readUserJSON(path)
	if value == nil {
		t.Fatalf("%s: no JSON object", path)
	}
	return value
}

func writeStatus(t *testing.T, a *app, status guard.Status) {
	t.Helper()
	os.MkdirAll(filepath.Dir(a.statusPath), 0o755)
	status.Updated = time.Now().Unix()
	if err := guard.WriteStatus(a.statusPath, status); err != nil {
		t.Fatal(err)
	}
}

func TestTrustCurrentAddsOnce(t *testing.T) {
	a, _ := testApp(t)
	if err := a.trustCurrent("Home", false); err != nil {
		t.Fatal(err)
	}
	if err := a.trustCurrent("Again", false); err != nil {
		t.Fatal(err)
	}
	settings := readJSON(t, a.settingsPath())
	want := []any{map[string]any{"name": "Home", "router": "192.168.1.1", "router_mac": homeMAC}}
	if !reflect.DeepEqual(settings["trusted_networks"], want) {
		t.Fatal(settings["trusted_networks"])
	}
	// What the CLI writes, the daemon accepts.
	if _, err := guard.LoadSettings(a.settingsPath()); err != nil {
		t.Fatal(err)
	}
}

func TestTrustCurrentKeepsOtherSettings(t *testing.T) {
	a, _ := testApp(t)
	os.MkdirAll(filepath.Dir(a.settingsPath()), 0o755)
	os.WriteFile(a.settingsPath(), []byte(`{"endpoints": ["203.0.113.9:51820/udp"], "vpn_only": true}`), 0o644)
	a.trustCurrent("", false)
	settings := readJSON(t, a.settingsPath())
	if !reflect.DeepEqual(settings["endpoints"], []any{"203.0.113.9:51820/udp"}) || settings["vpn_only"] != true {
		t.Fatal(settings)
	}
	if name := settings["trusted_networks"].([]any)[0].(map[string]any)["name"]; name != "Network 192.168.1.1" {
		t.Fatal(name)
	}
}

func TestTrustCurrentAsks(t *testing.T) {
	a, out := testApp(t)
	a.stdin = strings.NewReader("y\nOffice\n")
	if err := a.trustCurrent("", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Trust the network on en0") {
		t.Fatal(out.String())
	}
	networks := readJSON(t, a.settingsPath())["trusted_networks"].([]any)
	if networks[0].(map[string]any)["name"] != "Office" {
		t.Fatal(networks)
	}
	declined, _ := testApp(t)
	declined.stdin = strings.NewReader("n\n")
	declined.trustCurrent("", true)
	if readUserJSON(declined.settingsPath()) != nil {
		t.Fatal("trusted without a yes")
	}
}

func TestTrustCurrentWithoutAKnownMAC(t *testing.T) {
	a, out := testApp(t)
	a.uplinks = func() (map[string]guard.Link, error) { return map[string]guard.Link{"en0": {Router: "10.0.0.1"}}, nil }
	if err := a.trustCurrent("", false); !errors.Is(err, exitStatus(1)) {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no uplink with a known router MAC") {
		t.Fatal(out.String())
	}
}

func TestResourcesFoundInACheckout(t *testing.T) {
	root, _ := filepath.Abs("../..")
	a, _ := testApp(t)
	a.executable = filepath.Join(root, "build", "egressguard")
	script, config, err := a.installFiles()
	if err != nil || script != filepath.Join(root, "scripts/setup.sh") || config != filepath.Join(root, "config/config.json") {
		t.Fatal(script, config, err)
	}
	if got := a.resource("../scripts/uninstall.sh"); got != filepath.Join(root, "scripts/uninstall.sh") {
		t.Fatal(got)
	}
}

func TestResourcesFoundInAHomebrewPrefix(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "Cellar", "egressguard", "0.1.0")
	for _, path := range []string{"bin/egressguard", "libexec/setup.sh", "share/egressguard/config.json",
		"EgressGuard.app/Contents/Info.plist", "../../../opt/egressguard/EgressGuard.app/Contents/Info.plist"} {
		os.MkdirAll(filepath.Join(prefix, filepath.Dir(path)), 0o755)
		os.WriteFile(filepath.Join(prefix, path), nil, 0o755)
	}
	a, _ := testApp(t)
	a.executable = filepath.Join(prefix, "bin", "egressguard")
	script, config, err := a.installFiles()
	if err != nil || script != filepath.Join(prefix, "libexec/setup.sh") || config != filepath.Join(prefix, "share/egressguard/config.json") {
		t.Fatal(script, config, err)
	}
	// The login item points at the opt path, which survives upgrades.
	if app := a.menuApp(); !strings.HasSuffix(app, "/opt/egressguard/EgressGuard.app") {
		t.Fatal(app)
	}
}

func TestControlPathFromConfig(t *testing.T) {
	a, _ := testApp(t)
	os.MkdirAll(filepath.Dir(a.configPath), 0o755)
	os.WriteFile(a.configPath, []byte(`{"control": "/Users/someone/c.json"}`), 0o644)
	if got := a.controlPath(); got != "/Users/someone/c.json" {
		t.Fatal(got)
	}
	os.WriteFile(a.configPath, []byte("broken"), 0o644)
	if got := a.controlPath(); got != filepath.Join(a.home(), "Library/Application Support/EgressGuard/control.json") {
		t.Fatal(got)
	}
}

func TestTurnOffForAWhile(t *testing.T) {
	a, out := testApp(t)
	writeStatus(t, a, guard.Status{State: guard.StateOff, Mode: guard.ModeOff, Enforced: true})
	if err := a.run([]string{"off", "15"}); err != nil {
		t.Fatal(err)
	}
	control := readJSON(t, a.controlPath())
	until, _ := control["until"].(float64)
	if control["mode"] != "off" || until < float64(time.Now().Unix()+14*60) {
		t.Fatal(control)
	}
	if !strings.Contains(out.String(), "egressguard: off") {
		t.Fatal(out.String())
	}
	for _, args := range [][]string{{"off", "0"}, {"off", "soon"}, {"on", "now"}} {
		var badUsage usageError
		if err := a.run(args); !errors.As(err, &badUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestStatusWithoutADaemon(t *testing.T) {
	a, out := testApp(t)
	if err := a.run(nil); !errors.Is(err, exitStatus(1)) || !strings.Contains(out.String(), "does not answer") {
		t.Fatal(err, out.String())
	}
}

func TestDescribe(t *testing.T) {
	status := &statusFile{Status: guard.Status{State: guard.StateTrusted, Mode: guard.ModeOn, Enforced: true, Release: "0.0.1",
		Trusted: []guard.TrustedEntry{{Interface: "en0", Network: "Home"}}, Errors: []string{"something"}}, Age: 40 * time.Second}
	text := describe(status)
	for _, want := range []string{"trusted network (Home)", "40 s old", "the daemon is 0.0.1", "warning: something"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q not in %q", want, text)
		}
	}
	if strings.Contains(text, "not in force") {
		t.Error("an enforced status is reported as not in force")
	}
}

func TestUnknownCommand(t *testing.T) {
	a, out := testApp(t)
	var badUsage usageError
	if err := a.run([]string{"explode"}); !errors.As(err, &badUsage) || !strings.Contains(out.String(), "Usage:") {
		t.Fatal(err)
	}
	if exitCode(badUsage, io.Discard) != 2 || exitCode(exitStatus(3), io.Discard) != 3 || exitCode(nil, io.Discard) != 0 {
		t.Fatal("exit codes")
	}
}

func TestWriteUserJSONMakesDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "control.json")
	if err := writeUserJSON(path, map[string]any{"mode": "on", "note": "<&>"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"<&>"`) {
		t.Fatal(string(data))
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatal(info.Mode())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("a temporary file is left behind")
	}
}

func TestParseLeakArgs(t *testing.T) {
	if seconds, safari, err := parseLeakArgs([]string{"30", "--safari"}); seconds != 30 || !safari || err != nil {
		t.Fatal(seconds, safari, err)
	}
	if seconds, _, _ := parseLeakArgs(nil); seconds != 20 {
		t.Fatal(seconds)
	}
	for _, args := range [][]string{{"4"}, {"301"}, {"x"}} {
		if _, _, err := parseLeakArgs(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// --- judging captures -----------------------------------------------------------------

const myMAC = "02:00:5e:00:00:05"

func ipv4Frame(src, dst string, proto byte, body []byte) []byte {
	from, to := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	packet := append([]byte{0x45, 0, 0, byte(20 + len(body)), 0, 0, 0, 0, 64, proto, 0, 0}, from[:]...)
	packet = append(append(packet, to[:]...), body...)
	mac, _ := net.ParseMAC(myMAC)
	return append(append(append(make([]byte, 6), mac...), 0x08, 0x00), packet...)
}

func udp(sport, dport uint16) []byte {
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, sport), dport)
}

// pcapOf is a classic little-endian pcap with one frame a second from start.
func pcapOf(start int64, frames ...[]byte) []byte {
	data := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	data = binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(data, 2), 4)
	data = append(data, make([]byte, 8)...)
	data = binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(data, 65535), 1)
	for i, frame := range frames {
		for _, field := range []uint32{uint32(start) + uint32(i), 0, uint32(len(frame)), uint32(len(frame))} {
			data = binary.LittleEndian.AppendUint32(data, field)
		}
		data = append(data, frame...)
	}
	return data
}

func TestJudge(t *testing.T) {
	endpoint := []leak.Endpoint{{Address: "198.51.100.61", Family: "inet", Proto: "udp", Port: 51820}}
	data := map[string][]byte{"en0": pcapOf(100,
		ipv4Frame("192.168.1.57", "198.51.100.61", 17, udp(50000, 51820)), // the tunnel
		ipv4Frame("192.168.1.57", "1.1.1.1", 17, udp(50001, 443)),         // a leak
		ipv4Frame("192.168.1.57", "224.0.0.251", 17, udp(5353, 5353)),     // local, past pf
		ipv4Frame("192.168.1.57", "1.1.1.1", 17, udp(50002, 443)),         // after the window
	)}
	report, err := judge(data, map[string]string{"en0": myMAC}, time.Unix(100, 0), time.Unix(102, 0), endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.counts, map[string]int{"allowed": 1, "internet": 1, "local": 1}) || report.clean() {
		t.Fatal(report.counts)
	}
	if report.leaks[leakKey{"internet", "en0", "inet", "udp", "1.1.1.1", 443}] != 1 {
		t.Fatal(report.leaks)
	}
	if _, err := judge(map[string][]byte{"en0": []byte("not a capture")}, nil, time.Unix(0, 0), time.Unix(1, 0), nil, nil); err == nil {
		t.Fatal("an unreadable capture passed")
	}
}

func TestJudgeCleanCapture(t *testing.T) {
	data := map[string][]byte{"en0": pcapOf(100, ipv4Frame("192.168.1.57", "198.51.100.61", 17, udp(50000, 51820)))}
	endpoint := []leak.Endpoint{{Address: "198.51.100.61", Family: "inet", Proto: "udp", Port: 51820}}
	report, err := judge(data, map[string]string{"en0": myMAC}, time.Unix(100, 0), time.Unix(101, 0), endpoint, nil)
	if err != nil || !report.clean() {
		t.Fatal(report, err)
	}
	var out bytes.Buffer
	(&app{stdout: &out}).printReport(report, time.Second)
	if !strings.Contains(out.String(), "not a single packet got past the rules") {
		t.Fatal(out.String())
	}
}

func TestStatusFileIsWhatTheDaemonWrites(t *testing.T) {
	a, _ := testApp(t)
	writeStatus(t, a, guard.Status{State: guard.StateTunnel, Mode: guard.ModeOn, Enforced: true,
		Tunnel: &guard.TunnelState{Interface: "utun4", Services: []string{"home-wg"}}})
	status := a.readStatus()
	if status == nil || status.Age > 5*time.Second || !strings.Contains(describe(status), "through the tunnel (home-wg)") {
		t.Fatal(status)
	}
	var raw map[string]any
	data, _ := os.ReadFile(a.statusPath)
	json.Unmarshal(data, &raw)
	if raw["tunnel"].(map[string]any)["interface"] != "utun4" {
		t.Fatal(raw)
	}
}

func TestUpdateUserJSONKeepsAMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte("{broken"), 0o644)
	err := updateUserJSON(path, map[string]any{}, func(value map[string]any) { value["vpn_only"] = true })
	if err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "{broken" {
		t.Fatal("overwritten:", string(data))
	}
}

func TestUpdateUserJSONReappliesAfterAConcurrentChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte(`{"endpoints": []}`), 0o644)
	calls := 0
	err := updateUserJSON(path, map[string]any{}, func(value map[string]any) {
		calls++
		if calls == 1 { // the menu bar app writes in between
			os.WriteFile(path, []byte(`{"vpn_only": true}`), 0o644)
			os.Chtimes(path, time.Now(), time.Now().Add(time.Second))
		}
		value["learn_connections"] = true
	})
	if err != nil || calls != 2 {
		t.Fatal(err, calls)
	}
	settings := readJSON(t, path)
	if settings["vpn_only"] != true || settings["learn_connections"] != true {
		t.Fatal("a change was lost:", settings)
	}
}

// sh runs a shell script as a stand-in capture.
func sh(script string) func(string, string) *exec.Cmd {
	return func(iface, file string) *exec.Cmd { return exec.Command("/bin/sh", "-c", script) }
}

func TestCapturesThatIgnoreTheStopAreKilled(t *testing.T) {
	uplinks := map[string]string{"en0": myMAC, "en1": myMAC}
	captures, err := startCaptures(t.TempDir(), uplinks, sh(`trap "" INT; sleep 30`))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the shells set their traps
	started := time.Now()
	if err := captures.stop(200 * time.Millisecond); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatal(err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("waited past the deadline")
	}
	if err := captures.running(); err == nil {
		t.Fatal("a capture is still running")
	}
}

func TestCaptureThatStoppedEarlyIsInconclusive(t *testing.T) {
	captures, err := startCaptures(t.TempDir(), map[string]string{"en0": myMAC}, sh("exit 3"))
	if err != nil {
		t.Fatal(err)
	}
	<-captures["en0"].exited
	if err := captures.stop(time.Second); err == nil || !strings.Contains(err.Error(), "stopped early") {
		t.Fatal(err)
	}
}

func TestCapturesStopCleanly(t *testing.T) {
	captures, err := startCaptures(t.TempDir(), map[string]string{"en0": myMAC}, sh(`trap "exit 0" INT; sleep 30 & wait`))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the shell set its trap
	if err := captures.stop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedCaptureIsInconclusive(t *testing.T) {
	data := pcapOf(100, ipv4Frame("192.168.1.57", "1.1.1.1", 17, udp(50001, 443)))
	_, err := judge(map[string][]byte{"en0": data[:len(data)-3]}, map[string]string{"en0": myMAC},
		time.Unix(100, 0), time.Unix(101, 0), nil, nil)
	if !errors.Is(err, leak.ErrTruncated) {
		t.Fatal(err)
	}
}

func TestWatchLockNoticesALapse(t *testing.T) {
	a, _ := testApp(t)
	locked := guard.Status{State: guard.StateBlocked, Mode: guard.ModeLock, Enforced: true}
	writeStatus(t, a, locked)
	stop := a.watchLock()
	time.Sleep(20 * time.Millisecond)
	if err := stop(); err != nil {
		t.Fatal("a steady lock was reported:", err)
	}
	stop = a.watchLock()
	writeStatus(t, a, guard.Status{State: guard.StateTrusted, Mode: guard.ModeOn, Enforced: true}) // the lock lapses…
	time.Sleep(20 * time.Millisecond)
	writeStatus(t, a, locked) // …and comes back
	time.Sleep(20 * time.Millisecond)
	if err := stop(); err == nil || !strings.Contains(err.Error(), "ended before") {
		t.Fatal(err)
	}
}
