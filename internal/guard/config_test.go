package guard

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func readControlText(t *testing.T, text *string) Control {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.json")
	if text != nil {
		writeFile(t, path, *text)
	}
	return ReadControl(path, 1000)
}

func TestControlMissingOrBadMeansOn(t *testing.T) {
	if mode := readControlText(t, nil).Mode; mode != ModeOn {
		t.Fatalf("missing file: %s", mode)
	}
	for _, text := range []string{"", "{", "[]", `"off"`, `{"mode": "of"}`, `{"mode": "off", "until": "2000"}`,
		`{"mode": "off", "until": 1.5}`, `{"mode": "off", "until": true}`, `{"mode": "off", "until": -1}`,
		`{"mode": "off"} {}`, `{"mode": "off"}` + strings.Repeat(" ", 5000), `{"mode": 0}`, `{"until": 2000}`} {
		if mode := readControlText(t, &text).Mode; mode != ModeOn {
			t.Errorf("%.40q: %s", text, mode)
		}
	}
}

func TestControlOffAndExpiry(t *testing.T) {
	if got := readControlText(t, ptr(`{"mode": "off"}`)); !reflect.DeepEqual(got, Control{Mode: ModeOff}) {
		t.Fatalf("%+v", got)
	}
	if mode := readControlText(t, ptr(`{"mode": "off", "until": 1001}`)).Mode; mode != ModeOff {
		t.Errorf("timed off: %s", mode)
	}
	if mode := readControlText(t, ptr(`{"mode": "off", "until": 1000}`)).Mode; mode != ModeOn {
		t.Errorf("expired off: %s", mode)
	}
}

func TestControlSetupPending(t *testing.T) {
	if got := readControlText(t, ptr(`{"mode": "off", "setup_pending": true}`)); !reflect.DeepEqual(got,
		Control{Mode: ModeOff, SetupPending: true}) {
		t.Fatalf("%+v", got)
	}
	// Pending only qualifies an off for good: on, a timed off and false are not pending.
	for _, text := range []string{`{"mode": "on", "setup_pending": true}`, `{"mode": "off", "until": 2000, "setup_pending": true}`,
		`{"mode": "off", "setup_pending": false}`} {
		if got := readControlText(t, &text); got.SetupPending {
			t.Errorf("%s: %+v", text, got)
		}
	}
	if got := readControlText(t, ptr(`{"mode": "off", "setup_pending": "yes"}`)); got.Mode != ModeOn || got.Note == "" {
		t.Fatalf("%+v", got)
	}
}

func TestControlLockIsBounded(t *testing.T) {
	for text, want := range map[string]string{`{"mode": "lock", "until": 1030}`: ModeLock, `{"mode": "lock"}`: ModeOn,
		`{"mode": "lock", "until": 999}`: ModeOn, `{"mode": "lock", "until": 1601}`: ModeOn} {
		if got := readControlText(t, &text).Mode; got != want {
			t.Errorf("%s: %s", text, got)
		}
	}
}

func TestControlSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "target.json"), `{"mode": "off"}`)
	must(t, os.Symlink(filepath.Join(dir, "target.json"), filepath.Join(dir, "control.json")))
	if mode := ReadControl(filepath.Join(dir, "control.json"), 1000).Mode; mode != ModeOn {
		t.Fatal(mode)
	}
}

func loadConfigValue(t *testing.T, value any) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, string(marshal(t, value)))
	return LoadConfig(path)
}

func base(extra map[string]any) map[string]any {
	value := map[string]any{"version": 2, "control": "/Users/x/c.json"}
	for key, item := range extra {
		value[key] = item
	}
	return value
}

func TestRepoAndExampleConfigs(t *testing.T) {
	example, err := LoadConfig("../../config/config.example.json")
	if err != nil || len(example.TrustedNetworks) == 0 || len(example.Tunnels) == 0 {
		t.Fatalf("example: %v %+v", err, example)
	}
	// The shipped config knows no network and no server: those are the user's settings.
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, strings.ReplaceAll(readFile(t, "../../config/config.json"), "@CONTROL@", "/x"))
	config, err := LoadConfig(path)
	if err != nil || len(config.TrustedNetworks) != 0 || len(config.Tunnels) != 0 {
		t.Fatalf("shipped: %v %+v", err, config)
	}
}

func TestNothingConfiguredIsValid(t *testing.T) {
	config, err := loadConfigValue(t, base(nil))
	if err != nil || len(config.TrustedNetworks)+len(config.Tunnels) != 0 {
		t.Fatal(err, config)
	}
	if !config.VPNConfigurations {
		t.Fatalf("%+v", config)
	}
}

func TestTrustedVariants(t *testing.T) {
	config, err := loadConfigValue(t, base(map[string]any{"trusted_networks": []any{
		map[string]any{"name": "a", "router_mac": "0:1b:2:aa:bb:c"},
		map[string]any{"name": "b", "interface": "en5"},
		map[string]any{"name": "c", "interface": "en0", "router": "10.0.0.1", "router_mac": "AA:BB:CC:DD:EE:FF", "pin": "subnet"},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	want := []Network{{Name: "a", Pin: "address", RouterMAC: "00:1b:02:aa:bb:0c"}, {Name: "b", Pin: "address", Interface: "en5"},
		{Name: "c", Pin: "subnet", Interface: "en0", Router: "10.0.0.1", RouterMAC: "aa:bb:cc:dd:ee:ff"}}
	if !reflect.DeepEqual(config.TrustedNetworks, want) {
		t.Fatalf("%+v", config.TrustedNetworks)
	}
}

func TestConfigRejected(t *testing.T) {
	network := func(item map[string]any) map[string]any { return map[string]any{"trusted_networks": []any{item}} }
	tunnel := func(endpoints ...any) map[string]any {
		return map[string]any{"tunnels": []any{map[string]any{"name": "x", "endpoints": endpoints}}}
	}
	for _, extra := range []map[string]any{
		network(map[string]any{"name": "x", "router": "192.168.1.1"}),
		network(map[string]any{"name": "x"}),
		network(map[string]any{"router_mac": homeMAC}),
		network(map[string]any{"name": "x", "interface": "utun3"}),
		network(map[string]any{"name": "x", "router_mac": "zz"}),
		network(map[string]any{"name": "x", "router_mac": homeMAC, "pin": "loose"}),
		network(map[string]any{"name": "x", "router_mac": homeMAC, "router_ip": "1.1.1.1"}),
		network(map[string]any{"name": json.Number("5"), "router_mac": homeMAC}),
		network(map[string]any{"name": "x", "router_mac": homeMAC, "pin": true}),
		network(map[string]any{"name": "x", "interface": json.Number("0")}),
		{"tunnels": []any{map[string]any{"name": []any{"x"}, "endpoints": []any{"1.2.3.4:51820/udp"}}}},
		{"control": json.Number("5")},
		{"tunnels": []any{map[string]any{"name": "x", "endpoints": []any{}}}},
		tunnel("vpn.example.com:51820/udp"),
		tunnel("1.2.3.4:51820"),
		tunnel("224.0.0.1/udp"),
		tunnel("1.2.3.4:500/esp"),
		tunnel("fe80::1%en0/udp"),
		tunnel("1.2.3.4:0/udp"),
		tunnel("1.2.3.4:65536/udp"),
		tunnel("1.2.3.4:/udp"),
		tunnel(5),
		{"learn": map[string]any{"vpn_services": "yes"}},
		{"learn": map[string]any{"connections": true}}, // removed in 0.3.0
		{"learn": map[string]any{"processes": []any{"openvpn"}}},
		{"learn": nil},
		{"version": 1},
		{"surprise": true},
	} {
		_, err := loadConfigValue(t, base(extra))
		var configError *ConfigError
		if !errors.As(err, &configError) {
			t.Errorf("%v: %v", extra, err)
		}
	}
	if _, err := loadConfigValue(t, map[string]any{"version": 2}); err == nil {
		t.Error("a config without control accepted")
	}
	if _, err := loadConfigValue(t, base(map[string]any{"_comment": "ignored"})); err != nil {
		t.Error(err)
	}
}

func TestEndpoints(t *testing.T) {
	for text, want := range map[string]Endpoint{
		"1.2.3.4:51820/udp":     {"1.2.3.4", "inet", 51820, "udp"},
		"1.2.3.4/tcp":           {"1.2.3.4", "inet", 0, "tcp"},
		"[2001:db8::1]:443/tcp": {"2001:db8::1", "inet6", 443, "tcp"},
		"2001:db8::1/udp":       {"2001:db8::1", "inet6", 0, "udp"},
		"198.51.100.5/esp":      {"198.51.100.5", "inet", 0, "esp"},
	} {
		got, err := ParseEndpoint(text, "endpoint")
		if err != nil || got != want || got.String() != text {
			t.Errorf("%s: %+v %v", text, got, err)
		}
	}
}

func TestEffective(t *testing.T) {
	off := false
	settings := Settings{TrustedNetworks: []Network{{Name: "mine", Interface: "en5"}}, Endpoints: vpnEndpoints[:1],
		VPNConfigurations: &off}
	config := Effective(baseConfig, settings)
	if len(config.TrustedNetworks) != 3 || config.Tunnels[1].Name != "own endpoints" || config.VPNConfigurations {
		t.Fatalf("%+v", config)
	}
	if len(baseConfig.TrustedNetworks) != 2 {
		t.Fatal("the administrator's config changed")
	}
	settings.VPNOnly = true
	if config := Effective(baseConfig, settings); len(config.TrustedNetworks) != 0 || !config.VPNOnly {
		t.Fatalf("%+v", config)
	}
}

func TestOnlyRegularFilesAreRead(t *testing.T) {
	if _, err := ReadUserFile("/dev/null", 16); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatal("read a device:", err)
	}
}

func TestFIFOSettingsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatal("read a fifo:", err)
	}
}

func TestSymlinkedSettingsRefused(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "elsewhere.json"), `{"vpn_only": true}`)
	must(t, os.Symlink(filepath.Join(dir, "elsewhere.json"), filepath.Join(dir, "settings.json")))
	if _, err := LoadSettings(filepath.Join(dir, "settings.json")); err == nil {
		t.Fatal("followed a symlink")
	}
}

func TestOversizedSettingsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, path, `{"vpn_only": true}`+strings.Repeat(" ", settingsLimit))
	if _, err := LoadSettings(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatal(err)
	}
}

func TestFileStampIgnoresReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, "{}")
	before := fileStamp(path)
	readFile(t, path)
	must(t, os.Chmod(path, 0o600))
	if after := fileStamp(path); after != before {
		t.Fatalf("%s != %s", after, before)
	}
}
