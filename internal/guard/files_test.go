package guard

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestConfigReload(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "config.json")
	writeFile(t, path, "{}")
	next, broken := h.config(), false
	h.daemon = h.make(h.config(), func(sys *System) {
		sys.ConfigPath = path
		sys.LoadConfig = func(string) (Config, error) {
			if broken {
				return Config{}, configErrorf("broken")
			}
			return next, nil
		}
	})
	h.daemon.Step(nil)
	epoch := h.daemon.epoch
	h.clocks.advance(tick)
	h.daemon.Step(nil)
	if h.daemon.epoch != epoch {
		t.Fatal("an unchanged config broke trust")
	}

	next.TrustedNetworks = []Network{}
	writeFile(t, path, `{"changed": 1}`)
	h.clocks.advance(tick)
	h.expect(nil, StateBlocked)
	epoch = h.daemon.epoch
	h.clocks.advance(tick)
	h.daemon.Step(nil)
	if h.daemon.epoch != epoch {
		t.Fatal("reading the config counted as a change")
	}

	broken = true
	writeFile(t, path, `{"changed": 22}`)
	h.clocks.advance(tick)
	h.daemon.Step(nil)
	if !h.hasError("config not reloaded: broken") || len(h.daemon.Config().TrustedNetworks) != 0 {
		t.Fatal(h.last().Errors)
	}
}

func TestUserNetworkAndEndpoints(t *testing.T) {
	h := newHarness(t)
	config := h.config()
	config.TrustedNetworks, config.Tunnels = []Network{}, []Tunnel{}
	h.daemon = h.make(config, nil)
	h.expect(nil, StateBlocked)
	h.settings(map[string]any{"trusted_networks": []any{map[string]any{"name": "Home", "router": "192.168.1.1", "router_mac": homeMAC}},
		"endpoints": []any{"198.51.100.61:443/tcp"}})
	h.clocks.advance(1)
	h.expect(nil, StateTrusted)
	if !reflect.DeepEqual(h.last().Endpoints, []EndpointEntry{{"198.51.100.61:443/tcp", "config: own endpoints"}}) ||
		!reflect.DeepEqual(h.last().Networks, []string{"Home"}) {
		t.Fatalf("%+v", h.last())
	}
}

func TestVPNOnly(t *testing.T) {
	h := newHarness(t)
	h.daemon.Step(nil)
	h.settings(map[string]any{"vpn_only": true})
	h.clocks.advance(1)
	h.expect(nil, StateBlocked)
	if !h.last().VPNOnly {
		t.Fatal("vpn_only is not reported")
	}
	h.settings(map[string]any{"vpn_only": false})
	h.clocks.advance(1)
	h.expect(nil, StateTrusted)
}

func TestLearningSwitches(t *testing.T) {
	h := newHarness(t)
	h.settings(map[string]any{"learn_vpn_services": false, "learn_connections": true})
	h.daemon.Step(nil)
	if learn := h.daemon.Config().Learn; !reflect.DeepEqual(learn, Learn{Connections: true, Processes: []string{}}) {
		t.Fatalf("%+v", learn)
	}
}

func TestBadSettingsKeepTheLastGood(t *testing.T) {
	h := newHarness(t)
	h.settings(map[string]any{"trusted_networks": []any{map[string]any{"name": "x", "interface": "en1"}}})
	h.daemon.Step(nil)
	if !slices.Contains(h.last().Networks, "x") {
		t.Fatal(h.last().Networks)
	}
	writeFile(t, filepath.Join(h.dir, "settings.json"), `{"trusted_networks": [{"name": "y", "router": "1.2.3.4"}]}`)
	h.clocks.advance(1)
	h.daemon.Step(nil)
	if !slices.Contains(h.last().Networks, "x") || !h.hasError("router_mac") {
		t.Fatalf("%+v", h.last())
	}
}

func TestBadSettingsAtStartUseTheSavedCopy(t *testing.T) {
	h := newHarness(t)
	lastGood := filepath.Join(h.dir, "last-good.json")
	withCopy := func(sys *System) { sys.LastGoodPath = lastGood }
	h.settings(map[string]any{"trusted_networks": []any{map[string]any{"name": "x", "interface": "en1"}}})
	h.make(h.config(), withCopy).Step(nil)
	writeFile(t, filepath.Join(h.dir, "settings.json"), "broken")
	h.make(h.config(), withCopy).Step(nil)
	if !slices.Contains(h.last().Networks, "x") || !h.hasError("settings") {
		t.Fatalf("%+v", h.last())
	}
}

func TestLastGoodIsTheCheckedText(t *testing.T) {
	h := newHarness(t)
	lastGood := filepath.Join(h.dir, "last-good.json")
	h.settings(map[string]any{"trusted_networks": []any{map[string]any{"name": "x", "interface": "en1"}}})
	h.make(h.config(), func(sys *System) { sys.LastGoodPath = lastGood }).Step(nil)
	data := []byte(readFile(t, lastGood))
	if settings, err := ParseSettings(data); err != nil || settings.TrustedNetworks[0].Name != "x" {
		t.Fatal(err, string(data))
	}
}
