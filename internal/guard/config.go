package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// ConfigError is a configuration or settings file the daemon refuses.
type ConfigError struct{ Message string }

func (e *ConfigError) Error() string { return e.Message }

func configErrorf(format string, args ...any) error {
	return &ConfigError{fmt.Sprintf(format, args...)}
}

// Network is a trusted network: any of an interface, a router address and the
// router's MAC address. An empty field is absent.
type Network struct {
	Name      string
	Pin       string // "address", "subnet" or "none"
	Interface string
	Router    string
	RouterMAC string
}

// Tunnel is a named set of endpoints from the administrator's config.
type Tunnel struct {
	Name      string
	Endpoints []Endpoint
}

// Learn says which endpoints the daemon may find by itself.
type Learn struct {
	VPNServices bool     // server addresses of the VPN configurations macOS has
	Connections bool     // connections of running tunnel providers on a trusted network
	Processes   []string // more provider processes, by name
}

// Config is the administrator's config.json or, merged with the user's settings
// (Effective), the policy in force.
type Config struct {
	TrustedNetworks []Network
	Tunnels         []Tunnel
	Control         string // the user's control file; settings.json sits next to it
	Learn           Learn
	VPNOnly         bool
}

// Settings are the user's own settings.json, edited by the menu bar app.
type Settings struct {
	TrustedNetworks  []Network
	Endpoints        []Endpoint
	LearnVPNServices *bool // nil: the administrator's choice
	LearnConnections *bool
	VPNOnly          bool
}

// DefaultSettings are the settings of a user who has none.
func DefaultSettings() Settings {
	return Settings{TrustedNetworks: []Network{}, Endpoints: []Endpoint{}}
}

// Size limits for files the user controls.
const (
	settingsLimit = 256 << 10
	controlLimit  = 4 << 10
)

var (
	macPattern       = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	uplinkPattern    = regexp.MustCompile(`^[a-z][a-z_]*\d+$`)
	interfacePattern = regexp.MustCompile(`^([a-z_]+)(\d+)$`)
)

// NormalizeMAC writes a MAC address in one form: lower case, two digits per part
// (arp drops leading zeros).
func NormalizeMAC(mac string) string {
	parts := strings.Split(strings.ToLower(mac), ":")
	for i, part := range parts {
		if len(part) == 1 {
			parts[i] = "0" + part
		}
	}
	return strings.Join(parts, ":")
}

// LoadConfig reads and checks the administrator's config.json.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, configErrorf("%s: %v", path, err)
	}
	value, err := decodeJSON(data)
	if err != nil {
		return Config{}, configErrorf("%s: %v", path, err)
	}
	return parseConfig(value)
}

func parseConfig(value any) (Config, error) {
	item, err := object(value, "config", "version", "trusted_networks", "tunnels", "learn", "control")
	if err != nil {
		return Config{}, err
	}
	if version, present := item["version"]; present {
		if number, ok := version.(json.Number); !ok || number.String() != fmt.Sprint(StatusVersion) {
			return Config{}, configErrorf("config: version %v is not %d", version, StatusVersion)
		}
	}
	trusted, okTrusted := optionalList(item, "trusted_networks")
	tunnels, okTunnels := optionalList(item, "tunnels")
	if !okTrusted || !okTunnels {
		return Config{}, configErrorf("config: trusted_networks and tunnels are lists")
	}
	config := Config{TrustedNetworks: []Network{}, Tunnels: []Tunnel{}}
	for i, value := range trusted {
		network, err := parseNetwork(value, fmt.Sprintf("trusted_networks[%d]", i))
		if err != nil {
			return Config{}, err
		}
		config.TrustedNetworks = append(config.TrustedNetworks, network)
	}
	for i, value := range tunnels {
		tunnel, err := parseTunnel(value, fmt.Sprintf("tunnels[%d]", i))
		if err != nil {
			return Config{}, err
		}
		config.Tunnels = append(config.Tunnels, tunnel)
	}
	learn, present := item["learn"]
	if !present {
		learn = map[string]any{}
	}
	if config.Learn, err = parseLearn(learn); err != nil {
		return Config{}, err
	}
	if config.Control, err = text(item, "control", "config"); err != nil {
		return Config{}, err
	}
	if !filepath.IsAbs(config.Control) {
		return Config{}, configErrorf("config: control must be an absolute path")
	}
	return config, nil
}

func parseNetwork(value any, where string) (Network, error) {
	item, err := object(value, where, "name", "interface", "router", "router_mac", "pin")
	if err != nil {
		return Network{}, err
	}
	name, err := text(item, "name", where)
	if err != nil {
		return Network{}, err
	}
	if strings.TrimSpace(name) == "" {
		return Network{}, configErrorf("%s: needs a name", where)
	}
	network := Network{Name: strings.TrimSpace(name), Pin: "address"}
	if _, present := item["pin"]; present {
		if network.Pin, err = text(item, "pin", where); err != nil {
			return Network{}, err
		}
		if network.Pin != "address" && network.Pin != "subnet" && network.Pin != "none" {
			return Network{}, configErrorf("%s: pin is address, subnet or none", where)
		}
	}
	if _, present := item["interface"]; present {
		name, err := text(item, "interface", where)
		if err != nil {
			return Network{}, err
		}
		if !uplinkPattern.MatchString(name) || IsInternal(name) {
			return Network{}, configErrorf("%s: interface must be an uplink name such as en0", where)
		}
		network.Interface = name
	}
	if value, present := item["router"]; present {
		if network.Router = IPv4(scalar(value)); network.Router == "" {
			return Network{}, configErrorf("%s: router must be an IPv4 address", where)
		}
	}
	if value, present := item["router_mac"]; present {
		if network.RouterMAC = NormalizeMAC(scalar(value)); !macPattern.MatchString(network.RouterMAC) {
			return Network{}, configErrorf("%s: router_mac must look like 02:00:5e:10:00:01", where)
		}
	}
	switch {
	case network.Router != "" && network.RouterMAC == "":
		return Network{}, configErrorf("%s: a router address is shared by countless networks; add router_mac", where)
	case network.Interface == "" && network.RouterMAC == "":
		return Network{}, configErrorf("%s: needs router_mac, interface, or both", where)
	}
	return network, nil
}

func parseTunnel(value any, where string) (Tunnel, error) {
	item, err := object(value, where, "name", "endpoints")
	if err != nil {
		return Tunnel{}, err
	}
	name, err := text(item, "name", where)
	if err != nil {
		return Tunnel{}, err
	}
	if strings.TrimSpace(name) == "" {
		return Tunnel{}, configErrorf("%s: needs a name", where)
	}
	texts, ok := item["endpoints"].([]any)
	if !ok || len(texts) == 0 {
		return Tunnel{}, configErrorf("%s: needs a non-empty list of endpoints", where)
	}
	tunnel := Tunnel{Name: strings.TrimSpace(name)}
	for i, text := range texts {
		endpoint, err := ParseEndpoint(text, fmt.Sprintf("%s.endpoints[%d]", where, i))
		if err != nil {
			return Tunnel{}, err
		}
		tunnel.Endpoints = append(tunnel.Endpoints, endpoint)
	}
	return tunnel, nil
}

func parseLearn(value any) (Learn, error) {
	item, err := object(value, "learn", "vpn_services", "connections", "processes")
	if err != nil {
		return Learn{}, err
	}
	learn := Learn{VPNServices: true, Processes: []string{}}
	for key, target := range map[string]*bool{"vpn_services": &learn.VPNServices, "connections": &learn.Connections} {
		if value, present := item[key]; present {
			if *target, err = boolean(value, "learn."+key); err != nil {
				return Learn{}, err
			}
		}
	}
	processes, ok := optionalList(item, "processes")
	for _, process := range processes {
		name, isText := process.(string)
		if !isText || name == "" || strings.Contains(name, "/") {
			ok = false
			break
		}
		learn.Processes = append(learn.Processes, name)
	}
	if !ok {
		return Learn{}, configErrorf("learn.processes: a list of process names")
	}
	return learn, nil
}

// SettingsPath is where the user's settings live: next to the control file, so the
// menu bar app edits them without a password.
func SettingsPath(config Config) string {
	return filepath.Join(filepath.Dir(config.Control), "settings.json")
}

// LoadSettings reads the user's settings file; a missing file means defaults.
func LoadSettings(path string) (Settings, error) {
	data, err := ReadUserFile(path, settingsLimit)
	if errors.Is(err, fs.ErrNotExist) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, configErrorf("settings: %v", err)
	}
	return ParseSettings(data)
}

// ParseSettings reads and checks the text of a settings file.
func ParseSettings(data []byte) (Settings, error) {
	value, err := decodeJSON(data)
	if err != nil {
		return Settings{}, configErrorf("settings: %v", err)
	}
	item, err := object(value, "settings", "version", "trusted_networks", "endpoints", "learn_vpn_services",
		"learn_connections", "vpn_only")
	if err != nil {
		return Settings{}, err
	}
	networks, okNetworks := optionalList(item, "trusted_networks")
	endpoints, okEndpoints := optionalList(item, "endpoints")
	if !okNetworks || !okEndpoints {
		return Settings{}, configErrorf("settings: trusted_networks and endpoints are lists")
	}
	settings := DefaultSettings()
	for i, value := range networks {
		network, err := parseNetwork(value, fmt.Sprintf("settings.trusted_networks[%d]", i))
		if err != nil {
			return Settings{}, err
		}
		settings.TrustedNetworks = append(settings.TrustedNetworks, network)
	}
	for i, value := range endpoints {
		endpoint, err := ParseEndpoint(value, fmt.Sprintf("settings.endpoints[%d]", i))
		if err != nil {
			return Settings{}, err
		}
		settings.Endpoints = append(settings.Endpoints, endpoint)
	}
	for key, target := range map[string]**bool{"learn_vpn_services": &settings.LearnVPNServices,
		"learn_connections": &settings.LearnConnections} {
		if value, present := item[key]; present {
			b, err := boolean(value, "settings."+key)
			if err != nil {
				return Settings{}, err
			}
			*target = &b
		}
	}
	if value, present := item["vpn_only"]; present {
		if settings.VPNOnly, err = boolean(value, "settings.vpn_only"); err != nil {
			return Settings{}, err
		}
	}
	return settings, nil
}

// Effective is the policy in force: the administrator's config plus the user's settings.
func Effective(admin Config, settings Settings) Config {
	config := admin
	config.TrustedNetworks = []Network{}
	if !settings.VPNOnly {
		config.TrustedNetworks = append(slices.Clone(admin.TrustedNetworks), settings.TrustedNetworks...)
	}
	config.Tunnels = slices.Clone(admin.Tunnels)
	if len(settings.Endpoints) > 0 {
		config.Tunnels = append(config.Tunnels, Tunnel{Name: "own endpoints", Endpoints: settings.Endpoints})
	}
	config.Learn.Processes = slices.Clone(admin.Learn.Processes)
	if settings.LearnVPNServices != nil {
		config.Learn.VPNServices = *settings.LearnVPNServices
	}
	if settings.LearnConnections != nil {
		config.Learn.Connections = *settings.LearnConnections
	}
	config.VPNOnly = settings.VPNOnly
	return config
}

// decodeJSON parses one JSON value keeping numbers exact; text that is not UTF-8
// or has anything after the value is refused.
func decodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("not UTF-8 text")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("more data after the JSON value")
	}
	return value, nil
}

// object is value as a JSON object with only the allowed keys (and comments: keys starting with _).
func object(value any, where string, allowed ...string) (map[string]any, error) {
	item, ok := value.(map[string]any)
	if !ok {
		return nil, configErrorf("%s: expected an object", where)
	}
	var unknown []string
	for key := range item {
		if !strings.HasPrefix(key, "_") && !slices.Contains(allowed, key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		sorted := slices.Sorted(slices.Values(allowed))
		return nil, configErrorf("%s: unknown key %s (allowed: %s)", where, strings.Join(unknown, ", "),
			strings.Join(sorted, ", "))
	}
	return item, nil
}

// optionalList is the list under key, or an empty one when the key is absent.
func optionalList(item map[string]any, key string) ([]any, bool) {
	value, present := item[key]
	if !present {
		return []any{}, true
	}
	items, ok := value.([]any)
	return items, ok
}

// text is item[key] if it is a string, "" if it is absent, and an error otherwise.
func text(item map[string]any, key, where string) (string, error) {
	value, present := item[key]
	if !present {
		return "", nil
	}
	s, ok := value.(string)
	if !ok {
		return "", configErrorf("%s: %s must be a string", where, key)
	}
	return s, nil
}

func boolean(value any, where string) (bool, error) {
	b, ok := value.(bool)
	if !ok {
		return false, configErrorf("%s: true or false", where)
	}
	return b, nil
}

// scalar is a JSON string or number as text, for fields people may write either way.
func scalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}
