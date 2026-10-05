package guard

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

// StatusVersion is the format of status.json (and of config.json).
const StatusVersion = 2

// Release is the version of egressguard, set at build time.
var Release = "dev"

// States of the switch.
const (
	StateOff     = "off"
	StateTrusted = "trusted" // on, and a trusted network gives direct internet
	StateTunnel  = "tunnel"  // on, the internet only through a tunnel
	StateBlocked = "blocked" // on, no internet
)

// Status is status.json, read by the CLI and the menu bar app.
type Status struct {
	Anchor     string                `json:"anchor"`
	Bridged    map[string]string     `json:"bridged"`
	Enforced   bool                  `json:"enforced"`
	Endpoints  []EndpointEntry       `json:"endpoints"`
	Errors     []string              `json:"errors"`
	Mode       string                `json:"mode"`
	Networks   []string              `json:"networks"`
	Note       *string               `json:"note"`
	PowerWatch *bool                 `json:"power_watch"`
	Release    string                `json:"release"`
	Sealed     bool                  `json:"sealed"`
	Settings   string                `json:"settings"`
	State      string                `json:"state"`
	Trusted    []TrustedEntry        `json:"trusted"`
	Tunnel     *TunnelState          `json:"tunnel"`
	Until      *int64                `json:"until"`
	Updated    int64                 `json:"updated"`
	Uplinks    map[string]StatusLink `json:"uplinks"`
	Version    int                   `json:"version"`
	VPNOnly    bool                  `json:"vpn_only"`
}

// StatusLink is an uplink with a router or trust; nil is unknown.
type StatusLink struct {
	Router  *string `json:"router"`
	MAC     *string `json:"mac"`
	Trusted bool    `json:"trusted"`
	Network *string `json:"network"`
}

// TrustedEntry is a trusted uplink and its network.
type TrustedEntry struct {
	Interface string `json:"interface"`
	Network   string `json:"network"`
}

// EndpointEntry is an endpoint in force and where it came from.
type EndpointEntry struct {
	Endpoint string `json:"endpoint"`
	Source   string `json:"source"`
}

// StateOf is what the switch does with these uplinks.
func StateOf(control Control, uplinks map[string]Link, tunnel *TunnelState, trust bool) string {
	switch {
	case control.Mode == ModeOff:
		return StateOff
	case trust && control.Mode != ModeLock && len(trustedNames(uplinks)) > 0:
		return StateTrusted
	case tunnel != nil:
		return StateTunnel
	}
	return StateBlocked
}

// status describes the step just enforced. Hold d.mu.
func (d *Daemon) status(control Control, view map[string]Link, trust bool, endpoints []Sourced,
	errs []string, enforced bool) Status {
	status := Status{
		Anchor: Anchor, Bridged: map[string]string{}, Enforced: enforced, Endpoints: []EndpointEntry{},
		Errors: append([]string{}, errs...), Mode: control.Mode, Networks: []string{}, Note: optional(control.Note),
		PowerWatch: d.powerWatch, Release: Release, Sealed: d.sealed, Settings: SettingsPath(d.config),
		State: StateOf(control, view, d.tunnel, trust), Trusted: []TrustedEntry{}, Tunnel: d.tunnel,
		Until: control.Until, Uplinks: map[string]StatusLink{}, Version: StatusVersion, VPNOnly: d.config.VPNOnly,
	}
	for _, name := range sortedKeys(view) {
		link := view[name]
		trusted := link.Trusted && trust
		if trusted {
			status.Trusted = append(status.Trusted, TrustedEntry{name, link.Network})
		}
		if link.Router != "" || trusted {
			network := ""
			if trusted {
				network = link.Network
			}
			status.Uplinks[name] = StatusLink{optional(link.Router), optional(link.MAC), trusted, optional(network)}
		}
		if bridge := d.uplinks[name].Bridged; bridge != "" && working(d.uplinks[name]) {
			status.Bridged[name] = bridge
		}
	}
	for _, network := range d.config.TrustedNetworks {
		status.Networks = append(status.Networks, network.Name)
	}
	for _, item := range endpoints {
		status.Endpoints = append(status.Endpoints, EndpointEntry{item.Endpoint.String(), item.Source})
	}
	return status
}

// notes are the standing problems worth reporting with every status. Hold d.mu.
func (d *Daemon) notes() []string {
	var notes []string
	for _, note := range []string{d.configError, d.settingsError, d.sealNote, d.idleProblem} {
		if note != "" {
			notes = append(notes, note)
		}
	}
	for _, name := range sortedKeys(d.uplinks) {
		link := d.uplinks[name]
		if link.Router != "" && link.MAC == "" && d.awaitsMAC(name, link.Router) {
			notes = append(notes, fmt.Sprintf("%s: the MAC of router %s cannot be read, so its network cannot be verified",
				name, link.Router))
		}
		// Only a working uplink matters: Thunderbolt Bridge ports without an address carry nothing.
		if link.Bridged != "" && working(link) {
			notes = append(notes, fmt.Sprintf("%s is a member of %s: bridged VMs bypass the switch", name, link.Bridged))
		}
	}
	return notes
}

// awaitsMAC reports whether a trusted network would match this uplink if its
// router's MAC were known. Hold d.mu.
func (d *Daemon) awaitsMAC(name, router string) bool {
	return slices.ContainsFunc(d.config.TrustedNetworks, func(n Network) bool {
		return n.RouterMAC != "" && (n.Router == "" || n.Router == router) && (n.Interface == "" || n.Interface == name)
	})
}

func working(link Link) bool { return len(link.V4) > 0 || link.Router != "" }

// publish logs what changed and writes the status when it changed, and at least
// every tick as a heartbeat. Step's own: no lock.
func (d *Daemon) publish(status Status) {
	if status.State != d.lastState {
		trusted := make([]string, len(status.Trusted))
		for i, entry := range status.Trusted {
			trusted[i] = entry.Interface + " (" + entry.Network + ")"
		}
		logf("state %s -> %s, mode %s, trusted %v, tunnel %s", orNone(d.lastState), status.State, status.Mode,
			trusted, tunnelText(status.Tunnel))
		d.lastState = status.State
	}
	if !slices.Equal(status.Errors, d.lastErrors) { // logged when they change, not every second
		logAll(status.Errors)
		d.lastErrors = status.Errors
	}
	now := int64(d.sys.Wall())
	if previous := d.lastStatus; previous != nil {
		unchanged := *previous
		unchanged.Updated = 0
		if reflect.DeepEqual(status, unchanged) && float64(now-previous.Updated) < tick {
			return
		}
	}
	status.Updated = now
	d.sys.Publish(status)
	d.lastStatus = &status
}

// WriteStatus writes status.json for the CLI and the menu bar app.
func WriteStatus(path string, status Status) error {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomically(path, append(data, '\n'))
}

func optional(text string) *string {
	if text == "" {
		return nil
	}
	return &text
}

func orNone(text string) string {
	if text == "" {
		return "none"
	}
	return text
}

func tunnelText(tunnel *TunnelState) string {
	if tunnel == nil {
		return "none"
	}
	return fmt.Sprintf("%s %v", tunnel.Interface, tunnel.Services)
}
