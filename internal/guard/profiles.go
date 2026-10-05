package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sync"
)

// Sourced is an endpoint and where it came from ("config: …", "vpn: …").
type Sourced struct {
	Endpoint Endpoint
	Source   string
}

// EndpointSource gives endpoints the daemon did not get from its config.
type EndpointSource interface {
	Endpoints() []Sourced
}

// Profiles are the server addresses of the VPN configurations macOS has, as a
// live view: a deleted configuration takes its endpoint with it. A server given
// by host name is resolved where DNS works, and the last answer is kept in a
// file (root-owned, 0644), so the configuration still works where DNS does not:
// on a closed network, before its tunnel is up.
type Profiles struct {
	path    string
	run     Runner
	resolve func(host string) []string

	saving   sync.Mutex // orders writes of the file; taken before mu, never under it
	mu       sync.Mutex
	resolved map[string][]string // the last addresses of each host name
	services map[string]string   // endpoint text → "vpn: <configuration>"
	refused  string              // the configurations last refused, as logged
}

// resolvedFile is the file of the last addresses of host names.
type resolvedFile struct {
	Version  int                 `json:"version"`
	Resolved map[string][]string `json:"resolved"`
}

// NewProfiles starts with the addresses resolved before, kept in path. A file
// that cannot be read is reported and replaced on the next resolution.
func NewProfiles(path string, run Runner, resolve func(string) []string) *Profiles {
	resolved, err := loadResolved(path)
	if err != nil {
		logf("the last resolved VPN server addresses are not used: %v", err)
		resolved = map[string][]string{}
	}
	return &Profiles{path: path, run: run, resolve: resolve, resolved: resolved, services: map[string]string{}}
}

// loadResolved reads the file of resolved addresses; a missing file is empty.
func loadResolved(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var file resolvedFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if file.Resolved == nil {
		return map[string][]string{}, nil
	}
	return file.Resolved, nil
}

// save writes the resolved addresses as they are now, outside p.mu: the daemon
// reads endpoints under its own lock and must not wait for the disk.
func (p *Profiles) save() {
	p.saving.Lock()
	defer p.saving.Unlock()
	p.mu.Lock()
	data, err := json.MarshalIndent(resolvedFile{Version: 1, Resolved: p.resolved}, "", "  ")
	p.mu.Unlock()
	if err == nil {
		err = WriteAtomically(p.path, append(data, '\n'))
	}
	if err != nil {
		logf("resolved VPN server addresses not saved: %v", err)
	}
}

// Endpoints are the endpoints of the VPN configurations macOS has now.
func (p *Profiles) Endpoints() []Sourced {
	p.mu.Lock()
	defer p.mu.Unlock()
	var found []Sourced
	for _, key := range sortedKeys(p.services) {
		found = append(found, Sourced{MustEndpoint(key), p.services[key]})
	}
	return found
}

// addresses of a host name: resolved now if allowed, else the last answer.
func (p *Profiles) addresses(host string, mayResolve bool) []string {
	var fresh []string
	if mayResolve {
		fresh = p.resolve(host) // no lock held: this can take seconds
	}
	p.mu.Lock()
	changed := len(fresh) > 0 && !slices.Equal(fresh, p.resolved[host])
	if changed {
		p.resolved[host] = fresh
	}
	known := slices.Clone(p.resolved[host])
	p.mu.Unlock()
	if changed {
		p.save()
	}
	return known
}

// Scan takes the server address of every VPN configuration macOS has, right
// now. Host names are resolved only if mayResolve (where DNS works). If macOS
// does not answer, the previous view stays and the error is returned. A server
// address that cannot be an endpoint (a multicast address, say) is left out and
// logged when that changes.
func (p *Profiles) Scan(mayResolve bool) error {
	list, err := VPNServices(p.run)
	if err != nil {
		return err
	}
	services := map[string]string{}
	var refused []error
	for _, service := range list {
		remote, provider, err := ServiceDetails(service.ID, p.run)
		if err != nil {
			return err
		}
		resolve := func(host string) []string { return p.addresses(host, mayResolve) }
		for _, text := range ServiceEndpoints(service.Kind, remote, provider, resolve) {
			endpoint, err := ParseEndpoint(text, "VPN configuration "+service.Name)
			if err != nil {
				refused = append(refused, err)
				continue
			}
			if _, seen := services[endpoint.String()]; !seen {
				services[endpoint.String()] = "vpn: " + service.Name
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if added, removed := missingFrom(p.services, services), missingFrom(services, p.services); len(added)+len(removed) > 0 {
		logf("vpn configurations: +%v -%v", added, removed)
	}
	if text := fmt.Sprint(errors.Join(refused...)); len(refused) > 0 && text != p.refused {
		logf("vpn configuration servers left out: %s", text)
		p.refused = text
	} else if len(refused) == 0 {
		p.refused = ""
	}
	p.services = services
	return nil
}

// missingFrom are the keys of b that a lacks, sorted.
func missingFrom(a, b map[string]string) []string {
	var keys []string
	for key := range b {
		if _, ok := a[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}
