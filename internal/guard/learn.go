package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// learnKeep is how long a learned connection endpoint is kept unseen, in seconds.
const learnKeep = 180 * 86400

// Sourced is an endpoint and where it came from ("config: …", "vpn: …", "connection: …").
type Sourced struct {
	Endpoint Endpoint
	Source   string
}

// EndpointSource gives the endpoints found by learning.
type EndpointSource interface {
	Endpoints(now float64) []Sourced
}

type learnedEntry struct {
	First  int64  `json:"first"`
	Last   int64  `json:"last"`
	Source string `json:"source"`
}

// Learner finds endpoints by itself.
//
//   - Every VPN configuration macOS has, from its server address. This is a live
//     view: a deleted configuration takes its endpoint with it. Host names are
//     resolved where DNS works, and the last answer is kept in learned.json.
//   - Opt-in (learn.connections): while a trusted uplink carries a running tunnel
//     provider's own connection (and the internet route is a tunnel), the remote
//     end of that connection. These are kept in learned.json (root-owned, 0644)
//     and forgotten after learnKeep seconds unseen.
type Learner struct {
	path    string
	run     Runner
	resolve func(host string) []string
	bundle  func(path string) (string, error) // the bundle ID of an executable

	saving   sync.Mutex // orders writes of learned.json; taken before mu, never under it
	mu       sync.Mutex
	entries  map[string]learnedEntry // learned connections by endpoint text
	resolved map[string][]string     // the last addresses of each host name
	services map[string]string       // VPN configuration endpoints now, with their source
}

// NewLearner loads what was learned before from path.
func NewLearner(path string, run Runner, resolve func(string) []string, bundle func(string) (string, error)) *Learner {
	l := &Learner{path: path, run: run, resolve: resolve, bundle: bundle, services: map[string]string{}}
	l.entries, l.resolved = loadLearned(path)
	return l
}

// loadLearned reads learned.json; anything unreadable is skipped.
func loadLearned(path string) (map[string]learnedEntry, map[string][]string) {
	entries, resolved := map[string]learnedEntry{}, map[string][]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return entries, resolved
	}
	var file struct {
		Endpoints map[string]json.RawMessage `json:"endpoints"`
		Resolved  map[string]json.RawMessage `json:"resolved"`
	}
	if json.Unmarshal(data, &file) != nil {
		return entries, resolved
	}
	for key, raw := range file.Endpoints {
		var entry learnedEntry
		if json.Unmarshal(raw, &entry) == nil && validEndpoint(key) {
			entries[key] = entry
		}
	}
	for host, raw := range file.Resolved {
		var addresses []any
		if json.Unmarshal(raw, &addresses) != nil {
			continue
		}
		kept := []string{}
		for _, address := range addresses {
			if text, ok := address.(string); ok {
				kept = append(kept, text)
			}
		}
		resolved[host] = kept
	}
	return entries, resolved
}

// save writes learned.json as it is now, outside l.mu: the daemon reads
// endpoints under its own lock and must not wait for the disk.
func (l *Learner) save() {
	l.saving.Lock()
	defer l.saving.Unlock()
	l.mu.Lock()
	data, err := json.MarshalIndent(map[string]any{"version": 1, "endpoints": l.entries, "resolved": l.resolved}, "", "  ")
	l.mu.Unlock()
	if err == nil {
		err = WriteAtomically(l.path, append(data, '\n'))
	}
	if err != nil {
		logf("learned endpoints not saved: %v", err)
	}
}

// Endpoints are the VPN configurations now, then the connections seen within learnKeep of now.
func (l *Learner) Endpoints(now float64) []Sourced {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found []Sourced
	for _, key := range sortedKeys(l.services) {
		found = append(found, Sourced{MustEndpoint(key), l.services[key]})
	}
	for _, key := range sortedKeys(l.entries) {
		if entry := l.entries[key]; now-float64(entry.Last) <= learnKeep {
			source := entry.Source
			if source == "" {
				source = "learned"
			}
			found = append(found, Sourced{MustEndpoint(key), source})
		}
	}
	return found
}

// Remember keeps the endpoints seen at now and forgets old ones; it reports
// whether learned.json changed.
func (l *Learner) Remember(texts []string, source string, now float64) bool {
	changed := l.remember(texts, source, now)
	if changed {
		l.save()
	}
	return changed
}

func (l *Learner) remember(texts []string, source string, now float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	changed := false
	for _, text := range texts {
		endpoint, err := ParseEndpoint(text, "endpoint")
		if err != nil {
			continue
		}
		key := endpoint.String()
		entry, known := l.entries[key]
		switch {
		case !known:
			l.entries[key] = learnedEntry{First: int64(now), Last: int64(now), Source: source}
			logf("learned %s from %s", key, source)
			changed = true
		case now-float64(entry.Last) >= 3600: // seen again: refreshed at most hourly
			entry.Last = int64(now)
			l.entries[key] = entry
			changed = true
		}
	}
	for key, entry := range l.entries {
		if now-float64(entry.Last) > learnKeep {
			delete(l.entries, key)
			changed = true
		}
	}
	return changed
}

// addresses of a host name: resolved now if allowed, else the last answer.
func (l *Learner) addresses(host string, mayResolve bool) []string {
	var fresh []string
	if mayResolve {
		fresh = l.resolve(host) // no lock held: this can take seconds
	}
	l.mu.Lock()
	changed := len(fresh) > 0 && !slices.Equal(fresh, l.resolved[host])
	if changed {
		l.resolved[host] = fresh
	}
	known := slices.Clone(l.resolved[host])
	l.mu.Unlock()
	if changed {
		l.save()
	}
	return known
}

// ScanServices takes the server address of every VPN configuration macOS has,
// right now. Host names are resolved only if mayResolve (where DNS works). If
// macOS does not answer, the previous view stays.
func (l *Learner) ScanServices(mayResolve bool) error {
	list, err := VPNServices(l.run)
	if err != nil {
		return err
	}
	services := map[string]string{}
	for _, service := range list {
		remote, provider, err := ServiceDetails(service.ID, l.run)
		if err != nil {
			return err
		}
		resolve := func(host string) []string { return l.addresses(host, mayResolve) }
		for _, text := range ServiceEndpoints(service.Kind, remote, provider, resolve) {
			if endpoint, err := ParseEndpoint(text, "endpoint"); err == nil {
				if _, seen := services[endpoint.String()]; !seen {
					services[endpoint.String()] = "vpn: " + service.Name
				}
			}
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if added, removed := missingFrom(l.services, services), missingFrom(services, l.services); len(added)+len(removed) > 0 {
		logf("vpn configurations: +%v -%v", added, removed)
	}
	l.services = services
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

// ScanConnections learns, on a trusted uplink, where running tunnel providers
// connect to at now: the provider of every connected VPN configuration, and the
// processes named in extraProcesses. Nothing is learned without a tunnel. What
// could not be read is returned as an error, after learning from the rest.
func (l *Learner) ScanConnections(uplinks map[string]Link, tunnel *TunnelState, extraProcesses []string, now float64) error {
	if tunnel == nil {
		return nil
	}
	local := map[string]bool{}
	for _, link := range uplinks {
		if link.Trusted {
			for _, item := range slices.Concat(link.V4, link.V6) {
				if prefix, err := netip.ParsePrefix(item); err == nil {
					local[prefix.Addr().String()] = true
				}
			}
		}
	}
	if len(local) == 0 {
		return nil
	}
	services, err := VPNServices(l.run)
	if err != nil {
		return err
	}
	var problems []error
	providers := map[string]string{}
	for _, service := range services {
		if !service.Connected {
			continue
		}
		_, provider, err := ServiceDetails(service.ID, l.run)
		if err != nil {
			problems = append(problems, err)
		} else if provider != "" {
			providers[provider] = service.Name
		}
	}
	pids, err := l.providerProcesses(providers, extraProcesses)
	if err != nil {
		problems = append(problems, err)
	}
	if len(pids) == 0 {
		return errors.Join(problems...)
	}
	var list []string
	for _, pid := range slices.Sorted(maps.Keys(pids)) {
		list = append(list, strconv.Itoa(pid))
	}
	// lsof exits 1 when a process has no connections: only a missing answer is a failure.
	result, err := answer(l.run, "lsof", "-nP", "-a", "-i", "-p", strings.Join(list, ","), "-F", "pcPnT")
	if err != nil {
		return errors.Join(append(problems, err)...)
	}
	rows, err := LsofConnections(result.Stdout)
	if err != nil {
		return errors.Join(append(problems, err)...)
	}
	for _, row := range rows {
		name, known := pids[row.PID]
		localHost, _, okLocal := SplitHostPort(row.Local)
		host, port, okRemote := SplitHostPort(row.Remote)
		if !known || !okLocal || !local[localHost] || !okRemote || (row.Proto != "TCP" && row.Proto != "UDP") {
			continue
		}
		if row.Proto == "TCP" && row.State != "ESTABLISHED" {
			continue
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !isGlobal(address) {
			continue
		}
		endpoint := Endpoint{Address: address.String(), Family: family(address), Port: port, Proto: strings.ToLower(row.Proto)}
		l.Remember([]string{endpoint.String()}, "connection: "+name, now)
	}
	return errors.Join(problems...)
}

// providerProcesses are the running processes of the given providers (bundle ID →
// name) and of the extra process names, as pid → the name to credit. Extensions
// whose bundle ID cannot be read are skipped and reported.
func (l *Learner) providerProcesses(providers map[string]string, extra []string) (map[int]string, error) {
	ps := l.run([]string{"ps", "-axo", "pid=,comm="}, "", 0)
	if ps.Failed() {
		return nil, &Unanswered{Command: "ps -axo pid=,comm=", Err: errors.New(ps.Error())}
	}
	pids := map[int]string{}
	var problems []error
	for _, line := range strings.Split(ps.Stdout, "\n") {
		pidText, path, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found {
			continue // an empty line
		}
		pid, err := strconv.Atoi(pidText)
		if err != nil {
			return nil, fmt.Errorf("ps: bad process id %q", pidText)
		}
		path = strings.TrimSpace(path)
		switch {
		case slices.Contains(extra, filepath.Base(path)):
			pids[pid] = filepath.Base(path)
		case strings.HasPrefix(path, "/System/") || strings.HasPrefix(path, "/usr/"):
			// Apple's own extensions are never VPN providers.
		case strings.Contains(path, ".appex/") || strings.Contains(path, ".systemextension/"):
			bundle, err := l.bundle(path)
			if err != nil {
				problems = append(problems, err)
			} else if name, ok := providers[bundle]; ok {
				pids[pid] = name
			}
		}
	}
	return pids, errors.Join(problems...)
}
