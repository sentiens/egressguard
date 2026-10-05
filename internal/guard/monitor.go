package guard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Kinds of event.
const (
	EventLeave = "leave" // something on an uplink went away or changed: trust may be gone
	EventJoin  = "join"  // something appeared: worth a look
	EventWake  = "wake"  // a full wake from sleep
)

// Event is a routing-socket message that matters, or a wake.
type Event struct {
	Kind    string
	Names   map[string]bool // the interfaces it concerns, if known
	Gateway string          // the default route's gateway, for route messages
	// Handled means the route-monitor goroutine already broke trust for it.
	Handled bool
}

func (e *Event) String() string {
	if len(e.Names) > 0 {
		return fmt.Sprint(sortedKeys(e.Names))
	}
	return e.Gateway
}

var (
	rtmHeader    = regexp.MustCompile(`(?m)^(RTM_\w+): .*$`)
	ifName       = regexp.MustCompile(`\b([a-z_]+\d+)\b`)
	notHex       = regexp.MustCompile(`[g-z_]`) // tells en0 from a hex word such as ab12
	ifIndex      = regexp.MustCompile(`(?:if#|ifscope) (\d+)`)
	defaultRoute = regexp.MustCompile(`sockaddrs: <[^>]*>\n\s*default\s+(\S+)`)
	dottedQuad   = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
)

// IndexName is the name of an interface index.
func IndexName(index int) (string, bool) {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", false
	}
	return iface.Name, true
}

// Classify turns a `route -n monitor` message into an event, or nil. Only uplink
// events count: link changes, address changes and default routes. ARP and cloned
// host routes, lookups and misses are frequent noise.
func Classify(message string, indexName func(int) (string, bool)) *Event {
	header := rtmHeader.FindStringSubmatchIndex(message)
	if header == nil {
		return nil
	}
	kind, line, body := message[header[2]:header[3]], message[header[0]:header[1]], message[header[1]:]
	names := map[string]bool{}
	for _, match := range ifName.FindAllStringSubmatch(body, -1) {
		if notHex.MatchString(match[1]) {
			names[match[1]] = true
		}
	}
	for _, match := range ifIndex.FindAllStringSubmatch(line, -1) {
		index, err := strconv.Atoi(match[1])
		if err != nil {
			continue // more digits than an index has: not one
		}
		if name, ok := indexName(index); ok {
			names[name] = true
		}
	}
	if len(names) > 0 && allInternal(names) {
		return nil
	}
	event := &Event{Names: names}
	switch kind {
	case "RTM_IFINFO", "RTM_IFINFO2":
		event.Kind = EventLeave
	case "RTM_NEWADDR":
		event.Kind = EventJoin
	case "RTM_DELADDR":
		event.Kind = EventJoin
		if containsWord(body, dottedQuad) {
			event.Kind = EventLeave // an IPv4 address is gone
		}
	case "RTM_ADD", "RTM_DELETE", "RTM_CHANGE":
		match := defaultRoute.FindStringSubmatch(message)
		if match == nil {
			return nil
		}
		// A new default route is worth a look; a default route that went away or
		// changed its gateway may mean another network.
		event.Kind, event.Gateway = EventLeave, IPv4(match[1])
		if kind == "RTM_ADD" {
			event.Kind = EventJoin
		}
	default:
		return nil
	}
	return event
}

func allInternal(names map[string]bool) bool {
	for name := range names {
		if !IsInternal(name) {
			return false
		}
	}
	return true
}

func containsWord(text string, pattern *regexp.Regexp) bool {
	for _, word := range strings.Fields(text) {
		if pattern.MatchString(word) {
			return true
		}
	}
	return false
}

// Splitter cuts `route -n monitor` output into whole messages. Each message ends
// with an empty line, so none waits for the next one to arrive.
type Splitter struct{ block []string }

// Line takes one line (with or without its newline) and returns the message it
// completes, or "".
func (s *Splitter) Line(line string) string {
	message := ""
	if strings.HasPrefix(line, "got message of size") && len(s.block) > 0 {
		message = s.flush()
	}
	if strings.TrimSpace(line) == "" {
		if len(s.block) > 0 {
			message = s.flush()
		}
		return message
	}
	s.block = append(s.block, strings.TrimSuffix(line, "\n")+"\n")
	return message
}

// Rest is a last message cut off by the end of the output, or "".
func (s *Splitter) Rest() string {
	if len(s.block) == 0 {
		return ""
	}
	return s.flush()
}

func (s *Splitter) flush() string {
	message := strings.Join(s.block, "")
	s.block = nil
	return message
}

// watchRoutes feeds classified routing-socket messages to note until stop is closed.
func watchRoutes(note func(*Event), stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		if err := readRoutes(note, stop); err != nil {
			logf("route monitor failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		time.Sleep(time.Second)
	}
}

// readRoutes runs one `route -n monitor` until its output ends or stop is closed.
func readRoutes(note func(*Event), stop <-chan struct{}) (err error) {
	path, err := ToolPath("route")
	if err != nil {
		return err
	}
	cmd := exec.Command(path, "-n", "monitor")
	cmd.Env = SystemEnv()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer func() {
		close(done)
		// The output ended or failed: end the monitor, so the next one starts clean.
		// Exiting by our kill is expected; anything else is reported.
		if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			err = errors.Join(err, killErr)
		}
		var exit *exec.ExitError
		if waitErr := cmd.Wait(); waitErr != nil && !errors.As(waitErr, &exit) {
			err = errors.Join(err, waitErr)
		}
	}()
	go func() {
		select {
		case <-stop:
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				logf("route monitor not stopped: %v", err)
			}
		case <-done:
		}
	}()
	reader := bufio.NewReader(out)
	var splitter Splitter
	for {
		line, readErr := reader.ReadString('\n')
		if message := splitter.Line(line); message != "" {
			note(Classify(message, IndexName))
		}
		if readErr != nil {
			if message := splitter.Rest(); message != "" {
				note(Classify(message, IndexName))
			}
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, os.ErrClosed) {
				return nil
			}
			return readErr
		}
	}
}
