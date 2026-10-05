package guard

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func message(header, addrs, sockaddrs string) string {
	if sockaddrs == "" {
		sockaddrs = "<DST,GATEWAY,NETMASK>"
	}
	return fmt.Sprintf("got message of size 192 on Fri Oct  2 19:29:28 2026\n%s\nlocks:  inits: \nsockaddrs: %s\n %s\n\n",
		header, sockaddrs, addrs)
}

func TestLastMessageIsNotHeldBack(t *testing.T) {
	var splitter Splitter
	var first string
	for _, line := range strings.SplitAfter(message("RTM_IFINFO: iface status change: len 112, if# 14, flags:<UP>", "x", ""), "\n") {
		if found := splitter.Line(line); found != "" && first == "" {
			first = found
		}
	}
	if !strings.Contains(first, "RTM_IFINFO") {
		t.Fatal("the message waited for the next one")
	}
}

func TestMessagesSplit(t *testing.T) {
	var splitter Splitter
	var found []string
	text := message("RTM_MISS: a", "1.1.1.1", "<DST>") + message("RTM_GET: b", "2.2.2.2", "<DST>")
	for _, line := range strings.SplitAfter(text, "\n") {
		if message := splitter.Line(line); message != "" {
			found = append(found, message)
		}
	}
	if len(found) != 2 || !strings.HasPrefix(found[1], "got message") || !strings.Contains(found[1], "RTM_GET") {
		t.Fatal(found)
	}
	if splitter.Line("got message of size 9\n") != "" || splitter.Rest() != "got message of size 9\n" {
		t.Fatal("a message cut off by the end of the output is lost")
	}
}

var indexNames = map[int]string{14: "en0", 20: "utun4", 9: "awdl0", 7: "en5"}

func classify(text string) *Event {
	return Classify(text, func(index int) (string, bool) {
		name, ok := indexNames[index]
		return name, ok
	})
}

func kindOf(text string) string {
	if event := classify(text); event != nil {
		return event.Kind
	}
	return "none"
}

func TestClassifyNoise(t *testing.T) {
	for _, text := range []string{
		message("RTM_MISS: Lookup failed on this address: len 120, pid: 0, seq 0, errno 0, flags:<DONE>", "2001:4860:4860::8888", "<DST>"),
		message("RTM_GET: Report Metrics: len 164, pid: 16025, seq 1, errno 0, flags:<UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>",
			"default 192.168.1.1 default index: 14 en0:2.0.5e.0.0.5 192.168.1.108", ""),
		message("RTM_ADD: Add Route: len 200, pid: 0, seq 0, errno 0, flags:<UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE>",
			"192.168.1.1 en0:2.0.5e.10.0.1", ""),
		message("RTM_ADD: Add Route: len 200, pid: 0, seq 0, errno 0, flags:<UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE>",
			"142.250.1.1 192.168.1.1", ""),
	} {
		if kind := kindOf(text); kind != "none" {
			t.Errorf("%s: %s", text, kind)
		}
	}
}

func TestClassifyInternalIgnored(t *testing.T) {
	for _, text := range []string{
		"RTM_IFINFO: iface status change: len 112, if# 9, flags:<UP,BROADCAST,RUNNING>\n",
		message("RTM_ADD: Add Route: len 192, pid: 0, seq 0, errno 0, ifscope 20, flags:<UP,GATEWAY,DONE,STATIC,PRCLONING,IFSCOPE>",
			"default 10.8.0.2 default", ""),
		message("RTM_DELADDR: address being removed from iface: len 64, metric 0, flags:<UP,POINTOPOINT,RUNNING>",
			"255.255.255.255 utun5 10.8.0.3 10.8.0.3", "<NETMASK,IFP,IFA,BRD>"),
	} {
		if kind := kindOf(text); kind != "none" {
			t.Errorf("%s: %s", text, kind)
		}
	}
}

func TestClassifyLeave(t *testing.T) {
	event := classify("RTM_IFINFO: iface status change: len 112, if# 14, flags:<UP,BROADCAST,SMART,RUNNING>\n")
	if event.Kind != EventLeave || !reflect.DeepEqual(event.Names, names("en0")) || event.Gateway != "" {
		t.Fatalf("%+v", event)
	}
	if kind := kindOf(message("RTM_DELADDR: address being removed from iface: len 64, metric 0, flags:<UP,BROADCAST,RUNNING>",
		"255.255.255.0 en0:2.0.5e.0.0.5 192.168.1.108 192.168.1.255", "<NETMASK,IFP,IFA,BRD>")); kind != EventLeave {
		t.Error("a lost IPv4 address:", kind)
	}
	for _, header := range []string{"RTM_DELETE: Delete Route", "RTM_CHANGE: Change Route"} {
		event = classify(message(header+": len 192, pid: 0, seq 0, errno 0, flags:<UP,GATEWAY,DONE,STATIC,PRCLONING>",
			"default 192.168.1.1 default", ""))
		if event.Kind != EventLeave || len(event.Names) != 0 || event.Gateway != "192.168.1.1" {
			t.Fatalf("%s: %+v", header, event)
		}
	}
	event = classify("RTM_IFINFO: iface status change: len 112, if# 99, flags:<>\n")
	if event.Kind != EventLeave || len(event.Names) != 0 || event.Gateway != "" {
		t.Fatalf("%+v", event)
	}
}

func TestClassifyJoin(t *testing.T) {
	if kind := kindOf(message("RTM_NEWADDR: address being added to iface: len 64, metric 0, flags:<UP,BROADCAST,RUNNING>",
		"255.255.255.0 en0:2.0.5e.0.0.5 192.168.1.108 192.168.1.255", "<NETMASK,IFP,IFA,BRD>")); kind != EventJoin {
		t.Error("a new address:", kind)
	}
	if kind := kindOf(message("RTM_DELADDR: address being removed from iface: len 64, metric 0, flags:<UP>",
		"ffff:ffff:ffff:ffff:: en0:ab.cd.12.34.56.78 fe80::1c2d:3e4f:5a6b:7c8d", "<NETMASK,IFP,IFA>")); kind != EventJoin {
		t.Error("a lost IPv6 address:", kind)
	}
	event := classify(message("RTM_ADD: Add Route: len 192, pid: 0, seq 0, errno 0, ifscope 14, flags:<UP,GATEWAY,DONE,STATIC,PRCLONING,IFSCOPE>",
		"default 192.168.1.1 default", ""))
	if event.Kind != EventJoin || !reflect.DeepEqual(event.Names, names("en0")) || event.Gateway != "192.168.1.1" {
		t.Fatalf("%+v", event)
	}
}
