package leak

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const myMAC = "02:00:5e:00:00:05"

func ethernet(srcMAC string, payload []byte, ethertype uint16) []byte {
	frame := make([]byte, 6, 14+len(payload))
	for _, part := range strings.Split(srcMAC, ":") {
		var b byte
		for _, c := range part {
			b = b<<4 | byte(strings.IndexRune("0123456789abcdef", c))
		}
		frame = append(frame, b)
	}
	frame = binary.BigEndian.AppendUint16(frame, ethertype)
	return append(frame, payload...)
}

func ipv4Packet(src, dst string, proto byte, body []byte) []byte {
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	packet := []byte{0x45, 0, 0, byte(20 + len(body)), 0, 0, 0, 0, 64, proto, 0, 0}
	packet = append(append(packet, s[:]...), d[:]...)
	return append(packet, body...)
}

func ipv6Packet(src, dst string, proto byte, body []byte) []byte {
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	packet := binary.BigEndian.AppendUint16([]byte{0x60, 0, 0, 0}, uint16(len(body)))
	packet = append(append(append(packet, proto, 64), s[:]...), d[:]...)
	return append(packet, body...)
}

// ports is struct.pack('!HH', sport, dport) followed by zero bytes.
func ports(sport, dport uint16, pad int) []byte {
	b := binary.BigEndian.AppendUint16(nil, sport)
	return append(binary.BigEndian.AppendUint16(b, dport), make([]byte, pad)...)
}

func icmp(kind byte) []byte { return append([]byte{kind, 0}, make([]byte, 6)...) }

var frames = [][]byte{
	ethernet(myMAC, ipv4Packet("192.168.1.57", "198.51.100.61", 17, ports(50000, 51820, 4)), 0x0800),
	ethernet(myMAC, ipv4Packet("192.168.1.57", "1.1.1.1", 6, ports(50001, 443, 16)), 0x0800),
	ethernet(myMAC, ipv4Packet("0.0.0.0", "255.255.255.255", 17, ports(68, 67, 4)), 0x0800),
	ethernet(myMAC, ipv4Packet("192.168.1.57", "192.168.1.1", 1, icmp(8)), 0x0800),
	ethernet(myMAC, ipv4Packet("192.168.1.57", "8.8.8.8", 1, icmp(8)), 0x0800),
	ethernet(myMAC, ipv4Packet("192.168.1.57", "224.0.0.251", 17, ports(5353, 5353, 4)), 0x0800),
	ethernet(myMAC, ipv6Packet("fe80::1", "ff02::2", 58, icmp(133)), 0x86dd),
	ethernet(myMAC, ipv6Packet("2001:db8::5", "2606:4700::1111", 6, ports(50002, 443, 16)), 0x86dd),
	ethernet("02:00:5e:10:00:01", ipv4Packet("1.1.1.1", "192.168.1.57", 6, ports(443, 50001, 16)), 0x0800),
}

// pcap builds a classic capture; magic picks byte order and timestamp units.
func pcapWith(order binary.AppendByteOrder, magic uint32, linktype uint32, list [][]byte, start float64) []byte {
	data := order.AppendUint32(nil, magic)
	data = order.AppendUint16(data, 2)
	data = order.AppendUint16(data, 4)
	data = order.AppendUint32(data, 0)
	data = order.AppendUint32(data, 0)
	data = order.AppendUint32(data, 65535)
	data = order.AppendUint32(data, linktype)
	for i, frame := range list {
		for _, v := range []uint32{uint32(start) + uint32(i), 0, uint32(len(frame)), uint32(len(frame))} {
			data = order.AppendUint32(data, v)
		}
		data = append(data, frame...)
	}
	return data
}

func pcap(list [][]byte) []byte {
	return pcapWith(binary.LittleEndian, 0xa1b2c3d4, 1, list, 100)
}

func block(kind uint32, body []byte) []byte {
	body = append(body, make([]byte, (4-len(body)%4)%4)...)
	data := binary.LittleEndian.AppendUint32(nil, kind)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(body)+12))
	data = append(data, body...)
	return binary.LittleEndian.AppendUint32(data, uint32(len(body)+12))
}

func le(values ...any) []byte {
	var b bytes.Buffer
	for _, v := range values {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			panic(err) // a fixture with a value of no fixed size
		}
	}
	return b.Bytes()
}

// pcapngWith builds a capture of one interface; options go into its description block and
// perSecond is the timestamp unit they declare.
func pcapngWith(options []byte, perSecond float64, list [][]byte, start float64) []byte {
	data := block(0x0A0D0D0A, le(uint32(0x1A2B3C4D), uint16(1), uint16(0), int64(-1)))
	data = append(data, block(1, append(le(uint16(1), uint16(0), uint32(65535)), options...))...)
	data = append(data, block(0x80000001, []byte("apple process info"))...)
	for i, frame := range list {
		units := uint64((start + float64(i)) * perSecond)
		body := le(uint32(0), uint32(units>>32), uint32(units), uint32(len(frame)), uint32(len(frame)))
		data = append(data, block(6, append(body, frame...))...)
	}
	return data
}

func pcapng(list [][]byte) []byte { return pcapngWith(nil, 1e6, list, 100) }

var makers = map[string]func([][]byte) []byte{"pcap": pcap, "pcapng": pcapng}

func TestPcapFormats(t *testing.T) {
	for name, maker := range makers {
		got, err := Frames(maker(frames))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(frames) {
			t.Fatalf("%s: %d frames, want %d", name, len(got), len(frames))
		}
		if math.Abs(got[3].Time-103.0) > 5e-4 {
			t.Errorf("%s: time %v, want 103", name, got[3].Time)
		}
		if !bytes.Equal(got[1].Data, frames[1]) {
			t.Errorf("%s: frame 1 differs", name)
		}
	}
}

func TestVerdicts(t *testing.T) {
	endpoints := []Endpoint{{Address: "198.51.100.61", Family: "inet", Proto: "udp", Port: 51820}}
	var verdicts []string
	for _, frame := range frames {
		packet := ParseFrame(frame)
		if packet.SrcMAC == myMAC {
			verdicts = append(verdicts, Verdict(packet, endpoints, nil))
		} else {
			verdicts = append(verdicts, "inbound")
		}
	}
	want := []string{"allowed", "internet", "allowed", "allowed", "internet", "local", "allowed", "internet", "inbound"}
	if !reflect.DeepEqual(verdicts, want) {
		t.Errorf("verdicts %v, want %v", verdicts, want)
	}
	ping := ParseFrame(ethernet(myMAC, ipv4Packet("203.0.113.7", "203.0.113.1", 1, icmp(8)), 0x0800))
	if a, b := Verdict(ping, endpoints, nil), Verdict(ping, endpoints, map[string]bool{"203.0.113.1": true}); a != "internet" || b != "allowed" {
		t.Errorf("ping to the router: %s, %s", a, b)
	}
	dns := ParseFrame(ethernet(myMAC, ipv6Packet("fd00::5", "2001:4860:4860::8888", 17, ports(5000, 53, 4)), 0x86dd))
	if v := Verdict(dns, endpoints, nil); v != "internet" { // 2001::/23 is not "local"
		t.Errorf("dns: %s", v)
	}
	ula := ParseFrame(ethernet(myMAC, ipv6Packet("fd00::5", "fd00::1", 17, ports(5000, 53, 4)), 0x86dd))
	if v := Verdict(ula, endpoints, nil); v != "local" {
		t.Errorf("ula: %s", v)
	}
	broadcast := ParseFrame(ethernet(myMAC, ipv4Packet("203.0.113.7", "255.255.255.255", 17, ports(5000, 9, 4)), 0x0800))
	if v := Verdict(broadcast, endpoints, nil); v != "local" {
		t.Errorf("broadcast: %s", v)
	}
}

func TestCutShortCaptures(t *testing.T) {
	for name, maker := range makers {
		data := maker(frames)
		got, err := Frames(data[:len(data)-7])
		if !errors.Is(err, ErrTruncated) || len(got) != len(frames)-1 {
			t.Errorf("%s: %d frames, %v; want %d", name, len(got), err, len(frames)-1)
		}
	}
}

func TestParseFrame(t *testing.T) {
	p := ParseFrame(frames[7])
	if p.Family != "inet6" || p.Proto != 6 || p.Dst.String() != "2606:4700::1111" || !p.HasPorts || p.Dport != 443 {
		t.Errorf("got %+v", p)
	}
	if ParseFrame([]byte("short")) != nil {
		t.Error("a short frame parsed")
	}
}

func TestTruncatedInputDoesNotPanic(t *testing.T) {
	for i, frame := range frames {
		for n := 0; n <= len(frame); n++ {
			cut := frame[:n]
			ParseFrame(cut)
			garbage := append([]byte(nil), cut...)
			for j := range garbage {
				garbage[j] ^= byte(j*37 + i)
			}
			ParseFrame(garbage)
		}
	}
	for name, maker := range makers {
		data := maker(frames)
		for n := 0; n <= len(data); n++ {
			// Past the file header, a cut between records is a whole capture, and a cut
			// inside one is reported as such: nothing else.
			_, err := Frames(data[:n])
			if (name == "pcapng" && n >= 4 || n >= 24) && err != nil && !errors.Is(err, ErrTruncated) {
				t.Errorf("%s cut at %d: %v", name, n, err)
			}
		}
		if _, err := Frames(data); err != nil {
			t.Errorf("%s: a whole capture: %v", name, err)
		}
	}
	for n := 0; n < 4096; n++ {
		garbage := make([]byte, n%300)
		for j := range garbage {
			garbage[j] = byte(n*131 + j*j*7)
		}
		for _, data := range [][]byte{garbage, append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, garbage...),
			append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, garbage...)} {
			// Garbage must not panic, and what it yields must lie within it.
			frames, err := Frames(data)
			for _, frame := range frames {
				if err == nil && len(frame.Data) > len(data) {
					t.Fatalf("a frame of %d bytes from %d bytes", len(frame.Data), len(data))
				}
			}
		}
	}
}

func TestIPv6ExtensionHeadersPastTheEnd(t *testing.T) {
	// A hop-by-hop header claiming 2 KB, then a fragment header: no ports, no panic.
	hop := ethernet(myMAC, ipv6Packet("2001:db8::5", "2001:db8::6", 0, []byte{17, 255, 0, 0, 0, 0, 0, 0}), 0x86dd)
	if p := ParseFrame(hop); p == nil || p.Proto != 17 || p.HasPorts {
		t.Errorf("hop-by-hop: %+v", p)
	}
	frag := ethernet(myMAC, ipv6Packet("2001:db8::5", "2001:db8::6", 44, append([]byte{6, 0, 0, 0, 0, 0, 0, 1}, ports(1, 443, 0)...)), 0x86dd)
	if p := ParseFrame(frag); p == nil || p.Proto != 6 || !p.HasPorts || p.Dport != 443 {
		t.Errorf("fragment: %+v", p)
	}
	// IHL past the end of the packet leaves no payload.
	ihl := ipv4Packet("192.168.1.57", "1.1.1.1", 6, nil)
	ihl[0] = 0x4f
	if p := ParseFrame(ethernet(myMAC, ihl, 0x0800)); p == nil || p.HasPorts {
		t.Errorf("ihl: %+v", p)
	}
}

func TestBigEndianAndNanosecondPcap(t *testing.T) {
	cases := []struct {
		order interface {
			binary.ByteOrder
			binary.AppendByteOrder
		}
		magic uint32
	}{
		{binary.BigEndian, 0xa1b2c3d4},
		{binary.LittleEndian, 0xa1b23c4d},
		{binary.BigEndian, 0xa1b23c4d},
	}
	for _, c := range cases {
		data := pcapWith(c.order, c.magic, 1, frames, 100)
		c.order.PutUint32(data[24+4:], 500_000_000) // fraction of the first frame
		got, err := Frames(data)
		if err != nil || len(got) != len(frames) || !bytes.Equal(got[8].Data, frames[8]) {
			t.Fatalf("%x %v: %d frames, %v", c.magic, c.order, len(got), err)
		}
		want := 100.5
		if c.magic == 0xa1b2c3d4 {
			want = 600 // microseconds: 500 000 000 of them
		}
		if math.Abs(got[0].Time-want) > 1e-6 || got[3].Time != 103 {
			t.Errorf("%x %v: times %v, %v", c.magic, c.order, got[0].Time, got[3].Time)
		}
	}
	if _, err := Frames(pcapWith(binary.LittleEndian, 0xa1b2c3d4, 105, frames, 100)); err == nil {
		t.Error("a Wi-Fi capture was accepted")
	}
	if _, err := Frames([]byte("not a capture at all")); err == nil {
		t.Error("garbage was accepted")
	}
}

func TestPcapngResolutions(t *testing.T) {
	cases := []struct {
		raw       byte
		perSecond float64
	}{{9, 1e9}, {6, 1e6}, {0x80 | 10, 1024}}
	for _, c := range cases {
		options := append(le(uint16(9), uint16(1)), c.raw, 0, 0, 0)
		options = append(options, le(uint16(0), uint16(0))...)
		got, err := Frames(pcapngWith(options, c.perSecond, frames, 1_700_000_000))
		if err != nil || len(got) != len(frames) {
			t.Fatalf("tsresol %#x: %d frames, %v", c.raw, len(got), err)
		}
		if math.Abs(got[3].Time-1_700_000_003) > 1e-3 {
			t.Errorf("tsresol %#x: time %v", c.raw, got[3].Time)
		}
	}
}

func TestPcapngSkipsOtherInterfaces(t *testing.T) {
	data := pcapng(frames[:2])
	// A second, non-Ethernet interface and a packet on it.
	data = append(data, block(1, le(uint16(105), uint16(0), uint32(65535)))...)
	body := le(uint32(1), uint32(0), uint32(5), uint32(len(frames[2])), uint32(len(frames[2])))
	data = append(data, block(6, append(body, frames[2]...))...)
	got, err := Frames(data)
	if err != nil || len(got) != 2 {
		t.Errorf("%d frames, %v", len(got), err)
	}
}

func TestPcapngBigEndianSection(t *testing.T) {
	be := func(values ...any) []byte {
		var b bytes.Buffer
		for _, v := range values {
			if err := binary.Write(&b, binary.BigEndian, v); err != nil {
				panic(err) // a fixture with a value of no fixed size
			}
		}
		return b.Bytes()
	}
	bblock := func(kind uint32, body []byte) []byte {
		body = append(body, make([]byte, (4-len(body)%4)%4)...)
		return append(append(be(kind, uint32(len(body)+12)), body...), be(uint32(len(body)+12))...)
	}
	data := bblock(0x0A0D0D0A, be(uint32(0x1A2B3C4D), uint16(1), uint16(0), int64(-1)))
	data = append(data, bblock(1, be(uint16(1), uint16(0), uint32(65535)))...)
	frame := frames[0]
	data = append(data, bblock(6, append(be(uint32(0), uint32(0), uint32(7_000_000), uint32(len(frame)), uint32(len(frame))), frame...))...)
	got, err := Frames(data)
	if err != nil || len(got) != 1 || got[0].Time != 7 || !bytes.Equal(got[0].Data, frame) {
		t.Errorf("%+v, %v", got, err)
	}
}

func TestVLANTaggedFrame(t *testing.T) {
	inner := ethernet(myMAC, ipv4Packet("192.168.1.57", "1.1.1.1", 17, ports(5000, 53, 4)), 0x0800)
	// 802.1ad outer tag, 802.1Q inner tag, then IPv4.
	tagged := append(append([]byte(nil), inner[:12]...), 0x88, 0xa8, 0, 10, 0x81, 0x00, 0, 20, 0x08, 0x00)
	tagged = append(tagged, inner[14:]...)
	p := ParseFrame(tagged)
	if p == nil || p.Family != "inet" || p.Dst.String() != "1.1.1.1" || p.Dport != 53 || p.SrcMAC != myMAC {
		t.Errorf("got %+v", p)
	}
}

func TestVerdictPorts(t *testing.T) {
	esp := ParseFrame(ethernet(myMAC, ipv4Packet("192.168.1.57", "203.0.113.9", 50, make([]byte, 8)), 0x0800))
	anyPort := []Endpoint{{Address: "203.0.113.9", Family: "inet", Proto: "esp"}}
	withPort := []Endpoint{{Address: "203.0.113.9", Family: "inet", Proto: "esp", Port: 500}}
	if a, b := Verdict(esp, anyPort, nil), Verdict(esp, withPort, nil); a != "allowed" || b != "internet" {
		t.Errorf("esp: %s, %s", a, b)
	}
	if got := []string{ProtoName(6), ProtoName(17), ProtoName(50), ProtoName(1)}; !reflect.DeepEqual(got, []string{"tcp", "udp", "esp", "1"}) {
		t.Errorf("names %v", got)
	}
}

func TestPcapngPacketLongerThanItsBlock(t *testing.T) {
	data := pcapng(frames[:1])
	// The enhanced packet block's captured length sits 20 bytes into its body; claim more.
	at := bytes.LastIndex(data, frames[0]) - 8
	binary.LittleEndian.PutUint32(data[at:], uint32(len(frames[0])+100))
	if _, err := Frames(data); !errors.Is(err, ErrTruncated) {
		t.Fatal(err)
	}
}
