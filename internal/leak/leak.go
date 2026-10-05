// Package leak reads the leak test's packet captures and judges every outgoing packet.
package leak

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
)

// Frame is one captured Ethernet frame. Data shares memory with the capture.
type Frame struct {
	Time float64
	Data []byte
}

var (
	pcapngMagic = []byte{0x0a, 0x0d, 0x0d, 0x0a}
	pcapngLE    = []byte{0x4d, 0x3c, 0x2b, 0x1a}
)

// ErrTruncated means the capture ends in the middle of a record: the frames before
// it are returned with it.
var ErrTruncated = errors.New("the capture is cut short")

// Frames returns the Ethernet frames of a pcap or pcapng capture. A capture cut short
// returns the frames before the cut with ErrTruncated; an unknown format or a
// non-Ethernet classic pcap is an error.
func Frames(data []byte) ([]Frame, error) {
	if bytes.HasPrefix(data, pcapngMagic) {
		return pcapngFrames(data)
	}
	if len(data) < 4 {
		return nil, errors.New("not a pcap file")
	}
	var order binary.ByteOrder
	nano := false
	switch string(data[:4]) {
	case "\xd4\xc3\xb2\xa1":
		order = binary.LittleEndian
	case "\x4d\x3c\xb2\xa1":
		order, nano = binary.LittleEndian, true
	case "\xa1\xb2\xc3\xd4":
		order = binary.BigEndian
	case "\xa1\xb2\x3c\x4d":
		order, nano = binary.BigEndian, true
	default:
		return nil, errors.New("not a pcap file")
	}
	if len(data) < 24 {
		return nil, errors.New("pcap header is cut short")
	}
	if order.Uint32(data[20:24]) != 1 {
		return nil, errors.New("capture is not Ethernet")
	}
	scale := 1e6
	if nano {
		scale = 1e9
	}
	var frames []Frame
	offset := 24
	for offset+16 <= len(data) {
		seconds, fraction := order.Uint32(data[offset:]), order.Uint32(data[offset+4:])
		captured := uint64(order.Uint32(data[offset+8:]))
		if uint64(offset+16)+captured > uint64(len(data)) {
			break
		}
		start, end := offset+16, offset+16+int(captured)
		frames = append(frames, Frame{float64(seconds) + float64(fraction)/scale, data[start:end]})
		offset = end
	}
	if offset != len(data) {
		return frames, ErrTruncated
	}
	return frames, nil
}

type iface struct {
	linktype   uint16
	resolution float64
}

// pcapngFrames walks the blocks of a pcapng capture: Ethernet packets of every section.
func pcapngFrames(data []byte) ([]Frame, error) {
	var order binary.ByteOrder = binary.LittleEndian
	var units []iface
	var frames []Frame
	offset := 0
	for offset+12 <= len(data) {
		kind := order.Uint32(data[offset:])
		if kind == 0x0A0D0D0A {
			order = binary.BigEndian
			if bytes.Equal(data[offset+8:offset+12], pcapngLE) {
				order = binary.LittleEndian
			}
			units = nil
		}
		length := uint64(order.Uint32(data[offset+4:]))
		if length < 12 || uint64(offset)+length > uint64(len(data)) {
			return frames, ErrTruncated
		}
		body := data[offset+8 : offset+int(length)-4]
		switch kind {
		case 1:
			unit, err := interfaceBlock(body, order)
			if err != nil {
				return frames, err
			}
			units = append(units, unit)
		case 6:
			if len(body) < 20 {
				return frames, ErrTruncated
			}
			unit := iface{1, 1e6}
			if n := order.Uint32(body); uint64(n) < uint64(len(units)) {
				unit = units[n]
			}
			if unit.linktype == 1 {
				stamp := uint64(order.Uint32(body[4:]))<<32 | uint64(order.Uint32(body[8:]))
				end := 20 + uint64(order.Uint32(body[12:]))
				if end > uint64(len(body)) {
					return frames, ErrTruncated // the block is shorter than its packet
				}
				frames = append(frames, Frame{float64(stamp) / unit.resolution, body[20:end]})
			}
		}
		offset += int(length)
	}
	if offset != len(data) {
		return frames, ErrTruncated
	}
	return frames, nil
}

// interfaceBlock reads the link type and the if_tsresol option (units per second) of an
// interface description block.
func interfaceBlock(body []byte, order binary.ByteOrder) (iface, error) {
	if len(body) < 2 {
		return iface{}, errors.New("broken pcapng interface block")
	}
	unit := iface{order.Uint16(body), 1e6}
	for position := 8; position+4 <= len(body); {
		code, size := order.Uint16(body[position:]), int(order.Uint16(body[position+2:]))
		if code == 0 {
			break
		}
		if code == 9 && size >= 1 {
			if position+4 >= len(body) {
				return iface{}, errors.New("broken pcapng interface block")
			}
			raw := body[position+4]
			if raw&0x80 != 0 {
				unit.resolution = math.Ldexp(1, int(raw&0x7f))
			} else {
				unit.resolution = math.Pow10(int(raw))
			}
		}
		position += 4 + (size+3)/4*4
	}
	return unit, nil
}

// Packet is what the leak test needs to know about one IP packet.
type Packet struct {
	SrcMAC       string // lower-case aa:bb:cc:dd:ee:ff
	Family       string // "inet" or "inet6"
	Proto        int
	Src, Dst     netip.Addr
	HasPorts     bool
	Sport, Dport int
	HasICMP      bool
	ICMP         int
}

// tail is data[from:], empty when from is past the end.
func tail(data []byte, from int) []byte {
	if from >= len(data) {
		return nil
	}
	return data[from:]
}

// ParseFrame returns nil for frames that are not IPv4/IPv6 or too short.
func ParseFrame(frame []byte) *Packet {
	if len(frame) < 14 {
		return nil
	}
	m := frame[6:12]
	found := &Packet{SrcMAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])}
	ethertype, offset := binary.BigEndian.Uint16(frame[12:]), 14
	for (ethertype == 0x8100 || ethertype == 0x88a8) && len(frame) >= offset+4 {
		ethertype, offset = binary.BigEndian.Uint16(frame[offset+2:]), offset+4
	}
	packet := frame[offset:]
	var payload []byte
	switch {
	case ethertype == 0x0800 && len(packet) >= 20:
		found.Family, found.Proto = "inet", int(packet[9])
		found.Src = netip.AddrFrom4([4]byte(packet[12:16]))
		found.Dst = netip.AddrFrom4([4]byte(packet[16:20]))
		payload = tail(packet, int(packet[0]&0x0f)*4)
	case ethertype == 0x86dd && len(packet) >= 40:
		proto := packet[6]
		payload = packet[40:]
		for (proto == 0 || proto == 43 || proto == 60) && len(payload) >= 8 {
			proto, payload = payload[0], tail(payload, (int(payload[1])+1)*8)
		}
		if proto == 44 && len(payload) >= 8 {
			proto, payload = payload[0], payload[8:]
		}
		found.Family, found.Proto = "inet6", int(proto)
		found.Src = netip.AddrFrom16([16]byte(packet[8:24]))
		found.Dst = netip.AddrFrom16([16]byte(packet[24:40]))
	default:
		return nil
	}
	switch {
	case (found.Proto == 6 || found.Proto == 17) && len(payload) >= 4:
		found.HasPorts = true
		found.Sport, found.Dport = int(binary.BigEndian.Uint16(payload)), int(binary.BigEndian.Uint16(payload[2:]))
	case (found.Proto == 1 || found.Proto == 58) && len(payload) > 0:
		found.HasICMP, found.ICMP = true, int(payload[0])
	}
	return found
}

var protocols = map[int]string{6: "tcp", 17: "udp", 50: "esp"}

// ProtoName names an IP protocol: "tcp", "udp", "esp", else its number.
func ProtoName(proto int) string {
	if name, ok := protocols[proto]; ok {
		return name
	}
	return strconv.Itoa(proto)
}

func prefixes(texts ...string) []netip.Prefix {
	found := make([]netip.Prefix, len(texts))
	for i, text := range texts {
		found[i] = netip.MustParsePrefix(text)
	}
	return found
}

var (
	local  = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")
	local6 = prefixes("fe80::/10", "fc00::/7", "ff00::/8")
)

func within(addr netip.Addr, networks []netip.Prefix) bool {
	for _, n := range networks {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// Endpoint is what the switch lets out on a closed uplink. Port 0 means any port.
type Endpoint struct {
	Address, Family, Proto string
	Port                   int
}

// Verdict judges an outgoing packet: "allowed", "local" (it got past pf but stays
// on the local network) or "internet" (a leak).
func Verdict(p *Packet, endpoints []Endpoint, routers map[string]bool) string {
	proto, known := protocols[p.Proto]
	dst := p.Dst.String()
	for _, e := range endpoints {
		if known && e.Family == p.Family && e.Address == dst && e.Proto == proto &&
			(e.Port == 0 || p.HasPorts && e.Port == p.Dport) {
			return "allowed"
		}
	}
	if p.Family == "inet" && proto == "udp" && p.HasPorts && p.Sport == 68 && p.Dport == 67 {
		return "allowed"
	}
	if p.Family == "inet" && p.Proto == 1 && p.HasICMP && p.ICMP == 8 && (within(p.Dst, local) || routers[dst]) {
		return "allowed"
	}
	if p.Family == "inet6" && p.Proto == 58 && p.HasICMP {
		switch p.ICMP {
		case 133, 134, 135, 136, 137, 143:
			return "allowed"
		}
	}
	var isLocal bool
	if p.Family == "inet" {
		isLocal = within(p.Dst, local) || p.Dst.IsMulticast() || p.Dst == netip.AddrFrom4([4]byte{255, 255, 255, 255})
	} else {
		isLocal = within(p.Dst, local6)
	}
	if isLocal {
		return "local"
	}
	return "internet"
}
