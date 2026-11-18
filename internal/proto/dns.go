package proto

import (
	"encoding/binary"
	"strings"
)

// DNSInfo holds validated DNS packet fields.
type DNSInfo struct {
	IsResponse  bool
	Questions   []string
	PayloadSize int
}

// ParseDNSPacket validates and parses a DNS wire message (RFC 1035).
// Returns (info, true) only when the entire buffer decodes cleanly as a DNS packet,
// ensuring random high-entropy payloads or OpenVPN packets cannot masquerade as DNS.
func ParseDNSPacket(data []byte) (DNSInfo, bool) {
	if len(data) < 12 {
		return DNSInfo{}, false
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	isResp := (flags & 0x8000) != 0
	opcode := (flags >> 11) & 0x0F
	if opcode > 2 {
		return DNSInfo{}, false
	}
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	ns := int(binary.BigEndian.Uint16(data[8:10]))
	ar := int(binary.BigEndian.Uint16(data[10:12]))
	if qd == 0 || qd > 16 || an > 128 || ns > 64 || ar > 64 {
		return DNSInfo{}, false
	}
	if !isResp && (an != 0 || ns != 0) {
		return DNSInfo{}, false
	}

	off := 12
	questions := make([]string, 0, qd)
	for i := 0; i < qd; i++ {
		name, nextOff, ok := readDNSName(data, off, 0)
		if !ok || nextOff+4 > len(data) {
			return DNSInfo{}, false
		}
		qtype := binary.BigEndian.Uint16(data[nextOff : nextOff+2])
		qclass := binary.BigEndian.Uint16(data[nextOff+2 : nextOff+4])
		if qtype == 0 || qclass == 0 || qclass > 255 {
			return DNSInfo{}, false
		}
		off = nextOff + 4
		if name != "" {
			questions = append(questions, strings.ToLower(name))
		}
	}

	// Verify remaining RR sections do not truncate mid-record
	totalRR := an + ns + ar
	for i := 0; i < totalRR; i++ {
		_, nextOff, ok := readDNSName(data, off, 0)
		if !ok || nextOff+10 > len(data) {
			return DNSInfo{}, false
		}
		rdLen := int(binary.BigEndian.Uint16(data[nextOff+8 : nextOff+10]))
		off = nextOff + 10 + rdLen
		if off > len(data) {
			return DNSInfo{}, false
		}
	}
	if off != len(data) {
		return DNSInfo{}, false
	}

	return DNSInfo{
		IsResponse:  isResp,
		Questions:   questions,
		PayloadSize: len(data),
	}, true
}

func readDNSName(pkt []byte, off int, depth int) (string, int, bool) {
	if depth > 10 || off >= len(pkt) {
		return "", 0, false
	}
	var labels []string
	jumped := false
	retOff := off
	steps := 0
	for off < len(pkt) {
		steps++
		if steps > 128 {
			return "", 0, false
		}
		l := int(pkt[off])
		if l == 0 {
			if !jumped {
				retOff = off + 1
			}
			return strings.Join(labels, "."), retOff, true
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				return "", 0, false
			}
			ptr := int(l&0x3F)<<8 | int(pkt[off+1])
			if ptr >= off || ptr >= len(pkt) {
				return "", 0, false
			}
			if !jumped {
				retOff = off + 2
				jumped = true
			}
			off = ptr
			depth++
			if depth > 10 {
				return "", 0, false
			}
			continue
		}
		if l > 63 || off+1+l >= len(pkt) {
			return "", 0, false
		}
		lbl := pkt[off+1 : off+1+l]
		for _, ch := range lbl {
			if ch < 0x20 || ch > 0x7e {
				return "", 0, false
			}
		}
		labels = append(labels, string(lbl))
		off += 1 + l
		if !jumped {
			retOff = off
		}
	}
	return "", 0, false
}
