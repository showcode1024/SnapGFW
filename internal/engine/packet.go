package engine

import (
	"encoding/binary"
	"net"
)

const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
)

// ParsedPacket holds zero-copy slices pointing into the raw IP packet buffer.
type ParsedPacket struct {
	IPVersion uint8 // 4 or 6
	L4Proto   uint8 // 6 (TCP) or 17 (UDP)
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	TCPSeq    uint32
	TCPFlags  uint8
	Payload   []byte
	IsFrag    bool
}

// ParseIPPacket parses IPv4/IPv6 + TCP/UDP headers with zero heap allocations for payload.
func ParseIPPacket(data []byte) (ParsedPacket, bool) {
	var p ParsedPacket
	if len(data) < 20 {
		return p, false
	}
	ver := data[0] >> 4
	p.IPVersion = ver

	var l4Off int
	var l4End int

	switch ver {
	case 4:
		ihl := int(data[0]&0x0f) * 4
		if ihl < 20 || len(data) < ihl {
			return p, false
		}
		totLen := int(binary.BigEndian.Uint16(data[2:4]))
		if totLen < ihl || totLen > len(data) {
			totLen = len(data)
		}
		fragOff := binary.BigEndian.Uint16(data[6:8]) & 0x1fff
		if fragOff != 0 {
			p.IsFrag = true
			return p, true
		}
		p.L4Proto = data[9]
		p.SrcIP = net.IP(data[12:16])
		p.DstIP = net.IP(data[16:20])
		l4Off = ihl
		l4End = totLen

	case 6:
		if len(data) < 40 {
			return p, false
		}
		pLen := int(binary.BigEndian.Uint16(data[4:6]))
		l4End = 40 + pLen
		if l4End > len(data) {
			l4End = len(data)
		}
		p.SrcIP = net.IP(data[8:24])
		p.DstIP = net.IP(data[24:40])
		nextHdr := data[6]
		off := 40
		for step := 0; step < 8; step++ {
			switch nextHdr {
			case 6, 17: // TCP or UDP
				p.L4Proto = nextHdr
				l4Off = off
				step = 8
			case 0, 43, 60: // Hop-by-Hop, Routing, DestOpts
				if off+2 > l4End {
					return p, false
				}
				hdrLen := (int(data[off+1]) + 1) * 8
				if off+hdrLen > l4End {
					return p, false
				}
				nextHdr = data[off]
				off += hdrLen
			case 44: // Fragment header (8 bytes)
				if off+8 > l4End {
					return p, false
				}
				fragVal := binary.BigEndian.Uint16(data[off+2 : off+4])
				if fragVal&0xfff8 != 0 {
					p.IsFrag = true
					return p, true
				}
				nextHdr = data[off]
				off += 8
			case 51: // AH
				if off+2 > l4End {
					return p, false
				}
				hdrLen := (int(data[off+1]) + 2) * 4
				if off+hdrLen > l4End {
					return p, false
				}
				nextHdr = data[off]
				off += hdrLen
			default:
				p.L4Proto = nextHdr
				return p, true
			}
		}
		if p.L4Proto != 6 && p.L4Proto != 17 {
			return p, true
		}

	default:
		return p, false
	}

	if l4Off >= l4End {
		return p, false
	}
	l4 := data[l4Off:l4End]
	switch p.L4Proto {
	case 6: // TCP
		if len(l4) < 20 {
			return p, false
		}
		doff := int(l4[12]>>4) * 4
		if doff < 20 || doff > len(l4) {
			return p, false
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4[2:4])
		p.TCPSeq = binary.BigEndian.Uint32(l4[4:8])
		p.TCPFlags = l4[13]
		p.Payload = l4[doff:]
		return p, true

	case 17: // UDP
		if len(l4) < 8 {
			return p, false
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4[2:4])
		udpLen := int(binary.BigEndian.Uint16(l4[4:6]))
		if udpLen < 8 || udpLen > len(l4) {
			udpLen = len(l4)
		}
		p.Payload = l4[8:udpLen]
		return p, true

	default:
		return p, true
	}
}
