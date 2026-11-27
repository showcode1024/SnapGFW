package proto

import (
	"encoding/binary"
	"fmt"
	"net"
)

// VLESSParseStatus indicates passive VLESS request header parsing progress.
type VLESSParseStatus int

const (
	VLESSNotVLESS VLESSParseStatus = iota
	VLESSNeedMore
	VLESSMatched
)

// DetectVLESSHeader passively inspects the start of a raw TCP stream or unmasked WebSocket
// payload for an unencrypted VLESS v0 request header:
//
//	[1B version=0x00][16B UUID][1B addons_len][addons][1B cmd][2B port][1B addr_type][addr][payload...]
//
// It strictly validates UUID randomness, protobuf addons framing, command, port, and destination
// syntax (or inner protocol payload for raw IP targets) to prevent false positives on benign binary
// protocols. REALITY-wrapped VLESS starts with a TLS 1.3 ClientHello (0x16 0x03) and never matches.
func DetectVLESSHeader(b []byte) (VLESSParseStatus, string) {
	if len(b) == 0 {
		return VLESSNeedMore, ""
	}
	if b[0] != 0x00 {
		return VLESSNotVLESS, ""
	}
	// Once we have the 16-byte UUID, verify it has enough distinct bytes to exclude
	// zero-padded binary framing (e.g. PostgreSQL, SMB, Java RMI, length-prefixed RPC).
	if len(b) >= 17 {
		if distinctByteCount(b[1:17]) < 8 {
			return VLESSNotVLESS, ""
		}
	}
	if len(b) < 18 {
		return VLESSNeedMore, ""
	}

	addonLen := int(b[17])
	if addonLen > 64 {
		return VLESSNotVLESS, ""
	}
	pos := 18
	if len(b) < pos+addonLen+1 {
		return VLESSNeedMore, ""
	}
	if addonLen > 0 && !isValidVLESSAddons(b[pos:pos+addonLen]) {
		return VLESSNotVLESS, ""
	}
	pos += addonLen

	cmd := b[pos]
	pos++
	switch cmd {
	case 0x01, 0x02: // TCP / UDP
		cmdName := "tcp"
		if cmd == 0x02 {
			cmdName = "udp"
		}
		if len(b) < pos+3 {
			return VLESSNeedMore, ""
		}
		port := binary.BigEndian.Uint16(b[pos : pos+2])
		if port == 0 {
			return VLESSNotVLESS, ""
		}
		addrType := b[pos+2]
		pos += 3

		switch addrType {
		case 0x02: // Domain name
			if len(b) < pos+1 {
				return VLESSNeedMore, ""
			}
			dlen := int(b[pos])
			pos++
			if dlen < 4 || dlen > 253 {
				return VLESSNotVLESS, ""
			}
			if len(b) < pos+dlen {
				return VLESSNeedMore, ""
			}
			domain := string(b[pos : pos+dlen])
			if !isStrictVLESSDomain(domain) {
				return VLESSNotVLESS, ""
			}
			return VLESSMatched, fmt.Sprintf("vless %s->%s:%d", cmdName, domain, port)

		case 0x01: // IPv4
			if len(b) < pos+4 {
				return VLESSNeedMore, ""
			}
			ip := net.IP(b[pos : pos+4])
			if ip.IsUnspecified() {
				return VLESSNotVLESS, ""
			}
			tail := b[pos+4:]
			if len(tail) < 3 {
				return VLESSNeedMore, ""
			}
			if !looksLikeVLESSInnerPayload(tail) {
				return VLESSNotVLESS, ""
			}
			return VLESSMatched, fmt.Sprintf("vless %s->%s:%d", cmdName, ip.String(), port)

		case 0x03: // IPv6
			if len(b) < pos+16 {
				return VLESSNeedMore, ""
			}
			ip := net.IP(b[pos : pos+16])
			if ip.IsUnspecified() {
				return VLESSNotVLESS, ""
			}
			tail := b[pos+16:]
			if len(tail) < 3 {
				return VLESSNeedMore, ""
			}
			if !looksLikeVLESSInnerPayload(tail) {
				return VLESSNotVLESS, ""
			}
			return VLESSMatched, fmt.Sprintf("vless %s->[%s]:%d", cmdName, ip.String(), port)

		default:
			return VLESSNotVLESS, ""
		}

	case 0x03: // Xray Mux (followed by 2B metadata length + 2B session ID + 1B status + 1B option)
		if len(b) < pos+6 {
			return VLESSNeedMore, ""
		}
		metaLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		status := b[pos+4]
		opt := b[pos+5]
		if metaLen < 4 || metaLen > 300 || status != 0x01 || opt > 0x02 {
			return VLESSNotVLESS, ""
		}
		// Mux "New" frame with target address: [1B netType 1=tcp/2=udp][2B port][1B addrType]...
		if metaLen >= 8 {
			if len(b) < pos+2+metaLen {
				return VLESSNeedMore, ""
			}
			netType := b[pos+6]
			if netType != 0x01 && netType != 0x02 {
				return VLESSNotVLESS, ""
			}
			return VLESSMatched, "vless mux"
		}
		return VLESSNotVLESS, ""

	default:
		return VLESSNotVLESS, ""
	}
}

func distinctByteCount(b []byte) int {
	var seen [256]bool
	cnt := 0
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			cnt++
		}
	}
	return cnt
}

// isValidVLESSAddons checks that non-empty VLESS addons decode as valid protobuf length-delimited
// fields (field 1: Flow string, field 2: Seed bytes).
func isValidVLESSAddons(addons []byte) bool {
	i := 0
	for i < len(addons) {
		tag := addons[i]
		if tag != 0x0a && tag != 0x12 {
			return false
		}
		i++
		if i >= len(addons) {
			return false
		}
		flen := int(addons[i])
		i++
		if flen == 0 || i+flen > len(addons) {
			return false
		}
		if tag == 0x0a { // Flow name must be printable ASCII (e.g. "xtls-rprx-vision")
			for _, ch := range addons[i : i+flen] {
				if ch < 0x20 || ch > 0x7e {
					return false
				}
			}
		}
		i += flen
	}
	return i == len(addons)
}

func isStrictVLESSDomain(d string) bool {
	if len(d) < 4 || len(d) > 253 {
		return false
	}
	if d[0] == '.' || d[0] == '-' || d[len(d)-1] == '.' || d[len(d)-1] == '-' {
		return false
	}
	hasDot := false
	prevDot := false
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c == '.' {
			if prevDot {
				return false
			}
			hasDot = true
			prevDot = true
			continue
		}
		prevDot = false
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '-' && c != '_' {
			return false
		}
	}
	return hasDot
}

func looksLikeVLESSInnerPayload(tail []byte) bool {
	if len(tail) >= 3 && tail[0] == 0x16 && tail[1] == 0x03 && tail[2] <= 0x04 {
		return true // Inner TLS ClientHello
	}
	if HasHTTPPrefix(tail) {
		return true // Inner plaintext HTTP
	}
	if len(tail) >= 4 && string(tail[:4]) == "SSH-" {
		return true // Inner SSH
	}
	if len(tail) >= 16 && AnalyzeFET(tail).LooksEncrypted {
		return true // Inner encrypted payload
	}
	return false
}
