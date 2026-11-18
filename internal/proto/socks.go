package proto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// SOCKSDetectResult summarizes strict SOCKS4 / 4a / 5 detection.
type SOCKSDetectResult int

const (
	SOCKSNone SOCKSDetectResult = iota
	SOCKSNeedMore
	SOCKSMatched
	SOCKSNotSOCKS
)

// DetectSOCKS checks reassembled client (and optional server) buffers for valid SOCKS4/4a/5 handshakes.
// It uses structural validation rather than matching byte 0 alone, preventing false positives on binary streams.
func DetectSOCKS(client, server []byte) (SOCKSDetectResult, string) {
	if len(client) == 0 {
		return SOCKSNeedMore, ""
	}
	switch client[0] {
	case 0x04:
		return detectSOCKS4(client)
	case 0x05:
		return detectSOCKS5(client, server)
	default:
		return SOCKSNotSOCKS, ""
	}
}

func detectSOCKS4(c []byte) (SOCKSDetectResult, string) {
	if len(c) < 2 {
		return SOCKSNeedMore, ""
	}
	cmd := c[1]
	if cmd != 0x01 && cmd != 0x02 { // CONNECT or BIND
		return SOCKSNotSOCKS, ""
	}
	if len(c) < 9 {
		return SOCKSNeedMore, ""
	}
	port := binary.BigEndian.Uint16(c[2:4])
	if port == 0 {
		return SOCKSNotSOCKS, ""
	}
	nulIdx := bytes.IndexByte(c[8:], 0x00)
	if nulIdx < 0 {
		if len(c) > 256 {
			return SOCKSNotSOCKS, ""
		}
		return SOCKSNeedMore, ""
	}
	if nulIdx > 128 {
		return SOCKSNotSOCKS, ""
	}
	// Check userid is printable ASCII if non-empty
	for _, b := range c[8 : 8+nulIdx] {
		if b < 0x20 || b > 0x7e {
			return SOCKSNotSOCKS, ""
		}
	}
	// SOCKS4a: IP 0.0.0.x (x != 0) followed by null-terminated domain
	if c[4] == 0 && c[5] == 0 && c[6] == 0 && c[7] != 0 {
		hostStart := 8 + nulIdx + 1
		if hostStart >= len(c) {
			return SOCKSNeedMore, ""
		}
		hostNul := bytes.IndexByte(c[hostStart:], 0x00)
		if hostNul < 0 {
			if len(c) > 512 {
				return SOCKSNotSOCKS, ""
			}
			return SOCKSNeedMore, ""
		}
		host := string(c[hostStart : hostStart+hostNul])
		return SOCKSMatched, fmt.Sprintf("socks4a %s:%d", host, port)
	}
	ip := net.IPv4(c[4], c[5], c[6], c[7]).String()
	return SOCKSMatched, fmt.Sprintf("socks4 %s:%d", ip, port)
}

func detectSOCKS5(c, s []byte) (SOCKSDetectResult, string) {
	if len(c) < 2 {
		return SOCKSNeedMore, ""
	}
	nMethods := int(c[1])
	if nMethods == 0 || nMethods > 16 {
		return SOCKSNotSOCKS, ""
	}
	greetingLen := 2 + nMethods
	if len(c) < greetingLen {
		return SOCKSNeedMore, ""
	}
	hasKnownMethod := false
	for _, m := range c[2:greetingLen] {
		// Standard RFC 1928/1929 auth methods: 0x00 (no auth), 0x01 (GSSAPI), 0x02 (user/pass)
		if m == 0x00 || m == 0x01 || m == 0x02 {
			hasKnownMethod = true
		} else if m > 0x09 && m < 0x80 {
			return SOCKSNotSOCKS, ""
		}
	}
	if !hasKnownMethod {
		return SOCKSNotSOCKS, ""
	}
	// If client sent ONLY the exact SOCKS5 greeting (typical TCP first flight before server selection):
	if len(c) == greetingLen {
		// Unambiguous standard greetings like [05 01 00] or [05 02 00 02]
		if nMethods <= 4 && allStandardMethods(c[2:greetingLen]) {
			return SOCKSMatched, fmt.Sprintf("socks5 methods=%d", nMethods)
		}
		if len(s) >= 2 && s[0] == 0x05 {
			return SOCKSMatched, fmt.Sprintf("socks5 method=%d", s[1])
		}
		return SOCKSNeedMore, ""
	}
	// If server replied with SOCKS5 method selection:
	if len(s) >= 2 && s[0] == 0x05 && (s[1] == 0x00 || s[1] == 0x02 || s[1] == 0xff) {
		return SOCKSMatched, fmt.Sprintf("socks5 reply_method=%d", s[1])
	}
	// Otherwise check if client pipelined the SOCKS5 CONNECT request immediately after greeting (no-auth 0x00)
	if len(c) >= greetingLen+7 && c[greetingLen] == 0x05 && (c[greetingLen+1] >= 1 && c[greetingLen+1] <= 3) && c[greetingLen+2] == 0x00 {
		atyp := c[greetingLen+3]
		if atyp == 1 || atyp == 3 || atyp == 4 {
			return SOCKSMatched, "socks5 pipelined"
		}
	}
	return SOCKSNotSOCKS, ""
}

func allStandardMethods(methods []byte) bool {
	for _, m := range methods {
		if m != 0x00 && m != 0x01 && m != 0x02 {
			return false
		}
	}
	return true
}
