package proto

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// HTTPParseStatus describes the state of HTTP/1.x request parsing.
type HTTPParseStatus int

const (
	HTTPNeedMore HTTPParseStatus = iota
	HTTPInvalid                  // Starts like HTTP method or failed validation (possible fake HTTP obfs)
	HTTPValid
)

// HTTPInfo holds parsed HTTP/1.x request metadata.
type HTTPInfo struct {
	Method          string
	Target          string
	Version         string
	Host            string
	Upgrade         string
	IsProxy         bool // CONNECT or absolute http:// URI
	IsWebSocket     bool
	HeaderEndOffset int // Offset in client stream right after \r\n\r\n
}

var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("HEAD "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("CONNECT "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("TRACE "),
}

// HasHTTPPrefix returns true if b starts with a partial or full HTTP/1.x method prefix.
func HasHTTPPrefix(b []byte) bool {
	for _, m := range httpMethods {
		if len(b) < len(m) {
			if bytes.HasPrefix(m, b) {
				return true
			}
		} else if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

// ParseHTTPRequest parses an HTTP/1.x request line and headers from client bytes.
func ParseHTTPRequest(b []byte) (HTTPInfo, HTTPParseStatus) {
	if len(b) == 0 {
		return HTTPInfo{}, HTTPNeedMore
	}
	// If less than longest method prefix, check if it could still become one.
	if len(b) < 8 {
		if HasHTTPPrefix(b) {
			// Check if we already see invalid line breaks or binary before space
			return HTTPInfo{}, HTTPNeedMore
		}
		return HTTPInfo{}, HTTPInvalid
	}
	if !HasHTTPPrefix(b) {
		return HTTPInfo{}, HTTPInvalid
	}

	hdrEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		if len(b) > 8192 || hasInvalidHTTPHeaderBytes(b) {
			return HTTPInfo{}, HTTPInvalid
		}
		return HTTPInfo{}, HTTPNeedMore
	}
	if hasInvalidHTTPHeaderBytes(b[:hdrEnd]) {
		return HTTPInfo{}, HTTPInvalid
	}

	headerBlock := b[:hdrEnd]
	lines := bytes.Split(headerBlock, []byte("\r\n"))
	if len(lines) == 0 {
		return HTTPInfo{}, HTTPInvalid
	}
	reqFields := strings.Fields(string(lines[0]))
	if len(reqFields) != 3 || !strings.HasPrefix(reqFields[2], "HTTP/") {
		return HTTPInfo{}, HTTPInvalid
	}

	info := HTTPInfo{
		Method:          strings.ToUpper(reqFields[0]),
		Target:          reqFields[1],
		Version:         reqFields[2],
		HeaderEndOffset: hdrEnd + 4,
	}

	for _, line := range lines[1:] {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return HTTPInfo{}, HTTPInvalid
		}
		key := strings.ToLower(string(bytes.TrimSpace(k)))
		val := strings.TrimSpace(string(v))
		switch key {
		case "host":
			// Strip optional :port for domain matching
			host, _, hasColon := strings.Cut(val, ":")
			if hasColon && !strings.HasPrefix(val, "[") {
				info.Host = strings.ToLower(host)
			} else {
				info.Host = strings.ToLower(val)
			}
		case "upgrade":
			info.Upgrade = strings.ToLower(val)
		}
	}

	if info.Method == "CONNECT" || strings.HasPrefix(strings.ToLower(info.Target), "http://") || strings.HasPrefix(strings.ToLower(info.Target), "https://") {
		info.IsProxy = true
	}
	if info.Upgrade == "websocket" {
		info.IsWebSocket = true
	}
	return info, HTTPValid
}

func hasInvalidHTTPHeaderBytes(b []byte) bool {
	firstLine := true
	for _, ch := range b {
		if ch == '\n' {
			firstLine = false
			continue
		}
		if ch == '\r' || ch == '\t' {
			continue
		}
		if ch < 0x20 || ch == 0x7f {
			return true
		}
		// Request line (METHOD SP target SP HTTP/1.x) must be strict ASCII;
		// random binary prefixes (like "GET " + ciphertext) fail immediately.
		if firstLine && ch >= 0x80 {
			return true
		}
	}
	return false
}

// ExtractWSClientPayload parses client->server RFC 6455 WebSocket frames starting at payloadOffset,
// unmasking each frame's payload using its 4-byte masking key so plaintext JSON/text WS stays readable
// while encrypted VMess-WS remains high-entropy random bytes.
func ExtractWSClientPayload(buf []byte, minBytes int) (unmasked []byte, needMore bool, invalid bool) {
	pos := 0
	for pos < len(buf) && len(unmasked) < minBytes {
		if pos+2 > len(buf) {
			return unmasked, true, false
		}
		b0 := buf[pos]
		b1 := buf[pos+1]
		opcode := b0 & 0x0f
		masked := (b1 & 0x80) != 0
		if !masked {
			// RFC 6455 requires client->server frames to be masked; unmasked binary after upgrade is suspicious/non-WS.
			return nil, false, true
		}
		if opcode >= 3 && opcode <= 7 {
			return nil, false, true
		}
		plen := uint64(b1 & 0x7f)
		hdrLen := 2
		if plen == 126 {
			if pos+4 > len(buf) {
				return unmasked, true, false
			}
			plen = uint64(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
			hdrLen = 4
		} else if plen == 127 {
			if pos+10 > len(buf) {
				return unmasked, true, false
			}
			plen = binary.BigEndian.Uint64(buf[pos+2 : pos+10])
			hdrLen = 10
		}
		if pos+hdrLen+4 > len(buf) {
			return unmasked, true, false
		}
		maskKey := buf[pos+hdrLen : pos+hdrLen+4]
		dataStart := pos + hdrLen + 4
		avail := len(buf) - dataStart
		take := avail
		if uint64(take) > plen {
			take = int(plen)
		}
		if take > 0 && (opcode == 1 || opcode == 2 || opcode == 0) {
			for i := 0; i < take && len(unmasked) < minBytes; i++ {
				unmasked = append(unmasked, buf[dataStart+i]^maskKey[i&3])
			}
		}
		if uint64(avail) < plen {
			// Incomplete frame, but we may already have collected enough bytes.
			if len(unmasked) >= minBytes {
				return unmasked, false, false
			}
			return unmasked, true, false
		}
		pos = dataStart + int(plen)
	}
	if len(unmasked) >= minBytes {
		return unmasked, false, false
	}
	return unmasked, true, false
}
