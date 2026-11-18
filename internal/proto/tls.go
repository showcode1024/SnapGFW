package proto

import (
	"encoding/binary"
	"strings"
)

// TLSParseStatus indicates ClientHello parsing progress.
type TLSParseStatus int

const (
	TLSNeedMore TLSParseStatus = iota
	TLSNotTLS                  // Not a TLS handshake record
	TLSMalformed               // Looked like TLS record header but invalid ClientHello (possible fake TLS obfs)
	TLSValid
)

// TLSClientHello holds extracted ClientHello metadata.
type TLSClientHello struct {
	SNI        string
	ALPN       []string
	HasECH     bool
	HasESNI    bool
	RecordCount int
}

// ParseTLSClientHello parses a TLS ClientHello across ONE OR MORE TLS handshake records.
// Reassembling fragmented TLS records prevents record-splitting evasion that breaks single-record parsers.
func ParseTLSClientHello(b []byte) (TLSClientHello, TLSParseStatus) {
	if len(b) == 0 {
		return TLSClientHello{}, TLSNeedMore
	}
	// Record ContentType: 0x16 (Handshake). Note: fake TLS obfs sometimes starts with 0x17 0x03 ...
	if b[0] == 0x17 {
		if len(b) >= 3 && b[1] == 0x03 && b[2] <= 0x09 {
			return TLSClientHello{}, TLSMalformed
		}
		return TLSClientHello{}, TLSNotTLS
	}
	if b[0] != 0x16 {
		return TLSClientHello{}, TLSNotTLS
	}
	if len(b) < 3 {
		return TLSClientHello{}, TLSNeedMore
	}
	if b[1] != 0x03 || b[2] > 0x09 {
		return TLSClientHello{}, TLSNotTLS
	}
	if len(b) < 5 {
		return TLSClientHello{}, TLSNeedMore
	}

	// Collect handshake bytes across consecutive TLS 0x16 records.
	var hs []byte
	pos := 0
	records := 0
	var needLen int
	for pos < len(b) {
		if pos+5 > len(b) {
			return TLSClientHello{}, TLSNeedMore
		}
		if b[pos] != 0x16 || b[pos+1] != 0x03 || b[pos+2] > 0x09 {
			if records == 0 {
				return TLSClientHello{}, TLSMalformed
			}
			break
		}
		recLen := int(binary.BigEndian.Uint16(b[pos+3 : pos+5]))
		if recLen == 0 || recLen > 16384 {
			return TLSClientHello{}, TLSMalformed
		}
		if pos+5+recLen > len(b) {
			return TLSClientHello{}, TLSNeedMore
		}
		hs = append(hs, b[pos+5:pos+5+recLen]...)
		pos += 5 + recLen
		records++

		if len(hs) >= 4 {
			if hs[0] != 0x01 { // HandshakeType ClientHello
				return TLSClientHello{}, TLSMalformed
			}
			needLen = int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if needLen < 41 || needLen > 32768 {
				return TLSClientHello{}, TLSMalformed
			}
			if len(hs) >= 4+needLen {
				break
			}
		}
		if records > 16 {
			return TLSClientHello{}, TLSMalformed
		}
	}

	if len(hs) < 4 || len(hs) < 4+needLen {
		return TLSClientHello{}, TLSNeedMore
	}

	info, ok := ParseClientHelloBody(hs[4 : 4+needLen])
	if !ok {
		return TLSClientHello{}, TLSMalformed
	}
	info.RecordCount = records
	return info, TLSValid
}

// ParseClientHelloBody decodes the raw TLS ClientHello body (without 4-byte handshake header).
// Shared by both TLS and QUIC analyzers.
func ParseClientHelloBody(body []byte) (TLSClientHello, bool) {
	var out TLSClientHello
	// 2 bytes version + 32 bytes random + 1 byte session_id_len = 35
	if len(body) < 35 {
		return out, false
	}
	off := 34
	sidLen := int(body[off])
	off++
	if off+sidLen+2 > len(body) {
		return out, false
	}
	off += sidLen

	cipherLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if cipherLen%2 != 0 || off+cipherLen+1 > len(body) {
		return out, false
	}
	off += cipherLen

	compLen := int(body[off])
	off++
	if off+compLen > len(body) {
		return out, false
	}
	off += compLen

	if off == len(body) {
		return out, true // No extensions
	}
	if off+2 > len(body) {
		return out, false
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extTotalLen > len(body) {
		return out, false
	}
	extEnd := off + extTotalLen
	for off < extEnd {
		if off+4 > extEnd {
			return out, false
		}
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			return out, false
		}
		extData := body[off : off+extLen]
		off += extLen

		switch extType {
		case 0x0000: // server_name
			if len(extData) < 5 {
				return out, false
			}
			// list len (2) + name_type (1) + name_len (2)
			if extData[2] != 0x00 {
				return out, false
			}
			sniLen := int(binary.BigEndian.Uint16(extData[3:5]))
			if 5+sniLen > len(extData) {
				return out, false
			}
			out.SNI = strings.ToLower(string(extData[5 : 5+sniLen]))
		case 0x0010: // ALPN
			if len(extData) < 2 {
				return out, false
			}
			p := 2
			for p < len(extData) {
				l := int(extData[p])
				p++
				if p+l > len(extData) {
					return out, false
				}
				out.ALPN = append(out.ALPN, string(extData[p:p+l]))
				p += l
			}
		case 0xffce: // ESNI
			out.HasESNI = true
		case 0xfe0d: // ECH
			out.HasECH = true
		}
	}
	return out, true
}
