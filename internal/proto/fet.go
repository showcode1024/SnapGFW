package proto

import (
	"encoding/binary"
	"math/bits"
)

// FETResult holds metrics from USENIX Security '23 Fully Encrypted Traffic analysis.
type FETResult struct {
	AvgPopCount         float32
	FirstSixPrintable   bool
	PrintablePercentage float32
	ContiguousPrintable int
	LooksEncrypted      bool
}

// AnalyzeFET evaluates payload entropy and printable ASCII characteristics.
// Unlike OpenGFW's Ex5 check, this does NOT blindly exempt 3-byte "GET"/"TLS" prefixes;
// real HTTP/TLS parsers must validate structure first so fake prefixes cannot bypass detection.
func AnalyzeFET(data []byte) FETResult {
	if len(data) == 0 {
		return FETResult{}
	}
	ex1 := avgPopCount(data)
	ex2 := firstSixPrintable(data)
	ex3 := printablePct(data)
	ex4 := contiguousPrintable(data)
	exempt := (ex1 <= 3.4 || ex1 >= 4.6) || ex2 || ex3 > 0.5 || ex4 > 20
	return FETResult{
		AvgPopCount:         ex1,
		FirstSixPrintable:   ex2,
		PrintablePercentage: ex3,
		ContiguousPrintable: ex4,
		LooksEncrypted:      !exempt,
	}
}

func avgPopCount(b []byte) float32 {
	total := 0
	for _, x := range b {
		total += bits.OnesCount8(x)
	}
	return float32(total) / float32(len(b))
}

func firstSixPrintable(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if !isPrintableASCII(b[i]) {
			return false
		}
	}
	return true
}

func printablePct(b []byte) float32 {
	count := 0
	for _, x := range b {
		if isPrintableASCII(x) {
			count++
		}
	}
	return float32(count) / float32(len(b))
}

func contiguousPrintable(b []byte) int {
	maxRun, cur := 0, 0
	for _, x := range b {
		if isPrintableASCII(x) {
			cur++
			if cur > maxRun {
				maxRun = cur
			}
		} else {
			cur = 0
		}
	}
	return maxRun
}

func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

// IsLikelySTUN checks RFC 5389/8489 STUN header + magic cookie 0x2112A442.
func IsLikelySTUN(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	if data[0]&0xC0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(data[4:8]) != 0x2112A442 {
		return false
	}
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	return len(data) == 20+msgLen
}

// IsLikelyDTLS checks DTLS 1.0 / 1.2 / 1.3 record header.
func IsLikelyDTLS(data []byte) bool {
	if len(data) < 13 {
		return false
	}
	ct := data[0]
	if ct < 20 || ct > 23 {
		return false
	}
	return data[1] == 0xfe && (data[2] == 0xff || data[2] == 0xfd || data[2] == 0xfc)
}

// IsLikelyNTP checks standard 48-byte NTP v3/v4 packet on port 123.
func IsLikelyNTP(data []byte, srcPort, dstPort uint16) bool {
	if (srcPort != 123 && dstPort != 123) || len(data) < 48 {
		return false
	}
	vn := (data[0] >> 3) & 0x07
	mode := data[0] & 0x07
	return vn >= 1 && vn <= 4 && mode >= 1 && mode <= 7
}
