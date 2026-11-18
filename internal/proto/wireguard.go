package proto

import "encoding/binary"

// WireGuardTracker detects WireGuard UDP handshakes and transport data streams.
type WireGuardTracker struct {
	sawInitiation bool
	senderIdx     uint32
	dataCount     int
	invalidCount  int
}

// Feed checks one UDP packet for WireGuard framing.
// Matches unambiguously on 148B Handshake Initiation (or matched 92B Response) or 3 consecutive valid Data packets.
func (w *WireGuardTracker) Feed(rev bool, data []byte) (matched bool, done bool) {
	if len(data) < 4 || data[1] != 0 || data[2] != 0 || data[3] != 0 {
		w.invalidCount++
		return false, w.invalidCount >= 3
	}
	switch data[0] {
	case 1: // Handshake Initiation (always 148 bytes)
		if len(data) == 148 {
			w.sawInitiation = true
			w.senderIdx = binary.LittleEndian.Uint32(data[4:8])
			return true, true
		}
	case 2: // Handshake Response (always 92 bytes)
		if len(data) == 92 {
			recvIdx := binary.LittleEndian.Uint32(data[8:12])
			if !w.sawInitiation || (rev && recvIdx == w.senderIdx) {
				return true, true
			}
		}
	case 3: // Cookie Reply (always 64 bytes)
		if len(data) == 64 && w.sawInitiation {
			return true, true
		}
	case 4: // Transport Data (>= 32 bytes, padded to multiple of 16)
		if len(data) >= 32 && len(data)%16 == 0 {
			w.dataCount++
			if w.dataCount >= 3 {
				return true, true
			}
			return false, false
		}
	}
	w.invalidCount++
	return false, w.invalidCount >= 3
}
