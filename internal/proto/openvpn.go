package proto

import (
	"bytes"
	"encoding/binary"
)

const (
	ovpnCtrlHardResetClientV1 = 1
	ovpnCtrlHardResetServerV1 = 2
	ovpnCtrlSoftResetV1       = 3
	ovpnCtrlV1                = 4
	ovpnAckV1                 = 5
	ovpnDataV1                = 6
	ovpnCtrlHardResetClientV2 = 7
	ovpnCtrlHardResetServerV2 = 8
	ovpnDataV2                = 9
	ovpnCtrlHardResetClientV3 = 10
	ovpnCtrlWkcV1             = 11
)

// OpenVPNTracker tracks OpenVPN UDP/TCP bidirectional handshakes with strict Session ID echo checks.
type OpenVPNTracker struct {
	state           int // 0=init, 1=saw client hard reset, 2=saw server hard reset, 3=matched, -1=not openvpn
	clientOpcode    byte
	clientSessionID [8]byte
	followUpCount   int
}

// FeedPacket checks one OpenVPN packet (UDP payload, or single TCP-framed packet without 2-byte length prefix).
// Returns (matched, done).
func (o *OpenVPNTracker) FeedPacket(rev bool, pkt []byte) (matched bool, done bool) {
	if o.state < 0 || o.state == 3 {
		return o.state == 3, true
	}
	if len(pkt) < 14 {
		o.state = -1
		return false, true
	}
	opcode := pkt[0] >> 3
	if !isValidOpenVPNOpcode(opcode) {
		o.state = -1
		return false, true
	}

	switch o.state {
	case 0:
		if rev {
			o.state = -1
			return false, true
		}
		if opcode != ovpnCtrlHardResetClientV1 && opcode != ovpnCtrlHardResetClientV2 && opcode != ovpnCtrlHardResetClientV3 {
			o.state = -1
			return false, true
		}
		o.clientOpcode = opcode
		copy(o.clientSessionID[:], pkt[1:9])
		o.state = 1
		return false, false

	case 1:
		if !rev {
			// Client retransmissions of HardResetClient are valid while waiting for server.
			if opcode == o.clientOpcode && bytes.Equal(pkt[1:9], o.clientSessionID[:]) {
				return false, false
			}
			o.state = -1
			return false, true
		}
		if opcode != ovpnCtrlHardResetServerV1 && opcode != ovpnCtrlHardResetServerV2 {
			o.state = -1
			return false, true
		}
		// Plain OpenVPN and tls-auth OpenVPN echo clientSessionID inside server HardResetServer packet.
		// Checking an 8-byte (64-bit) session ID match reduces random/DNS false positives to near zero.
		if bytes.Contains(pkt[9:], o.clientSessionID[:]) {
			o.state = 3
			return true, true
		}
		// Could be tls-crypt (V3/WKC) where remote session ID is encrypted: wait for 2 more control/ack packets.
		if o.clientOpcode == ovpnCtrlHardResetClientV3 || len(pkt) >= 28 {
			o.state = 2
			return false, false
		}
		o.state = -1
		return false, true

	case 2:
		if opcode == ovpnCtrlV1 || opcode == ovpnAckV1 || opcode == ovpnDataV1 || opcode == ovpnDataV2 || opcode == ovpnCtrlWkcV1 {
			o.followUpCount++
			if o.followUpCount >= 2 {
				o.state = 3
				return true, true
			}
			return false, false
		}
		o.state = -1
		return false, true
	}
	return false, true
}

// FeedTCP extracts length-prefixed OpenVPN TCP packets from client/server prefix buffers.
func (o *OpenVPNTracker) FeedTCP(clientBuf, serverBuf []byte) (matched bool, done bool) {
	if o.state < 0 || o.state == 3 {
		return o.state == 3, true
	}
	if len(clientBuf) < 2 {
		return false, false
	}
	cLen := int(binary.BigEndian.Uint16(clientBuf[0:2]))
	if cLen < 14 || cLen > 256 {
		o.state = -1
		return false, true
	}
	if len(clientBuf) >= 3 {
		op := clientBuf[2] >> 3
		if op != ovpnCtrlHardResetClientV1 && op != ovpnCtrlHardResetClientV2 && op != ovpnCtrlHardResetClientV3 {
			o.state = -1
			return false, true
		}
	}
	if len(clientBuf) < 2+cLen {
		return false, false
	}
	if o.state == 0 {
		m, d := o.FeedPacket(false, clientBuf[2:2+cLen])
		if d {
			return m, true
		}
	}
	if len(serverBuf) < 2 {
		return false, false
	}
	sLen := int(binary.BigEndian.Uint16(serverBuf[0:2]))
	if sLen < 14 || sLen > 4096 {
		o.state = -1
		return false, true
	}
	if len(serverBuf) < 2+sLen {
		return false, false
	}
	return o.FeedPacket(true, serverBuf[2:2+sLen])
}

func isValidOpenVPNOpcode(op byte) bool {
	switch op {
	case ovpnCtrlHardResetClientV1, ovpnCtrlHardResetServerV1, ovpnCtrlSoftResetV1,
		ovpnCtrlV1, ovpnAckV1, ovpnDataV1,
		ovpnCtrlHardResetClientV2, ovpnCtrlHardResetServerV2, ovpnDataV2,
		ovpnCtrlHardResetClientV3, ovpnCtrlWkcV1:
		return true
	default:
		return false
	}
}
