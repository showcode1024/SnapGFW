package proto

import (
	"bytes"
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"golang.org/x/crypto/hkdf"
)

const (
	quicV1 uint32 = 0x00000001
	quicV2 uint32 = 0x6b3343cf

	maxQUICCryptoSize = 64 * 1024
	maxQUICFrames     = 512
)

var (
	quicSaltV1  = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2  = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	quicSaltOld = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
)

type quicCryptoFrame struct {
	Offset int64
	Data   []byte
}

// QUICStream collects and decrypts QUIC v1/v2 Client Initial CRYPTO frames across UDP datagrams.
type QUICStream struct {
	dcid    []byte
	version uint32
	frames  []quicCryptoFrame
	size    int
}

// IsQUICInitialCandidate quickly checks if a UDP datagram looks like a QUIC v1/v2 Long Header Initial packet.
func IsQUICInitialCandidate(data []byte) bool {
	if len(data) < 20 || data[0]&0x80 == 0 {
		return false
	}
	ver := binary.BigEndian.Uint32(data[1:5])
	return ver == quicV1 || ver == quicV2
}

// Feed processes one UDP datagram (potentially containing coalesced QUIC packets) and tries
// to extract a complete ClientHello once contiguous CRYPTO bytes are ready.
func (q *QUICStream) Feed(data []byte) (info TLSClientHello, done bool, validInitial bool) {
	if err := q.feedDatagram(data); err != nil {
		return TLSClientHello{}, false, false
	}
	stream := q.assemble()
	if len(stream) < 4 {
		return TLSClientHello{}, false, true
	}
	if stream[0] != 0x01 { // ClientHello
		return TLSClientHello{}, true, true
	}
	chLen := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if chLen < 41 || chLen > maxQUICCryptoSize-4 {
		return TLSClientHello{}, true, true
	}
	if len(stream)-4 < chLen {
		return TLSClientHello{}, false, true
	}
	parsed, ok := ParseClientHelloBody(stream[4 : 4+chLen])
	if !ok {
		return TLSClientHello{}, true, true
	}
	q.frames = nil // Free fragment memory once parsed
	return parsed, true, true
}

func (q *QUICStream) feedDatagram(data []byte) error {
	found := false
	for len(data) > 0 {
		hdr, pnOff, pktLen, ok := parseQUICInitialHeader(data)
		if !ok || (hdr.version != quicV1 && hdr.version != quicV2) ||
			pktLen <= 0 || pnOff+pktLen > len(data) {
			break
		}
		pkt := data[:pnOff+pktLen]
		data = data[len(pkt):]

		wantType := byte(0)
		if hdr.version == quicV2 {
			wantType = 1
		}
		if hdr.pktType != wantType {
			continue
		}
		if q.dcid != nil && (q.version != hdr.version || !bytes.Equal(q.dcid, hdr.dcid)) {
			continue
		}

		payload, err := decryptQUICInitial(pkt, pnOff, hdr.version, hdr.dcid)
		if err != nil {
			continue
		}
		frames, err := parseQUICCryptoFrames(payload)
		if err != nil {
			continue
		}
		addSz := 0
		for _, f := range frames {
			addSz += len(f.Data)
		}
		if len(q.frames)+len(frames) > maxQUICFrames || q.size+addSz > maxQUICCryptoSize {
			return errors.New("quic crypto limit exceeded")
		}
		if q.dcid == nil {
			q.dcid = bytes.Clone(hdr.dcid)
			q.version = hdr.version
		}
		q.frames = append(q.frames, frames...)
		q.size += addSz
		found = true
	}
	if !found {
		return errors.New("no valid initial packet")
	}
	return nil
}

func (q *QUICStream) assemble() []byte {
	slices.SortStableFunc(q.frames, func(a, b quicCryptoFrame) int {
		return cmp.Compare(a.Offset, b.Offset)
	})
	var out []byte
	for _, f := range q.frames {
		n := int64(len(out))
		if f.Offset > n {
			break
		}
		if end := f.Offset + int64(len(f.Data)); end > n {
			out = append(out, f.Data[n-f.Offset:]...)
		}
	}
	return out
}

type quicInitialHeader struct {
	pktType byte
	version uint32
	dcid    []byte
}

func parseQUICInitialHeader(data []byte) (hdr quicInitialHeader, pnOff int, pktLen int, ok bool) {
	if len(data) < 7 || data[0]&0x80 == 0 {
		return hdr, 0, 0, false
	}
	hdr.pktType = (data[0] & 0x30) >> 4
	hdr.version = binary.BigEndian.Uint32(data[1:5])
	pos := 5
	dcidLen := int(data[pos])
	pos++
	if dcidLen > 20 || pos+dcidLen >= len(data) {
		return hdr, 0, 0, false
	}
	hdr.dcid = data[pos : pos+dcidLen]
	pos += dcidLen

	scidLen := int(data[pos])
	pos++
	if scidLen > 20 || pos+scidLen >= len(data) {
		return hdr, 0, 0, false
	}
	pos += scidLen

	tokenLen, n := readQUICVarint(data[pos:])
	if n <= 0 || tokenLen > uint64(len(data)-pos-n) {
		return hdr, 0, 0, false
	}
	pos += n + int(tokenLen)

	length, n := readQUICVarint(data[pos:])
	if n <= 0 || length > uint64(len(data)-pos-n) {
		return hdr, 0, 0, false
	}
	pos += n
	return hdr, pos, int(length), true
}

func decryptQUICInitial(rawPkt []byte, pnOff int, version uint32, dcid []byte) ([]byte, error) {
	if pnOff+4+16 > len(rawPkt) {
		return nil, errors.New("initial packet too short for sample")
	}
	pkt := bytes.Clone(rawPkt)

	var salt []byte
	keyLbl, ivLbl, hpLbl := "quic key", "quic iv", "quic hp"
	switch version {
	case quicV1:
		salt = quicSaltV1
	case quicV2:
		salt = quicSaltV2
		keyLbl, ivLbl, hpLbl = "quicv2 key", "quicv2 iv", "quicv2 hp"
	default:
		salt = quicSaltOld
	}

	initialSecret := hkdf.Extract(sha256.New, dcid, salt)
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", 32)
	if err != nil {
		return nil, err
	}
	key, err := hkdfExpandLabel(clientSecret, keyLbl, 16)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabel(clientSecret, ivLbl, 12)
	if err != nil {
		return nil, err
	}
	hpKey, err := hkdfExpandLabel(clientSecret, hpLbl, 16)
	if err != nil {
		return nil, err
	}

	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])

	pkt[0] ^= mask[0] & 0x0f
	pnLen := int(pkt[0]&0x03) + 1
	if pnOff+pnLen >= len(pkt) {
		return nil, errors.New("invalid packet number length")
	}

	var pn uint64
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
		pn = (pn << 8) | uint64(pkt[pnOff+i])
	}

	var nonce [12]byte
	copy(nonce[:], iv)
	var pnBuf [8]byte
	binary.BigEndian.PutUint64(pnBuf[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnBuf[i]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ad := pkt[:pnOff+pnLen]
	ciphertext := pkt[pnOff+pnLen:]
	return aead.Open(nil, nonce[:], ciphertext, ad)
}

func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1)
	binary.BigEndian.PutUint16(info[0:2], uint16(length))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = 0

	r := hkdf.Expand(sha256.New, secret, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseQUICCryptoFrames(payload []byte) ([]quicCryptoFrame, error) {
	var frames []quicCryptoFrame
	pos := 0
	for pos < len(payload) {
		ft, n := readQUICVarint(payload[pos:])
		if n <= 0 {
			return nil, errors.New("invalid frame type")
		}
		pos += n
		if ft == 0x00 || ft == 0x01 { // PADDING or PING
			continue
		}
		if ft == 0x02 || ft == 0x03 { // ACK or ACK_ECN (allowed in Initial retransmissions per RFC 9000)
			nextPos, ok := skipQUICAckFrame(payload, pos, ft == 0x03)
			if !ok {
				return nil, errors.New("invalid ack frame in initial")
			}
			pos = nextPos
			continue
		}
		if ft != 0x06 { // CRYPTO
			return nil, errors.New("unexpected frame in initial")
		}
		offset, n := readQUICVarint(payload[pos:])
		if n <= 0 {
			return nil, errors.New("invalid crypto offset")
		}
		pos += n
		dataLen, n := readQUICVarint(payload[pos:])
		if n <= 0 || dataLen > uint64(len(payload)-pos-n) {
			return nil, errors.New("invalid crypto length")
		}
		pos += n
		frames = append(frames, quicCryptoFrame{
			Offset: int64(offset),
			Data:   bytes.Clone(payload[pos : pos+int(dataLen)]),
		})
		pos += int(dataLen)
	}
	return frames, nil
}

func readQUICVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0
	}
	val := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length
}

func skipQUICAckFrame(payload []byte, pos int, hasECN bool) (int, bool) {
	// Largest Acknowledged, ACK Delay, ACK Range Count, First ACK Range
	var rangeCount uint64
	for i := 0; i < 4; i++ {
		v, n := readQUICVarint(payload[pos:])
		if n <= 0 {
			return 0, false
		}
		if i == 2 {
			rangeCount = v
		}
		pos += n
	}
	if rangeCount > 64 {
		return 0, false
	}
	for i := uint64(0); i < rangeCount; i++ {
		for j := 0; j < 2; j++ { // Gap + ACK Range Length
			_, n := readQUICVarint(payload[pos:])
			if n <= 0 {
				return 0, false
			}
			pos += n
		}
	}
	if hasECN {
		for i := 0; i < 3; i++ { // ECT0, ECT1, ECN-CE counts
			_, n := readQUICVarint(payload[pos:])
			if n <= 0 {
				return 0, false
			}
			pos += n
		}
	}
	return pos, true
}
