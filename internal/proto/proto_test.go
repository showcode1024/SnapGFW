package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/crypto/hkdf"

	"snapgfw/internal/model"
)

func buildClientHelloMsg(sni string, ech bool) []byte {
	var exts []byte
	if sni != "" {
		var sniExt []byte
		sniBytes := []byte(sni)
		listLen := 1 + 2 + len(sniBytes)
		sniExt = binary.BigEndian.AppendUint16(sniExt, 0x0000) // server_name
		sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(2+listLen))
		sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(listLen))
		sniExt = append(sniExt, 0x00)
		sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniBytes)))
		sniExt = append(sniExt, sniBytes...)
		exts = append(exts, sniExt...)
	}
	if ech {
		exts = binary.BigEndian.AppendUint16(exts, 0xfe0d)
		exts = binary.BigEndian.AppendUint16(exts, 4)
		exts = append(exts, 1, 2, 3, 4)
	}

	var body []byte
	body = append(body, 0x03, 0x03)              // legacy TLS 1.2
	body = append(body, make([]byte, 32)...)     // random
	body = append(body, 0x00)                    // session_id len
	body = binary.BigEndian.AppendUint16(body, 2) // cipher suites len
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 0x01, 0x00) // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	var hs []byte
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)
	return hs
}

func wrapTLSRecord(hsChunk []byte) []byte {
	var rec []byte
	rec = append(rec, 0x16, 0x03, 0x01)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hsChunk)))
	rec = append(rec, hsChunk...)
	return rec
}

func buildQUICInitialPacket(t *testing.T, version uint32, dcid []byte, clientHelloHS []byte) []byte {
	t.Helper()
	// CRYPTO frame at offset 0
	var payload []byte
	payload = append(payload, 0x06) // CRYPTO frame type
	payload = append(payload, 0x00) // offset = 0 (1-byte varint)
	// length 2-byte varint (prefix 01)
	payload = append(payload, 0x40|byte(len(clientHelloHS)>>8), byte(len(clientHelloHS)))
	payload = append(payload, clientHelloHS...)
	for len(payload) < 40 {
		payload = append(payload, 0x00) // PADDING
	}

	var salt []byte
	keyLbl, ivLbl, hpLbl := "quic key", "quic iv", "quic hp"
	if version == quicV2 {
		salt = quicSaltV2
		keyLbl, ivLbl, hpLbl = "quicv2 key", "quicv2 iv", "quicv2 hp"
	} else {
		salt = quicSaltV1
	}

	initSec := hkdf.Extract(sha256.New, dcid, salt)
	cSec, err := hkdfExpandLabel(initSec, "client in", 32)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hkdfExpandLabel(cSec, keyLbl, 16)
	iv, _ := hkdfExpandLabel(cSec, ivLbl, 12)
	hpKey, _ := hkdfExpandLabel(cSec, hpLbl, 16)

	firstByte := byte(0xc1) // Long header + fixed bit + type 0 (v1) + 2-byte PN
	if version == quicV2 {
		firstByte = byte(0xd1) // type 1 (v2) + 2-byte PN
	}
	pnOffset := 5 + 1 + len(dcid) + 1 + 1 // flags + ver + dcidLen + dcid + scidLen(0) + tokenLen(0)
	// Build header up to length varint (2 bytes) + 2-byte PN
	pnLen := 2
	ctLen := len(payload) + 16 // GCM tag
	totalLen := pnLen + ctLen

	var hdr []byte
	hdr = append(hdr, firstByte)
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // scid len = 0
	hdr = append(hdr, 0x00) // token len = 0
	hdr = append(hdr, 0x40|byte(totalLen>>8), byte(totalLen))
	pnOffset = len(hdr)
	hdr = append(hdr, 0x00, 0x01) // PN = 1

	var nonce [12]byte
	copy(nonce[:], iv)
	nonce[11] ^= 0x01

	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	ct := gcm.Seal(nil, nonce[:], payload, hdr)

	pkt := append(hdr, ct...)
	hpBlk, _ := aes.NewCipher(hpKey)
	var mask [16]byte
	hpBlk.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	pkt[pnOffset+1] ^= mask[2]
	return pkt
}

func testPolicy() *CompiledPolicy {
	p := model.BuildPreset("anti_blacklist")
	return CompilePolicy(p, "")
}

func testMeta(l4 string, dir model.Direction, dstPort uint16) FlowMeta {
	return FlowMeta{
		L4Proto:   l4,
		Direction: dir,
		TenantIP:  net.ParseIP("10.91.0.2"),
		PeerIP:    net.ParseIP("8.8.8.8"),
		SrcPort:   45678,
		DstPort:   dstPort,
	}
}

func TestTLSMultiRecordAndSNI(t *testing.T) {
	cp := testPolicy()
	hs := buildClientHelloMsg("www.bilibili.com", false)
	// Split ClientHello across 2 TLS records to verify multi-record reassembly!
	rec1 := wrapTLSRecord(hs[:30])
	rec2 := wrapTLSRecord(hs[30:])

	sess := NewTCPSession(testMeta("tcp", DirInbound, 443), cp, 16384)
	res1 := sess.Feed(false, rec1)
	if res1.Decision != DecisionContinue {
		t.Fatalf("expected continue after fragment 1, got %v", res1.Decision)
	}
	res2 := sess.Feed(false, rec2)
	if res2.Decision != DecisionBlock || len(res2.Events) != 1 || res2.Events[0].Protocol != model.ProtoTLSSNI {
		t.Fatalf("expected block on domestic SNI across split TLS records, got %+v", res2)
	}

	// Overseas SNI should be allowed (note trojan is ActionLog in anti_blacklist)
	overseas := wrapTLSRecord(buildClientHelloMsg("www.cloudflare.com", false))
	sess2 := NewTCPSession(testMeta("tcp", DirInbound, 443), cp, 16384)
	res3 := sess2.Feed(false, overseas)
	if res3.Decision == DecisionBlock {
		t.Fatalf("overseas SNI must not be blocked: %+v", res3)
	}

	// Outbound domestic SNI must NOT be blocked in anti_blacklist
	sessOut := NewTCPSession(testMeta("tcp", DirOutbound, 443), cp, 16384)
	resOut := sessOut.Feed(false, append(rec1, rec2...))
	if resOut.Decision != DecisionAllow {
		t.Fatalf("outbound domestic SNI should be allowed, got %+v", resOut)
	}
}

func TestQUICInitialDecryptionAndSNI(t *testing.T) {
	cp := testPolicy()
	hs := buildClientHelloMsg("v.qq.com", false)
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	for _, ver := range []uint32{quicV1, quicV2} {
		pkt := buildQUICInitialPacket(t, ver, dcid, hs)
		sess := NewUDPSession(testMeta("udp", DirInbound, 443), cp, 6)
		res := sess.Feed(false, pkt)
		if res.Decision != DecisionBlock || len(res.Events) != 1 || res.Events[0].Protocol != model.ProtoQUICSNI {
			t.Fatalf("QUIC v=%#x expected block on v.qq.com, got %+v", ver, res)
		}
	}

	// Overseas QUIC SNI allowed
	pktOK := buildQUICInitialPacket(t, quicV1, dcid, buildClientHelloMsg("example.org", false))
	sessOK := NewUDPSession(testMeta("udp", DirInbound, 443), cp, 6)
	resOK := sessOK.Feed(false, pktOK)
	if resOK.Decision != DecisionAllow {
		t.Fatalf("expected allow for overseas QUIC SNI, got %+v", resOK)
	}
}

func TestShadowsocks2022TCPAndFakePrefixBypass(t *testing.T) {
	cp := testPolicy()
	rnd := make([]byte, 128)
	_, _ = rand.Read(rnd)

	// Pure SS-2022 TCP random ciphertext
	sess := NewTCPSession(testMeta("tcp", DirInbound, 8388), cp, 16384)
	res := sess.Feed(false, rnd)
	if res.Decision != DecisionBlock || len(res.Events) == 0 || res.Events[0].Protocol != model.ProtoFETTCP {
		t.Fatalf("expected SS-2022 TCP to be blocked by fet_tcp, got %+v", res)
	}

	// Fake "GET " prefix trying to dodge FET ex5 exemption!
	fakeGet := append([]byte("GET "), rnd...)
	sessFake := NewTCPSession(testMeta("tcp", DirInbound, 8388), cp, 16384)
	resFake := sessFake.Feed(false, fakeGet)
	if resFake.Decision != DecisionBlock {
		t.Fatalf("expected fake GET prefix + random bytes to be blocked, got %+v", resFake)
	}

	// Fake TLS header prefix trying to dodge FET!
	fakeTLS := append([]byte{0x16, 0x03, 0x01, 0x00, 0x30}, rnd[:48]...)
	sessFakeTLS := NewTCPSession(testMeta("tcp", DirInbound, 443), cp, 16384)
	resFakeTLS := sessFakeTLS.Feed(false, fakeTLS)
	if resFakeTLS.Decision != DecisionBlock {
		t.Fatalf("expected fake TLS prefix to be blocked, got %+v", resFakeTLS)
	}
}

func TestTwoStageWebSocketPlaintextVsEncrypted(t *testing.T) {
	cp := testPolicy()
	wsReq := "GET /chat HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

	buildMaskedFrame := func(payload []byte) []byte {
		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		var frame []byte
		frame = append(frame, 0x82) // FIN + binary/text
		if len(payload) < 126 {
			frame = append(frame, 0x80|byte(len(payload)))
		} else {
			frame = append(frame, 0x80|126)
			frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
		}
		frame = append(frame, mask[:]...)
		for i, b := range payload {
			frame = append(frame, b^mask[i&3])
		}
		return frame
	}

	// 1. Legitimate JSON WebSocket (client masked on wire, but readable ASCII after unmasking!)
	sessLegit := NewTCPSession(testMeta("tcp", DirInbound, 80), cp, 16384)
	if r := sessLegit.Feed(false, []byte(wsReq)); r.Decision != DecisionContinue {
		t.Fatalf("expected two-stage WS handshake to continue, got %v", r.Decision)
	}
	jsonPayload := []byte(`{"type":"heartbeat","user":"alice","msg":"hello world"}`)
	if r := sessLegit.Feed(false, buildMaskedFrame(jsonPayload)); r.Decision != DecisionAllow {
		t.Fatalf("legitimate plaintext JSON WS must be allowed after unmasking, got %+v", r)
	}

	// 2. VMess-WS (high-entropy ciphertext even after unmasking!)
	sessProxy := NewTCPSession(testMeta("tcp", DirInbound, 80), cp, 16384)
	_ = sessProxy.Feed(false, []byte(wsReq))
	encPayload := make([]byte, 64)
	_, _ = rand.Read(encPayload)
	if r := sessProxy.Feed(false, buildMaskedFrame(encPayload)); r.Decision != DecisionBlock {
		t.Fatalf("encrypted VMess-WS payload must be blocked, got %+v", r)
	}
}

func TestOpenVPNStrictVsDNSSafety(t *testing.T) {
	cp := testPolicy()

	// 1. Standard DNS query whose Transaction ID starts with OpenVPN opcode 0x38!
	dnsPkt := []byte{
		0x38, 0x11, // Transaction ID starting with 0x38 (looks like HardResetClientV2 opcode 7!)
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01, // A IN
	}
	sessDNS := NewUDPSession(testMeta("udp", DirInbound, 53), cp, 6)
	resDNS := sessDNS.Feed(false, dnsPkt)
	if resDNS.Decision != DecisionAllow {
		t.Fatalf("DNS packet starting with 0x38 must NEVER be blocked by OpenVPN rule! got %+v", resDNS)
	}

	// 2. Real OpenVPN UDP handshake with 8-byte session ID echo
	cliSessID := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
	cliPkt := append([]byte{0x38}, cliSessID...)
	cliPkt = append(cliPkt, make([]byte, 12)...)

	srvPkt := append([]byte{0x40}, []byte{1, 2, 3, 4, 5, 6, 7, 8}...)
	srvPkt = append(srvPkt, 0x01, 0x00, 0x00, 0x00, 0x00) // ack len + packet_id
	srvPkt = append(srvPkt, cliSessID...)                   // echoed remote session ID!

	sessOvpn := NewUDPSession(testMeta("udp", DirInbound, 1194), cp, 6)
	if r := sessOvpn.Feed(false, cliPkt); r.Decision != DecisionContinue {
		t.Fatalf("expected continue after client HardReset, got %+v", r)
	}
	if r := sessOvpn.Feed(true, srvPkt); r.Decision != DecisionBlock || r.Events[0].Protocol != model.ProtoOpenVPN {
		t.Fatalf("expected OpenVPN block after session ID echo, got %+v", r)
	}
}

func TestSOCKSAndHTTPConnectAndWireGuard(t *testing.T) {
	cp := testPolicy()

	// SOCKS5
	s5 := NewTCPSession(testMeta("tcp", DirInbound, 1080), cp, 16384)
	if r := s5.Feed(false, []byte{0x05, 0x01, 0x00}); r.Decision != DecisionBlock || r.Events[0].Protocol != model.ProtoSOCKS {
		t.Fatalf("expected SOCKS5 block, got %+v", r)
	}

	// HTTP CONNECT
	hc := NewTCPSession(testMeta("tcp", DirInbound, 8080), cp, 16384)
	if r := hc.Feed(false, []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); r.Decision != DecisionBlock || r.Events[0].Protocol != model.ProtoHTTPProxy {
		t.Fatalf("expected HTTP CONNECT block, got %+v", r)
	}

	// WireGuard (ActionLog in anti_blacklist, ActionBlock in strict_block)
	wgInit := make([]byte, 148)
	wgInit[0] = 0x01
	sessWG := NewUDPSession(testMeta("udp", DirInbound, 51820), cp, 6)
	rWG := sessWG.Feed(false, wgInit)
	if len(rWG.Events) != 1 || rWG.Events[0].Protocol != model.ProtoWireGuard || rWG.Decision != DecisionAllow {
		t.Fatalf("expected WireGuard log event in anti_blacklist, got %+v", rWG)
	}
}
