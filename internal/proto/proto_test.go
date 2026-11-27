package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

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
	p := model.BuildPreset("anti_abuse")
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

	// Overseas QUIC SNI: blocked by udp_proxy in default anti_abuse (blocks Hy2/TUIC),
	// and allowed when udp_proxy is turned off (verifying quic_sni itself does not block overseas SNI).
	pktOK := buildQUICInitialPacket(t, quicV1, dcid, buildClientHelloMsg("example.org", false))
	sessBlocked := NewUDPSession(testMeta("udp", DirInbound, 443), cp, 6)
	resBlocked := sessBlocked.Feed(false, pktOK)
	if resBlocked.Decision != DecisionBlock || len(resBlocked.Events) != 1 || resBlocked.Events[0].Protocol != model.ProtoUDPProxy {
		t.Fatalf("expected anti_abuse udp_proxy to block inbound Hy2/TUIC QUIC, got %+v", resBlocked)
	}

	polNoUDPProxy := model.BuildPreset("anti_abuse")
	for i := range polNoUDPProxy.Protocols {
		if polNoUDPProxy.Protocols[i].ID == model.ProtoUDPProxy {
			polNoUDPProxy.Protocols[i].Enabled = false
		}
	}
	cpNoUDPProxy := CompilePolicy(polNoUDPProxy, "")
	sessOK := NewUDPSession(testMeta("udp", DirInbound, 443), cpNoUDPProxy, 6)
	resOK := sessOK.Feed(false, pktOK)
	if resOK.Decision != DecisionAllow {
		t.Fatalf("expected allow for overseas QUIC SNI when udp_proxy disabled, got %+v", resOK)
	}
}

func TestShadowsocks2022TCPAndFakePrefixBypass(t *testing.T) {
	cp := testPolicy()
	rnd := makeDeterministicCipher(128, 1)

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
	encPayload := makeDeterministicCipher(64, 2)
	if r := sessProxy.Feed(false, buildMaskedFrame(encPayload)); r.Decision != DecisionBlock {
		t.Fatalf("encrypted VMess-WS payload must be blocked, got %+v", r)
	}
}

func makeDeterministicCipher(n int, seed byte) []byte {
	out := make([]byte, n)
	var state byte = seed ^ 0x9b
	for i := range out {
		state = byte((int(state)*73 + 179) & 0xff)
		out[i] = state
	}
	return out
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

	// WireGuard (ActionLog in anti_abuse)
	wgInit := make([]byte, 148)
	wgInit[0] = 0x01
	sessWG := NewUDPSession(testMeta("udp", DirInbound, 51820), cp, 6)
	rWG := sessWG.Feed(false, wgInit)
	if len(rWG.Events) != 1 || rWG.Events[0].Protocol != model.ProtoWireGuard || rWG.Decision != DecisionAllow {
		t.Fatalf("expected WireGuard log event in anti_abuse, got %+v", rWG)
	}
}

func TestStratumAndMiningPoolDetection(t *testing.T) {
	cp := testPolicy()

	// Outbound Stratum JSON-RPC mining.subscribe
	s1 := NewTCPSession(testMeta("tcp", DirOutbound, 3333), cp, 16384)
	r1 := s1.Feed(false, []byte("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"cgminer/4.10\"]}\n"))
	if r1.Decision != DecisionBlock || len(r1.Events) != 1 || r1.Events[0].Protocol != model.ProtoMining {
		t.Fatalf("expected Stratum mining block, got %+v", r1)
	}

	// Outbound XMRig CryptoNote Stratum login
	s2 := NewTCPSession(testMeta("tcp", DirOutbound, 14444), cp, 16384)
	r2 := s2.Feed(false, []byte("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"login\":\"44tL\",\"pass\":\"x\",\"agent\":\"XMRig/6.21.0\"}}\n"))
	if r2.Decision != DecisionBlock || len(r2.Events) != 1 || r2.Events[0].Protocol != model.ProtoMining {
		t.Fatalf("expected XMRig login block, got %+v", r2)
	}

	// Outbound SSL mining pool TLS SNI
	sTLS := NewTCPSession(testMeta("tcp", DirOutbound, 14433), cp, 16384)
	rTLS := sTLS.Feed(false, wrapTLSRecord(buildClientHelloMsg("pool.supportxmr.com", false)))
	if rTLS.Decision != DecisionBlock || len(rTLS.Events) != 1 || rTLS.Events[0].Protocol != model.ProtoMining {
		t.Fatalf("expected mining pool TLS SNI block, got %+v", rTLS)
	}

	// Normal HTTPS API / JSON over HTTP must NOT false-positive as Stratum mining
	sHTTP := NewTCPSession(testMeta("tcp", DirOutbound, 80), cp, 16384)
	rHTTP := sHTTP.Feed(false, []byte("POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 29\r\n\r\n{\"method\":\"login\",\"user\":\"a\"}"))
	if rHTTP.Decision != DecisionAllow {
		t.Fatalf("expected normal HTTP POST JSON to pass cleanly, got %+v", rHTTP)
	}
}

func TestUDPProxy_BlocksHy2TUICAndObfsButAllowsDNSAndNTP(t *testing.T) {
	cp := testPolicy()
	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	// 1. Inbound Hysteria2 / TUIC (standard QUIC with arbitrary domain) -> blocked on packet 1
	pktHy2 := buildQUICInitialPacket(t, quicV1, dcid, buildClientHelloMsg("my-tuic.example.net", false))
	sHy2 := NewUDPSession(testMeta("udp", DirInbound, 8443), cp, 6)
	rHy2 := sHy2.Feed(false, pktHy2)
	if rHy2.Decision != DecisionBlock || len(rHy2.Events) != 1 || rHy2.Events[0].Protocol != model.ProtoUDPProxy {
		t.Fatalf("expected inbound Hy2/TUIC QUIC block, got %+v", rHy2)
	}

	// 2. Inbound Hysteria2 + Salamander obfs (random high-entropy UDP) -> blocked on packet 1
	obfs := makeDeterministicCipher(120, 7)
	sObfs := NewUDPSession(testMeta("udp", DirInbound, 20001), cp, 6)
	rObfs := sObfs.Feed(false, obfs)
	if rObfs.Decision != DecisionBlock || len(rObfs.Events) != 1 || rObfs.Events[0].Protocol != model.ProtoUDPProxy {
		t.Fatalf("expected inbound Salamander obfs UDP block on packet 1, got %+v", rObfs)
	}

	// 3. Inbound small/custom UDP proxy (e.g. KCP) blocked when BlockAllUDP=true
	sCustom := NewUDPSession(testMeta("udp", DirInbound, 29900), cp, 6)
	rCustom := sCustom.Feed(false, []byte("kcp-custom-hello-payload"))
	if rCustom.Decision != DecisionBlock || len(rCustom.Events) != 1 || rCustom.Events[0].Protocol != model.ProtoUDPProxy {
		t.Fatalf("expected inbound custom UDP block under BlockAllUDP=true, got %+v", rCustom)
	}

	// 4. Outbound QUIC (e.g. container visiting HTTP/3 website) must remain allowed when udp_proxy is DirInbound
	sOutQUIC := NewUDPSession(testMeta("udp", DirOutbound, 443), cp, 6)
	rOutQUIC := sOutQUIC.Feed(false, pktHy2)
	if rOutQUIC.Decision != DecisionAllow {
		t.Fatalf("expected outbound QUIC to remain allowed, got %+v", rOutQUIC)
	}

	// 5. Standard DNS & NTP must NEVER be blocked by udp_proxy even on matched direction
	dnsQuery := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	sDNS := NewUDPSession(testMeta("udp", DirInbound, 53), cp, 6)
	if rDNS := sDNS.Feed(false, dnsQuery); rDNS.Decision != DecisionAllow {
		t.Fatalf("expected standard DNS to pass, got %+v", rDNS)
	}

	ntpPkt := make([]byte, 48)
	ntpPkt[0] = 0x23 // LI=0, VN=4, Mode=3 (client)
	sNTP := NewUDPSession(testMeta("udp", DirInbound, 123), cp, 6)
	if rNTP := sNTP.Feed(false, ntpPkt); rNTP.Decision != DecisionAllow {
		t.Fatalf("expected standard NTP to pass, got %+v", rNTP)
	}

	// 6. When BlockAllUDP=false, small plain UDP passes while QUIC/Hy2/TUIC & obfs stay blocked
	polSoft := model.BuildPreset("anti_abuse")
	for i := range polSoft.Protocols {
		if polSoft.Protocols[i].ID == model.ProtoUDPProxy {
			polSoft.Protocols[i].Options.BlockAllUDP = false
		}
	}
	cpSoft := CompilePolicy(polSoft, "")
	sPlain := NewUDPSession(testMeta("udp", DirInbound, 29900), cpSoft, 6)
	if rPlain := sPlain.Feed(false, []byte("plain-game-ping-1234")); rPlain.Decision != DecisionAllow {
		t.Fatalf("expected plain UDP to pass when BlockAllUDP=false, got %+v", rPlain)
	}
	sHy2Soft := NewUDPSession(testMeta("udp", DirInbound, 8443), cpSoft, 6)
	if rHy2Soft := sHy2Soft.Feed(false, pktHy2); rHy2Soft.Decision != DecisionBlock {
		t.Fatalf("expected Hy2/TUIC QUIC to stay blocked when BlockAllUDP=false, got %+v", rHy2Soft)
	}
}

func TestTrojanOffloadWithoutCCSAndSharedGeoSite(t *testing.T) {
	cp := testPolicy()

	// P0-3: tls_sni and quic_sni with identical geosite config must share the same DomainPolicyMatcher pointer
	if cp.Rules[model.ProtoTLSSNI].DomainMatcher == nil || cp.Rules[model.ProtoTLSSNI].DomainMatcher != cp.Rules[model.ProtoQUICSNI].DomainMatcher {
		t.Fatalf("expected tls_sni and quic_sni to share a single DomainPolicyMatcher instance")
	}

	// P0-1: TLS 1.3 connection without ChangeCipherSpec must offload promptly instead of looping forever
	sess := NewTCPSession(testMeta("tcp", DirInbound, 443), cp, 16384)
	ch := wrapTLSRecord(buildClientHelloMsg("www.cloudflare.com", false))
	r := sess.Feed(false, ch)
	if r.Decision != DecisionContinue {
		t.Fatalf("expected post-TLS Trojan tracking to continue initially, got %+v", r)
	}
	offloaded := false
	chunk := make([]byte, 1400)
	chunk[0] = 0x17
	for i := 0; i < 30; i++ {
		res := sess.Feed(i%2 == 1, chunk)
		if res.Decision == DecisionAllow {
			offloaded = true
			break
		}
	}
	if !offloaded {
		t.Fatalf("expected TLS stream without ChangeCipherSpec to offload within 24 packets/32KB")
	}

	// P1-5: Stratum mining with leading whitespace must still be caught
	sMine := NewTCPSession(testMeta("tcp", DirOutbound, 3333), cp, 16384)
	rMine := sMine.Feed(false, []byte("  \t{\"id\":1,\"method\":\"mining.hello\",\"params\":[]}\n"))
	if rMine.Decision != DecisionBlock || len(rMine.Events) != 1 || rMine.Events[0].Protocol != model.ProtoMining {
		t.Fatalf("expected leading-whitespace Stratum mining block, got %+v", rMine)
	}

	// P1-5: QUIC CRYPTO frame parser must skip ACK frames inside Initial packets
	// ACK frame: type=0x02, largest=0, delay=0, range_count=0, first_range=0, followed by CRYPTO frame (0x06, off=0, len=3, "abc")
	payloadWithAck := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 'a', 'b', 'c'}
	frames, err := parseQUICCryptoFrames(payloadWithAck)
	if err != nil || len(frames) != 1 || string(frames[0].Data) != "abc" {
		t.Fatalf("expected parseQUICCryptoFrames to skip ACK frame, got frames=%+v err=%v", frames, err)
	}
}

func makeTestCert(t *testing.T, dnsName string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	isCA := caCert == nil
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tmpl.DNSNames = []string{dnsName}
	}
	parent := tmpl
	signer := key
	if caCert != nil {
		parent = caCert
		signer = caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, parsed, key
}

func buildTLSServerHello(tls13 bool) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)          // legacy version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len
	body = append(body, 0x13, 0x01)          // cipher suite
	body = append(body, 0x00)                // compression
	if tls13 {
		// supported_versions extension (0x002b) = 0x0304 (TLS 1.3)
		exts := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
		body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
		body = append(body, exts...)
	} else {
		body = binary.BigEndian.AppendUint16(body, 0)
	}
	hs := append([]byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return wrapTLSRecord(hs)
}

func buildTLS12CertMsg(derCerts ...[]byte) []byte {
	var list []byte
	for _, der := range derCerts {
		list = append(list, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		list = append(list, der...)
	}
	body := append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...)
	hs := append([]byte{0x0b, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return wrapTLSRecord(hs)
}

func TestVLESSPlainDetectionAndBenignSafety(t *testing.T) {
	cp := testPolicy()
	uuid := []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x88, 0x99, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76}

	// 1. Raw VLESS TCP targeting a domain (with plaintext HTTP inner payload -> would NOT look like high-entropy FET!)
	var vlessDomain []byte
	vlessDomain = append(vlessDomain, 0x00)
	vlessDomain = append(vlessDomain, uuid...)
	vlessDomain = append(vlessDomain, 0x00)       // addon_len = 0
	vlessDomain = append(vlessDomain, 0x01)       // cmd = TCP
	vlessDomain = append(vlessDomain, 0x00, 0x50) // port = 80
	vlessDomain = append(vlessDomain, 0x02)       // addrType = domain
	dom := "www.example.com"
	vlessDomain = append(vlessDomain, byte(len(dom)))
	vlessDomain = append(vlessDomain, dom...)
	vlessDomain = append(vlessDomain, "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"...)

	s1 := NewTCPSession(testMeta("tcp", DirInbound, 10086), cp, 16384)
	r1 := s1.Feed(false, vlessDomain)
	if r1.Decision != DecisionBlock || len(r1.Events) != 1 || r1.Events[0].Protocol != model.ProtoVLESSPlain {
		t.Fatalf("expected raw VLESS TCP domain request to be blocked as vless_plain, got %+v", r1)
	}

	// 2. Plaintext VLESS-WS (WebSocket carrying VLESS header + plaintext HTTP -> caught by vless_plain!)
	wsReq := "GET /vless HTTP/1.1\r\nHost: edge.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	mask := [4]byte{0x44, 0x55, 0x66, 0x77}
	wsFrame := []byte{0x82, 0x80 | byte(len(vlessDomain))}
	wsFrame = append(wsFrame, mask[:]...)
	for i, b := range vlessDomain {
		wsFrame = append(wsFrame, b^mask[i&3])
	}
	s2 := NewTCPSession(testMeta("tcp", DirInbound, 80), cp, 16384)
	if r := s2.Feed(false, []byte(wsReq)); r.Decision != DecisionContinue {
		t.Fatalf("expected continue on WS upgrade, got %+v", r)
	}
	r2 := s2.Feed(false, wsFrame)
	if r2.Decision != DecisionBlock || len(r2.Events) != 1 || r2.Events[0].Protocol != model.ProtoVLESSPlain {
		t.Fatalf("expected plaintext VLESS-WS to be blocked as vless_plain, got %+v", r2)
	}

	// 3. Benign binary starting with 0x00 (e.g. PostgreSQL startup message) must NOT match VLESS
	pgStartup := []byte{
		0x00, 0x00, 0x00, 0x26, // len = 38
		0x00, 0x03, 0x00, 0x00, // protocol 3.0
		'u', 's', 'e', 'r', 0x00, 'p', 'o', 's', 't', 'g', 'r', 'e', 's', 0x00,
		'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0x00, 'a', 'p', 'p', 0x00, 0x00,
	}
	if st, _ := DetectVLESSHeader(pgStartup); st != VLESSNotVLESS {
		t.Fatalf("PostgreSQL startup packet must not match VLESS, got status=%v", st)
	}
}

func TestPassiveTLS12CertCheckAndTLS13RealitySafety(t *testing.T) {
	pol := model.BuildPreset("anti_abuse")
	// Disable trojan so we isolate tls_untrusted behavior deterministically
	for i := range pol.Protocols {
		if pol.Protocols[i].ID == model.ProtoTrojan {
			pol.Protocols[i].Enabled = false
		}
	}
	cp := CompilePolicy(pol, "")

	_, caCert, caKey := makeTestCert(t, "Test Root CA", nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	validDER, _, _ := makeTestCert(t, "www.cloudflare.com", caCert, caKey)
	selfDER, _, _ := makeTestCert(t, "www.cloudflare.com", nil, nil)

	ch := wrapTLSRecord(buildClientHelloMsg("www.cloudflare.com", false))

	// 1. TLS 1.2 with self-signed cert -> blocked immediately on Connection #1
	sSelf := NewTCPSession(testMeta("tcp", DirInbound, 443), cp, 16384)
	sSelf.SetCertRoots(roots)
	if r := sSelf.Feed(false, ch); r.Decision != DecisionContinue {
		t.Fatalf("expected continue waiting for server cert, got %+v", r)
	}
	srvSelf := append(buildTLSServerHello(false), buildTLS12CertMsg(selfDER)...)
	if r := sSelf.Feed(true, srvSelf); r.Decision != DecisionBlock || len(r.Events) != 1 || r.Events[0].Protocol != model.ProtoTLSUntrusted {
		t.Fatalf("expected TLS 1.2 self-signed cert to be blocked as tls_untrusted, got %+v", r)
	}

	// 2. TLS 1.2 with valid CA cert matching SNI -> allowed cleanly
	sValid := NewTCPSession(testMeta("tcp", DirInbound, 443), cp, 16384)
	sValid.SetCertRoots(roots)
	_ = sValid.Feed(false, ch)
	srvValid := append(buildTLSServerHello(false), buildTLS12CertMsg(validDER)...)
	if r := sValid.Feed(true, srvValid); r.Decision != DecisionAllow || len(r.Events) != 0 {
		t.Fatalf("expected valid CA-signed TLS 1.2 cert to be allowed, got %+v", r)
	}

	// 3. TLS 1.3 (e.g. VLESS+REALITY / AnyTLS+REALITY / TLS 1.3 HTTPS) -> passive check sees TLS 1.3 and offloads cleanly
	s13 := NewTCPSession(testMeta("tcp", DirInbound, 443), cp, 16384)
	s13.SetCertRoots(roots)
	_ = s13.Feed(false, ch)
	if r := s13.Feed(true, buildTLSServerHello(true)); r.Decision != DecisionAllow || len(r.Events) != 0 {
		t.Fatalf("expected TLS 1.3 handshake (REALITY/HTTPS) to offload cleanly without false block, got %+v", r)
	}
}

func TestAirportPanelDetectionAllows3XUIAndSUI(t *testing.T) {
	cp := testPolicy()

	// 1. Outbound V2bX / XrayR UniProxy backend sync -> blocked as airport_panel
	sOut := NewTCPSession(testMeta("tcp", DirOutbound, 80), cp, 16384)
	rOut := sOut.Feed(false, []byte("GET /api/v1/server/UniProxy/config?node_id=1&node_type=vless HTTP/1.1\r\nHost: panel.airport.example\r\n\r\n"))
	if rOut.Decision != DecisionBlock || len(rOut.Events) != 1 || rOut.Events[0].Protocol != model.ProtoAirportPanel {
		t.Fatalf("expected V2Board UniProxy backend sync to be blocked as airport_panel, got %+v", rOut)
	}

	// 2. Outbound SSPanel mod_mu backend sync -> blocked as airport_panel
	sSS := NewTCPSession(testMeta("tcp", DirOutbound, 80), cp, 16384)
	rSS := sSS.Feed(false, []byte("GET /mod_mu/users?node_id=5&key=abc HTTP/1.1\r\nHost: ss.airport.example\r\n\r\n"))
	if rSS.Decision != DecisionBlock || len(rSS.Events) != 1 || rSS.Events[0].Protocol != model.ProtoAirportPanel {
		t.Fatalf("expected SSPanel mod_mu sync to be blocked as airport_panel, got %+v", rSS)
	}

	// 3. Inbound hosted V2Board/Xboard homepage over plain HTTP -> caught on first server response
	sHome := NewTCPSession(testMeta("tcp", DirInbound, 80), cp, 16384)
	if r := sHome.Feed(false, []byte("GET / HTTP/1.1\r\nHost: myairport.example\r\n\r\n")); r.Decision != DecisionContinue {
		t.Fatalf("expected GET / to inspect homepage response, got %+v", r)
	}
	v2bResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><script>window.settings={title:'Cloud',is_email_verify:1,is_invite_force:0}</script><script src=\"/theme/v2board/assets/umi.js\"></script></html>"
	if r := sHome.Feed(true, []byte(v2bResp)); r.Decision != DecisionBlock || len(r.Events) != 1 || r.Events[0].Protocol != model.ProtoAirportPanel {
		t.Fatalf("expected hosted V2Board homepage to be blocked as airport_panel, got %+v", r)
	}

	// 4. Personal node panels (3x-ui / x-ui / s-ui) MUST NOT be blocked!
	s3xui := NewTCPSession(testMeta("tcp", DirInbound, 2053), cp, 16384)
	r3xui := s3xui.Feed(false, []byte("POST /panel/inbound/list HTTP/1.1\r\nHost: node.example.com:2053\r\n\r\n"))
	if r3xui.Decision != DecisionAllow || len(r3xui.Events) != 0 {
		t.Fatalf("3x-ui API must NOT be blocked by airport_panel, got %+v", r3xui)
	}
	s3xuiHome := NewTCPSession(testMeta("tcp", DirInbound, 2053), cp, 16384)
	_ = s3xuiHome.Feed(false, []byte("GET / HTTP/1.1\r\nHost: node.example.com:2053\r\n\r\n"))
	xuiHTML := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: 3x-ui=abc; Path=/\r\n\r\n<html><title>3x-ui Login</title><body>" + string(make([]byte, 2200)) + "</body></html>"
	if r := s3xuiHome.Feed(true, []byte(xuiHTML)); r.Decision != DecisionAllow || len(r.Events) != 0 {
		t.Fatalf("3x-ui login homepage must NOT be blocked by airport_panel, got %+v", r)
	}
}
