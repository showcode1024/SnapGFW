package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"snapgfw/internal/config"
	"snapgfw/internal/model"
	"snapgfw/internal/proto"
	"snapgfw/internal/store"
)

func buildIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, flags uint8, payload []byte) []byte {
	totLen := 20 + 20 + len(payload)
	pkt := make([]byte, totLen)
	pkt[0] = 0x45 // v4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totLen))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	pkt[32] = 0x50 // data offset 20
	pkt[33] = flags
	copy(pkt[40:], payload)
	return pkt
}

func buildIPv6UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	totLen := 40 + 8 + len(payload)
	pkt := make([]byte, totLen)
	pkt[0] = 0x60 // v6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	pkt[6] = 17 // UDP
	pkt[7] = 64
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(8+len(payload)))
	copy(pkt[48:], payload)
	return pkt
}

func TestEngine_TCPReassemblyOutOfOrderAndQuarantine(t *testing.T) {
	cfg := config.Default()
	cfg.Workers = 2
	pol := model.BuildPreset("anti_abuse")
	pol.Abuse.AutoQuarantineEnabled = true
	pol.Abuse.QuarantineThreshold = 2
	pol.Abuse.QuarantineWindowSec = 60
	pol.Abuse.QuarantineDurationSec = 120

	audit, err := store.NewAuditStore("", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	qm := NewQuarantineManager(cfg.NftTable, audit, nil)
	qm.applyBan = func(_, _ string, _ int) error { return nil }
	qm.applyUnban = func(_, _ string) error { return nil }
	eng := New(cfg, pol, audit, nil, qm)

	peerIP := net.ParseIP("198.51.100.10")
	tenantIP := net.ParseIP("10.91.0.2")

	// Stream 1: segmented SOCKS5 handshake arriving out-of-order!
	syn := buildIPv4TCP(peerIP, tenantIP, 50000, 1080, 1000, TCPFlagSYN, nil)
	if v := eng.ProcessSync(PacketEvent{StreamID: 101, Direction: proto.DirInbound, Reverse: false, Data: syn}); v != VerdictAccept {
		t.Fatalf("expected VerdictAccept on SYN, got %v", v)
	}
	// Send segment 2 (bytes [2:3] = {0x00}) BEFORE segment 1 (bytes [0:2] = {0x05, 0x01})!
	seg2 := buildIPv4TCP(peerIP, tenantIP, 50000, 1080, 1003, TCPFlagACK|TCPFlagPSH, []byte{0x00})
	if v := eng.ProcessSync(PacketEvent{StreamID: 101, Direction: proto.DirInbound, Reverse: false, Data: seg2}); v != VerdictAccept {
		t.Fatalf("expected VerdictAccept while OOO buffered, got %v", v)
	}
	seg1 := buildIPv4TCP(peerIP, tenantIP, 50000, 1080, 1001, TCPFlagACK|TCPFlagPSH, []byte{0x05, 0x01})
	if v := eng.ProcessSync(PacketEvent{StreamID: 101, Direction: proto.DirInbound, Reverse: false, Data: seg1}); v != VerdictDropStream {
		t.Fatalf("expected VerdictDropStream once OOO SOCKS5 reassembled, got %v", v)
	}

	// Stream 2: SS-2022 random ciphertext -> hits threshold=2 and triggers auto-quarantine!
	rnd := makeTestCipher(64, 1)
	syn2 := buildIPv4TCP(peerIP, tenantIP, 50001, 8388, 2000, TCPFlagSYN, nil)
	_ = eng.ProcessSync(PacketEvent{StreamID: 102, Direction: proto.DirInbound, Reverse: false, Data: syn2})
	segFET := buildIPv4TCP(peerIP, tenantIP, 50001, 8388, 2001, TCPFlagACK|TCPFlagPSH, rnd)
	if v := eng.ProcessSync(PacketEvent{StreamID: 102, Direction: proto.DirInbound, Reverse: false, Data: segFET}); v != VerdictDropStream {
		t.Fatalf("expected VerdictDropStream on FET TCP, got %v", v)
	}

	banned := qm.ListActive()
	if len(banned) != 1 || banned[0].TenantIP != "10.91.0.2" {
		t.Fatalf("expected tenant 10.91.0.2 auto-quarantined, got %+v", banned)
	}
	events := audit.Query("10.91.0.2", "", "", "", 10)
	if len(events) != 3 { // socks + fet_tcp + quarantine
		t.Fatalf("expected 3 audit events, got %d: %+v", len(events), events)
	}
}

func TestEngine_IPv6UDPAndMidStreamSafety(t *testing.T) {
	cfg := config.Default()
	cfg.Workers = 1
	pol := model.BuildPreset("anti_abuse")
	// Enable WireGuard block manually to test IPv6 UDP detection
	for i := range pol.Protocols {
		if pol.Protocols[i].ID == model.ProtoWireGuard {
			pol.Protocols[i].Enabled = true
			pol.Protocols[i].Action = model.ActionBlock
			pol.Protocols[i].Direction = model.DirBoth
		}
	}
	eng := New(cfg, pol, nil, nil, nil)

	peer6 := net.ParseIP("2001:db8::99")
	tenant6 := net.ParseIP("fd91:cafe:cafe:10::2")

	// IPv6 WireGuard handshake initiation (must be caught even over IPv6!)
	wg := make([]byte, 148)
	wg[0] = 0x01
	pkt6 := buildIPv6UDP(peer6, tenant6, 40000, 51820, wg)
	if v := eng.ProcessSync(PacketEvent{StreamID: 201, Direction: proto.DirInbound, Reverse: false, Data: pkt6}); v != VerdictDropStream {
		t.Fatalf("expected IPv6 WireGuard to be blocked, got %v", v)
	}

	// Mid-stream TCP packet without SYN must offload safely without false FET block
	rnd := makeTestCipher(128, 9)
	midTCP := buildIPv4TCP(net.ParseIP("198.51.100.1"), net.ParseIP("10.91.0.2"), 44444, 22, 99999, TCPFlagACK|TCPFlagPSH, rnd)
	if v := eng.ProcessSync(PacketEvent{StreamID: 202, Direction: proto.DirInbound, Reverse: false, Data: midTCP}); v != VerdictAcceptStream {
		t.Fatalf("expected mid-stream TCP without SYN to offload safely, got %v", v)
	}
}

func TestEngine_BurstLogDeduplication(t *testing.T) {
	cfg := config.Default()
	cfg.Workers = 1
	cfg.AuditRingCap = 50
	cfg.AuditBurstSec = 5
	pol := model.BuildPreset("anti_abuse")

	audit, err := store.NewAuditStore("", cfg.AuditRingCap, 0)
	if err != nil {
		t.Fatal(err)
	}
	eng := New(cfg, pol, audit, nil, nil)

	peerIP := net.ParseIP("198.51.100.20")
	tenantIP := net.ParseIP("10.91.0.9")

	for i := uint32(1); i <= 6; i++ {
		rnd := makeTestCipher(64, byte(i))
		syn := buildIPv4TCP(peerIP, tenantIP, uint16(40000+i), 8388, i*1000, TCPFlagSYN, nil)
		_ = eng.ProcessSync(PacketEvent{StreamID: 500 + i, Direction: proto.DirInbound, Reverse: false, Data: syn})
		pay := buildIPv4TCP(peerIP, tenantIP, uint16(40000+i), 8388, i*1000+1, TCPFlagACK|TCPFlagPSH, rnd)
		if v := eng.ProcessSync(PacketEvent{StreamID: 500 + i, Direction: proto.DirInbound, Reverse: false, Data: pay}); v != VerdictDropStream {
			t.Fatalf("expected drop on FET stream %d, got %v", i, v)
		}
	}

	blocks, _, _ := audit.Totals()
	events := audit.Query("10.91.0.9", "fet_tcp", "block", "", 20)
	if blocks != 6 {
		t.Fatalf("expected exact counter blocks=6, got %d", blocks)
	}
	if len(events) != 1 {
		t.Fatalf("expected burst log deduplication to store 1 ring event, got %d", len(events))
	}
}

func TestQuarantineReapplyActive(t *testing.T) {
	qm := NewQuarantineManager("snapgfw", nil, nil)
	var applied []string
	var lastDur int
	qm.applyBan = func(_, ip string, dur int) error {
		applied = append(applied, ip)
		lastDur = dur
		return nil
	}
	qm.applyUnban = func(_, _ string) error { return nil }

	if err := qm.Ban("10.91.0.55", "c1", "box1", "mining", 300, false, model.NotifyConfig{}); err != nil {
		t.Fatal(err)
	}
	applied = nil
	if err := qm.ReapplyActive(); err != nil {
		t.Fatalf("ReapplyActive failed: %v", err)
	}
	if len(applied) != 1 || applied[0] != "10.91.0.55" || lastDur < 290 || lastDur > 300 {
		t.Fatalf("expected ReapplyActive to restore active ban with remaining TTL, got applied=%v dur=%d", applied, lastDur)
	}
}

func makeTestCipher(n int, seed byte) []byte {
	out := make([]byte, n)
	state := seed ^ 0x9b
	for i := range out {
		state = byte((int(state)*73 + 179) & 0xff)
		out[i] = state
	}
	return out
}

func startTestTLS13Server(t *testing.T, cert tls.Certificate, httpBody string) (uint16, func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tc := conn.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				if httpBody != "" {
					buf := make([]byte, 1024)
					_ = tc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					if n, _ := tc.Read(buf); n > 0 {
						_, _ = tc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" + httpBody))
					}
				}
			}(c)
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port), func() { _ = ln.Close() }
}

func makeEngineTestCert(t *testing.T, dnsName string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, parsed, key
}

func buildTestTLSClientHello(sni string) []byte {
	var sniExt []byte
	sniBytes := []byte(sni)
	listLen := 1 + 2 + len(sniBytes)
	sniExt = binary.BigEndian.AppendUint16(sniExt, 0x0000)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(2+listLen))
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(listLen))
	sniExt = append(sniExt, 0x00)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniBytes)))
	sniExt = append(sniExt, sniBytes...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(sniExt)))
	body = append(body, sniExt...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestStrategyA_ActiveTLSProbeBlocksSelfSignedAndAllowsReality(t *testing.T) {
	_, caCert, caKey := makeEngineTestCert(t, "Test Root CA", nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Server 1: Self-signed TLS 1.3 (simulating Trojan / VLESS+TLS / AnyTLS without REALITY)
	selfCert, _, _ := makeEngineTestCert(t, "www.microsoft.com", nil, nil)
	selfPort, stopSelf := startTestTLS13Server(t, selfCert, "")
	defer stopSelf()

	// Server 2: CA-signed TLS 1.3 matching SNI (simulating VLESS+REALITY / AnyTLS+REALITY proxying probe to real dest)
	realityCert, _, _ := makeEngineTestCert(t, "www.microsoft.com", caCert, caKey)
	realityPort, stopReality := startTestTLS13Server(t, realityCert, "<html><title>Microsoft</title></html>")
	defer stopReality()

	// Server 3: CA-signed TLS 1.3 with mismatched domain
	mismatchCert, _, _ := makeEngineTestCert(t, "other.example.net", caCert, caKey)
	mismatchPort, stopMismatch := startTestTLS13Server(t, mismatchCert, "")
	defer stopMismatch()

	// Server 4: CA-signed HTTPS V2Board commercial airport panel -> blocked by airport_panel!
	v2bCert, _, _ := makeEngineTestCert(t, "shop.airport.example", caCert, caKey)
	v2bPort, stopV2B := startTestTLS13Server(t, v2bCert, "<html><script>window.settings={is_email_verify:1,is_invite_force:0}</script><script src=\"/theme/xboard/assets/app.js\"></script></html>")
	defer stopV2B()

	// Server 5: CA-signed HTTPS 3x-ui personal node panel -> MUST stay allowed!
	xuiCert, _, _ := makeEngineTestCert(t, "node.personal.example", caCert, caKey)
	xuiPort, stopXUI := startTestTLS13Server(t, xuiCert, "<html><title>3x-ui Panel</title><body>s-ui / 3x-ui</body></html>")
	defer stopXUI()

	cfg := config.Default()
	cfg.Workers = 1
	pol := model.BuildPreset("anti_abuse")
	for i := range pol.Protocols {
		if pol.Protocols[i].ID == model.ProtoTrojan {
			pol.Protocols[i].Enabled = false
		}
	}
	audit, err := store.NewAuditStore("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	eng := New(cfg, pol, audit, nil, nil)
	eng.Prober().SetRoots(roots)

	tenantIP := net.ParseIP("127.0.0.1")
	peerIP := net.ParseIP("198.51.100.88")
	ch := buildTestTLSClientHello("www.microsoft.com")

	// 1. Probe self-signed port -> cached Untrusted -> engine blocks inbound TLS stream!
	if res := eng.Prober().ProbeSync(tenantIP, selfPort, "www.microsoft.com", true); res.CertStatus != proto.TLSProbeUntrusted {
		t.Fatalf("expected self-signed server to probe as Untrusted, got %+v", res)
	}
	syn1 := buildIPv4TCP(peerIP, tenantIP, 51001, selfPort, 100, TCPFlagSYN, nil)
	_ = eng.ProcessSync(PacketEvent{StreamID: 901, Direction: proto.DirInbound, Reverse: false, Data: syn1})
	pay1 := buildIPv4TCP(peerIP, tenantIP, 51001, selfPort, 101, TCPFlagACK|TCPFlagPSH, ch)
	if v := eng.ProcessSync(PacketEvent{StreamID: 901, Direction: proto.DirInbound, Reverse: false, Data: pay1}); v != VerdictDropStream {
		t.Fatalf("expected self-signed TLS proxy to be blocked, got %v", v)
	}

	// 2. Probe REALITY / valid HTTPS port -> cached Trusted & Clean -> engine allows immediately!
	if res := eng.Prober().ProbeSync(tenantIP, realityPort, "www.microsoft.com", true); res.CertStatus != proto.TLSProbeTrusted || res.AirportStatus != proto.TLSProbeTrusted {
		t.Fatalf("expected REALITY/valid CA server to probe as Trusted+Clean, got %+v", res)
	}
	syn2 := buildIPv4TCP(peerIP, tenantIP, 51002, realityPort, 200, TCPFlagSYN, nil)
	_ = eng.ProcessSync(PacketEvent{StreamID: 902, Direction: proto.DirInbound, Reverse: false, Data: syn2})
	pay2 := buildIPv4TCP(peerIP, tenantIP, 51002, realityPort, 201, TCPFlagACK|TCPFlagPSH, ch)
	if v := eng.ProcessSync(PacketEvent{StreamID: 902, Direction: proto.DirInbound, Reverse: false, Data: pay2}); v != VerdictAcceptStream {
		t.Fatalf("expected REALITY / valid HTTPS to be allowed cleanly, got %v", v)
	}

	// 3. Probe SNI-mismatched port -> cached Untrusted -> engine blocks!
	if res := eng.Prober().ProbeSync(tenantIP, mismatchPort, "www.microsoft.com", true); res.CertStatus != proto.TLSProbeUntrusted {
		t.Fatalf("expected mismatched cert to probe as Untrusted, got %+v", res)
	}
	syn3 := buildIPv4TCP(peerIP, tenantIP, 51003, mismatchPort, 300, TCPFlagSYN, nil)
	_ = eng.ProcessSync(PacketEvent{StreamID: 903, Direction: proto.DirInbound, Reverse: false, Data: syn3})
	pay3 := buildIPv4TCP(peerIP, tenantIP, 51003, mismatchPort, 301, TCPFlagACK|TCPFlagPSH, ch)
	if v := eng.ProcessSync(PacketEvent{StreamID: 903, Direction: proto.DirInbound, Reverse: false, Data: pay3}); v != VerdictDropStream {
		t.Fatalf("expected SNI-mismatched TLS proxy to be blocked, got %v", v)
	}

	// 4. Probe CA-signed HTTPS Xboard/V2Board airport panel -> Cert Trusted, Airport Untrusted -> blocked as airport_panel!
	if res := eng.Prober().ProbeSync(tenantIP, v2bPort, "shop.airport.example", true); res.CertStatus != proto.TLSProbeTrusted || res.AirportStatus != proto.TLSProbeUntrusted {
		t.Fatalf("expected HTTPS Xboard panel to probe as CertTrusted+AirportUntrusted, got %+v", res)
	}
	chV2B := buildTestTLSClientHello("shop.airport.example")
	syn5 := buildIPv4TCP(peerIP, tenantIP, 51005, v2bPort, 500, TCPFlagSYN, nil)
	_ = eng.ProcessSync(PacketEvent{StreamID: 905, Direction: proto.DirInbound, Reverse: false, Data: syn5})
	pay5 := buildIPv4TCP(peerIP, tenantIP, 51005, v2bPort, 501, TCPFlagACK|TCPFlagPSH, chV2B)
	if v := eng.ProcessSync(PacketEvent{StreamID: 905, Direction: proto.DirInbound, Reverse: false, Data: pay5}); v != VerdictDropStream {
		t.Fatalf("expected CA-signed HTTPS Xboard airport panel to be blocked, got %v", v)
	}

	// 5. Probe CA-signed HTTPS 3x-ui personal panel -> Cert Trusted + Airport Clean -> ALLOWED!
	if res := eng.Prober().ProbeSync(tenantIP, xuiPort, "node.personal.example", true); res.CertStatus != proto.TLSProbeTrusted || res.AirportStatus != proto.TLSProbeTrusted {
		t.Fatalf("expected HTTPS 3x-ui panel to probe as CertTrusted+AirportClean, got %+v", res)
	}
	chXUI := buildTestTLSClientHello("node.personal.example")
	syn6 := buildIPv4TCP(peerIP, tenantIP, 51006, xuiPort, 600, TCPFlagSYN, nil)
	_ = eng.ProcessSync(PacketEvent{StreamID: 906, Direction: proto.DirInbound, Reverse: false, Data: syn6})
	pay6 := buildIPv4TCP(peerIP, tenantIP, 51006, xuiPort, 601, TCPFlagACK|TCPFlagPSH, chXUI)
	if v := eng.ProcessSync(PacketEvent{StreamID: 906, Direction: proto.DirInbound, Reverse: false, Data: pay6}); v != VerdictAcceptStream {
		t.Fatalf("expected HTTPS 3x-ui personal panel to remain allowed, got %v", v)
	}

	// 6. Verify IsOwnProbe bypasses DPI completely so host probes never self-block
	eng.Prober().inFlightMu.Lock()
	eng.Prober().inFlight[probeEndpoint{localIP: peerIP.String(), localPort: 51999, dstIP: tenantIP.String(), dstPort: selfPort}] = struct{}{}
	eng.Prober().inFlightMu.Unlock()
	synOwn := buildIPv4TCP(peerIP, tenantIP, 51999, selfPort, 400, TCPFlagSYN, nil)
	if v := eng.ProcessSync(PacketEvent{StreamID: 904, Direction: proto.DirInbound, Reverse: false, Data: synOwn}); v != VerdictAcceptStream {
		t.Fatalf("expected own probe stream to bypass DPI immediately, got %v", v)
	}
}
