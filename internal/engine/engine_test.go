package engine

import (
	"encoding/binary"
	"net"
	"testing"

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
