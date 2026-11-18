package store

import (
	"path/filepath"
	"testing"

	"natgfw/internal/model"
)

func TestPolicyStore_CreatePresetUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	ps, err := NewPolicyStore(path)
	if err != nil {
		t.Fatalf("NewPolicyStore failed: %v", err)
	}
	p := ps.Get()
	if p.ActivePreset != "anti_blacklist" || len(p.Protocols) != len(model.AllProtocolIDs) {
		t.Fatalf("unexpected initial policy: preset=%s protos=%d", p.ActivePreset, len(p.Protocols))
	}

	var hookCalled int
	ps.OnChange(func(next model.Policy) error {
		hookCalled++
		return nil
	})
	if _, err := ps.ApplyPreset("strict_block", true); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if hookCalled != 1 || ps.Get().ActivePreset != "strict_block" {
		t.Fatalf("unexpected preset apply state")
	}

	ps2, err := NewPolicyStore(path)
	if err != nil || ps2.Get().ActivePreset != "strict_block" {
		t.Fatalf("reload from disk failed: err=%v", err)
	}
}

func TestAuditStore_RecordQueryRotate(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "audit.jsonl")
	as, err := NewAuditStore(logFile, 5, 512)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()

	for i := 0; i < 8; i++ {
		as.Record(AuditEvent{
			TenantIP: "10.91.0.2",
			PeerIP:   "1.2.3.4",
			L4Proto:  "tcp",
			Direction: "in",
			DstPort:  443,
			Protocol: "tls_sni",
			Action:   "block",
			Detail:   "sni=www.baidu.com",
		})
	}
	events := as.Query("10.91.0.2", "", "", "baidu", 10)
	if len(events) != 5 {
		t.Fatalf("expected ringCap=5 events, got %d", len(events))
	}
	blocks, _, _ := as.Totals()
	if blocks != 8 {
		t.Fatalf("expected 8 total blocks, got %d", blocks)
	}
}
