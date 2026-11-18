package store

import (
	"path/filepath"
	"testing"

	"snapgfw/internal/model"
)

func TestPolicyStore_EmptyDefaultImportAndEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	ps, err := NewPolicyStore(path)
	if err != nil {
		t.Fatalf("NewPolicyStore failed: %v", err)
	}
	p := ps.Get()
	if p.ActivePreset != "custom" || len(p.Protocols) != len(model.AllProtocolIDs) || len(p.PortRules) != 0 {
		t.Fatalf("unexpected initial empty policy: preset=%s protos=%d ports=%d", p.ActivePreset, len(p.Protocols), len(p.PortRules))
	}
	for _, pr := range p.Protocols {
		if pr.Enabled {
			t.Fatalf("expected default policy protocol %s to start disabled", pr.ID)
		}
	}

	var hookCalled int
	ps.OnChange(func(next model.Policy) error {
		hookCalled++
		return nil
	})
	// Importing recommended preset populates anti_blacklist rules
	if _, err := ps.ApplyPreset("anti_blacklist", true); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if hookCalled != 1 || ps.Get().ActivePreset != "anti_blacklist" {
		t.Fatalf("unexpected preset apply state")
	}

	// Unknown presets must be rejected cleanly
	if _, err := ps.ApplyPreset("strict_block", true); err == nil {
		t.Fatalf("expected error for unknown preset")
	}

	// User can freely modify the imported policy afterwards
	edited := ps.Get()
	edited.Protocols[0].Enabled = false
	edited.PortRules = nil
	if err := ps.Update(edited); err != nil {
		t.Fatalf("editing imported policy failed: %v", err)
	}

	ps2, err := NewPolicyStore(path)
	if err != nil || ps2.Get().Protocols[0].Enabled || len(ps2.Get().PortRules) != 0 {
		t.Fatalf("reload edited policy from disk failed: err=%v", err)
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

	// Default NewAuditStore must enforce restrained RAM (<=200) and ROM (<=4 MiB total)
	defAS, err := NewAuditStore(filepath.Join(dir, "def.jsonl"), -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer defAS.Close()
	if defAS.RingCap() != 200 || defAS.MaxDiskBytes() != 4*1024*1024 {
		t.Fatalf("unexpected default audit bounds: ring=%d maxDisk=%d", defAS.RingCap(), defAS.MaxDiskBytes())
	}
}
