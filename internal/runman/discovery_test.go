package runman

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscovery(t *testing.T) {
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "instances", "11111111-1111-1111-1111-111111111111")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	instJSON := `{
		"id": "11111111-1111-1111-1111-111111111111",
		"idx": 0,
		"cpu": 1,
		"ram_mb": 256,
		"hostname": "vps-11111111",
		"desired": "running",
		"builder": false,
		"addrs": {"ipv4": "10.91.0.2", "ipv6": "fd91:cafe:cafe:10::2"}
	}`
	if err := os.WriteFile(filepath.Join(vmDir, "instance.json"), []byte(instJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	fwJSON := `[
		{"vm_id":"11111111-1111-1111-1111-111111111111","proto":"tcp","host_port":22022,"guest_port":22,"description":"ssh"}
	]`
	if err := os.WriteFile(filepath.Join(dir, "portforwards.json"), []byte(fwJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	d := NewDiscovery(dir)
	snap := d.Snapshot()
	if !snap.Available || len(snap.Instances) != 1 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	inst, ok := snap.LookupByIP("10.91.0.2")
	if !ok || inst.Hostname != "vps-11111111" {
		t.Fatalf("LookupByIP failed: %+v, %v", inst, ok)
	}
	if _, ok := snap.LookupByIP("fd91:cafe:cafe:10::2"); !ok {
		t.Fatal("IPv6 lookup failed")
	}
	if hp := snap.LookupHostPort("10.91.0.2", "tcp", 22); hp != 22022 {
		t.Fatalf("expected host port 22022, got %d", hp)
	}
}
