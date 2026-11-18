package netfilter

import (
	"strings"
	"testing"

	"snapgfw/internal/config"
	"snapgfw/internal/model"
)

func TestRenderNFT_IsolationAndQueues(t *testing.T) {
	cfg := config.Default()
	pol := model.BuildPreset("anti_abuse")
	pol.PortRules = append(pol.PortRules, model.PortRule{
		ID:        "allow-tenant-25",
		Name:      "放行指定实例25",
		Enabled:   true,
		Priority:  200,
		Direction: model.DirOutbound,
		Scope:     model.PortScopeDst,
		L4Proto:   "tcp",
		PortStart: 25,
		TenantIP:  "10.91.0.2",
		Action:    model.ActionAllow,
	}, model.PortRule{
		ID:        "block-host-mapped",
		Name:      "封宿主机映射端口",
		Enabled:   true,
		Priority:  150,
		Direction: model.DirInbound,
		Scope:     model.PortScopeHostMapped,
		L4Proto:   "tcp",
		PortStart: 22022,
		Action:    model.ActionBlock,
	})

	script, err := RenderNFT(cfg, pol)
	if err != nil {
		t.Fatalf("RenderNFT failed: %v", err)
	}
	checks := []string{
		`table inet snapgfw`,
		`type filter hook forward priority filter + 10`,
		`iifname != "rmbr0" oifname != "rmbr0" accept`,
		`ip saddr 10.91.0.2 meta l4proto tcp tcp dport 25 counter accept`,
		`ct original protocol tcp ct original proto-dst 22022 counter drop`,
		`ct mark 2001 counter accept`,
		`ct mark 2002 counter drop`,
		`queue num 200 bypass`,
		`queue num 201 bypass`,
		`queue num 202 bypass`,
		`queue num 203 bypass`,
	}
	for _, want := range checks {
		if !strings.Contains(script, want) {
			t.Fatalf("rendered nft script missing %q\n---\n%s", want, script)
		}
	}
	// Priority 200 allow rule must appear BEFORE priority 100 block rule
	idxAllow := strings.Index(script, "ip saddr 10.91.0.2 meta l4proto tcp tcp dport 25 counter accept")
	idxBlock := strings.Index(script, `iifname "rmbr0" oifname != "rmbr0" ct direction original meta l4proto tcp tcp dport 25 counter drop`)
	if idxAllow < 0 || idxBlock < 0 || idxAllow >= idxBlock {
		t.Fatalf("expected priority 200 allow rule before priority 100 block rule")
	}

	// Empty default policy skips NFQUEUE dispatch completely for zero fastpath overhead
	emptyScript, err := RenderNFT(cfg, model.DefaultPolicy())
	if err != nil {
		t.Fatalf("RenderNFT empty failed: %v", err)
	}
	if strings.Contains(emptyScript, "queue num") {
		t.Fatalf("expected empty default policy to skip NFQUEUE rules:\n%s", emptyScript)
	}
}
