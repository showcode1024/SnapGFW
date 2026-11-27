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
	}, model.PortRule{
		ID:        "block-low-guest-ports",
		Name:      "封容器入站低端口",
		Enabled:   true,
		Priority:  140,
		Direction: model.DirInbound,
		Scope:     model.PortScopeDst,
		L4Proto:   "tcp",
		PortStart: 1,
		PortEnd:   20000,
		Action:    model.ActionBlock,
	})

	script, err := RenderNFT(cfg, pol)
	if err != nil {
		t.Fatalf("RenderNFT failed: %v", err)
	}
	checks := []string{
		`table inet snapgfw`,
		`type filter hook forward priority filter + 10`,
		`type filter hook output priority filter + 10`,
		`type filter hook input priority filter + 10`,
		`iifname != "rmbr0" oifname != "rmbr0" accept`,
		`oifname != "rmbr0" accept`,
		`iifname != "rmbr0" accept`,
		`ct direction reply accept`,
		`ct direction original accept`,
		`ip saddr 10.91.0.2 meta l4proto tcp tcp dport 25 counter accept`,
		`ct original protocol tcp ct original proto-dst 22022 counter drop`,
		`oifname "rmbr0" ct direction original meta l4proto tcp tcp dport 1-20000 counter drop`,
		`ct mark 2001 counter accept`,
		`ct mark 2002 counter drop`,
		`queue num 200 bypass`,
		`queue num 201 bypass`,
		`queue num 202 bypass`,
		`queue num 203 bypass`,
		`oifname "rmbr0" ct direction original counter queue num 200 bypass`,
		`iifname "rmbr0" ct direction reply counter queue num 203 bypass`,
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

	// Host-proxy chains can be opted out via DisableHostProxy
	cfgNoProxy := cfg
	cfgNoProxy.DisableHostProxy = true
	noProxyScript, err := RenderNFT(cfgNoProxy, pol)
	if err != nil {
		t.Fatalf("RenderNFT disable host proxy failed: %v", err)
	}
	if strings.Contains(noProxyScript, "hook output") || strings.Contains(noProxyScript, "hook input") {
		t.Fatalf("expected DisableHostProxy=true to omit output/input chains:\n%s", noProxyScript)
	}

	// Empty default policy skips NFQUEUE dispatch completely for zero fastpath overhead
	emptyScript, err := RenderNFT(cfg, model.DefaultPolicy())
	if err != nil {
		t.Fatalf("RenderNFT empty failed: %v", err)
	}
	if strings.Contains(emptyScript, "queue num") {
		t.Fatalf("expected empty default policy to skip NFQUEUE rules:\n%s", emptyScript)
	}

	// TCP-only DPI policy must skip UDP from NFQUEUE (zero userspace copy for UDP)
	tcpOnly := model.DefaultPolicy()
	for i := range tcpOnly.Protocols {
		if tcpOnly.Protocols[i].ID == model.ProtoTLSSNI {
			tcpOnly.Protocols[i].Enabled = true
			tcpOnly.Protocols[i].Action = model.ActionBlock
		}
	}
	tcpScript, err := RenderNFT(cfg, tcpOnly)
	if err != nil {
		t.Fatalf("RenderNFT tcp-only failed: %v", err)
	}
	if !strings.Contains(tcpScript, "meta l4proto != tcp accept") {
		t.Fatalf("expected TCP-only policy to bypass UDP before NFQUEUE:\n%s", tcpScript)
	}

	// UDP-only DPI policy must skip TCP from NFQUEUE
	udpOnly := model.DefaultPolicy()
	for i := range udpOnly.Protocols {
		if udpOnly.Protocols[i].ID == model.ProtoUDPProxy {
			udpOnly.Protocols[i].Enabled = true
			udpOnly.Protocols[i].Action = model.ActionBlock
		}
	}
	udpScript, err := RenderNFT(cfg, udpOnly)
	if err != nil {
		t.Fatalf("RenderNFT udp-only failed: %v", err)
	}
	if !strings.Contains(udpScript, "meta l4proto != udp accept") {
		t.Fatalf("expected UDP-only policy to bypass TCP before NFQUEUE:\n%s", udpScript)
	}
}

func TestParseNFTJSONStats(t *testing.T) {
	raw := `{
		"nftables": [
			{"rule": {"chain": "forward", "expr": [{"match": {"right": "@quarantine4"}}, {"counter": {"packets": 12, "bytes": 720}}, {"drop": null}]}},
			{"rule": {"chain": "forward", "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 3333}}, {"counter": {"packets": 5, "bytes": 300}}, {"drop": null}]}},
			{"rule": {"chain": "forward", "expr": [{"add": {"set": "@conn_rate4"}}, {"counter": {"packets": 63472, "bytes": 3845885}}, {"drop": null}]}},
			{"rule": {"chain": "forward", "expr": [{"match": {"left": {"ct": {"key": "mark"}}, "right": 2002}}, {"counter": {"packets": 999, "bytes": 50000}}, {"drop": null}]}}
		]
	}`
	st := ParseNFTJSONStats([]byte(raw), 2002)
	if st.QuarantineDrops != 12 || st.PortDrops != 5 || st.RateDrops != 63472 || st.TotalDrops != 63489 {
		t.Fatalf("unexpected L4 stats (must exclude ct mark 2002 DPI drops): %+v", st)
	}
}
