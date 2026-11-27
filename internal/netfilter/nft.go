package netfilter

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"snapgfw/internal/config"
	"snapgfw/internal/geo"
	"snapgfw/internal/model"
)

// RenderNFT generates the complete atomic nftables ruleset for `table inet <NftTable>`.
// It inspects both kernel-forwarded bridge traffic (`forward`) and, unless DisableHostProxy is set,
// host userspace proxy traffic entering the container bridge (`output` original + `input` reply,
// covering narwhal-agent / docker-proxy / Podman port forwards) while exempting host non-bridge
// traffic and container-to-host local services (such as DNS 53).
func RenderNFT(cfg config.Config, pol model.Policy) (string, error) {
	var b strings.Builder
	tbl := cfg.NftTable
	br := cfg.BridgeIface

	fmt.Fprintf(&b, "add table inet %s\n", tbl)
	fmt.Fprintf(&b, "delete table inet %s\n\n", tbl)
	fmt.Fprintf(&b, "table inet %s {\n", tbl)

	// Quarantine sets (dynamically updated via nft add/delete element without full reload)
	b.WriteString("  set quarantine4 {\n    type ipv4_addr\n    flags timeout\n  }\n")
	b.WriteString("  set quarantine6 {\n    type ipv6_addr\n    flags timeout\n  }\n")

	// Dynamic per-tenant meters for L4 abuse protection
	if pol.Abuse.MaxConnsPerTenant > 0 {
		b.WriteString("  set conn_limit4 {\n    type ipv4_addr\n    size 65535\n    flags dynamic\n  }\n")
		b.WriteString("  set conn_limit6 {\n    type ipv6_addr\n    size 65535\n    flags dynamic\n  }\n")
	}
	if pol.Abuse.NewConnRatePerSec > 0 {
		b.WriteString("  set conn_rate4 {\n    type ipv4_addr\n    size 65535\n    flags dynamic,timeout\n    timeout 1m\n  }\n")
		b.WriteString("  set conn_rate6 {\n    type ipv6_addr\n    size 65535\n    flags dynamic,timeout\n    timeout 1m\n  }\n")
	}
	if pol.Abuse.UDPPPSLimitPerTenant > 0 {
		b.WriteString("  set udp_pps4 {\n    type ipv4_addr\n    size 65535\n    flags dynamic,timeout\n    timeout 1m\n  }\n")
		b.WriteString("  set udp_pps6 {\n    type ipv6_addr\n    size 65535\n    flags dynamic,timeout\n    timeout 1m\n  }\n")
	}

	// Collect GeoIP country sets required by enabled port rules
	geoSetsNeeded := collectGeoIPCountries(pol.PortRules)
	if len(geoSetsNeeded) > 0 {
		loaded, err := geo.LoadGeoIPCountries(cfg.GeoIPPath, geoSetsNeeded)
		if err != nil {
			return "", fmt.Errorf("enabled GeoIP port rule requires geoip.dat (%s): %w", cfg.GeoIPPath, err)
		}
		for _, cc := range geoSetsNeeded {
			nets := loaded[cc]
			if len(nets) == 0 {
				return "", fmt.Errorf("country code %q not found in %s", cc, cfg.GeoIPPath)
			}
			v4, v6 := splitCIDRStrings(nets)
			fmt.Fprintf(&b, "  set geo_%s_4 {\n    type ipv4_addr\n    flags interval\n    auto-merge\n", cc)
			if len(v4) > 0 {
				fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(v4, ", "))
			}
			b.WriteString("  }\n")
			fmt.Fprintf(&b, "  set geo_%s_6 {\n    type ipv6_addr\n    flags interval\n    auto-merge\n", cc)
			if len(v6) > 0 {
				fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(v6, ", "))
			}
			b.WriteString("  }\n")
		}
	}

	b.WriteString("\n  chain forward {\n")
	b.WriteString("    type filter hook forward priority filter + 10; policy accept;\n")
	// Only process traffic crossing the container bridge (never host traffic or intra-bridge hairpin)
	fmt.Fprintf(&b, "    iifname != %q oifname != %q accept\n", br, br)
	fmt.Fprintf(&b, "    iifname %q oifname %q accept\n", br, br)

	if pol.GlobalBypass {
		b.WriteString("    # global_bypass enabled: all rules bypassed\n")
		b.WriteString("  }\n}\n")
		return b.String(), nil
	}

	// 1. Dynamic tenant quarantine sets
	b.WriteString("    ip saddr @quarantine4 counter drop\n")
	b.WriteString("    ip daddr @quarantine4 counter drop\n")
	b.WriteString("    ip6 saddr @quarantine6 counter drop\n")
	b.WriteString("    ip6 daddr @quarantine6 counter drop\n")

	// 2. User-configured L4 Port & Access Rules (sorted by Priority descending, preserving order)
	sorted := make([]model.PortRule, 0, len(pol.PortRules))
	for _, r := range pol.PortRules {
		if r.Enabled {
			sorted = append(sorted, r)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})
	for _, r := range sorted {
		lines, err := renderPortRule(br, r)
		if err != nil {
			return "", err
		}
		for _, line := range lines {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}

	// 3. Per-tenant abuse rate/conntrack limits (outbound new connections / UDP PPS)
	if pol.Abuse.MaxConnsPerTenant > 0 {
		fmt.Fprintf(&b, "    iifname %q oifname != %q ct state new add @conn_limit4 { ip saddr ct count over %d } counter drop\n",
			br, br, pol.Abuse.MaxConnsPerTenant)
		fmt.Fprintf(&b, "    iifname %q oifname != %q ct state new add @conn_limit6 { ip6 saddr ct count over %d } counter drop\n",
			br, br, pol.Abuse.MaxConnsPerTenant)
	}
	if pol.Abuse.NewConnRatePerSec > 0 {
		fmt.Fprintf(&b, "    iifname %q oifname != %q ct state new add @conn_rate4 { ip saddr limit rate over %d/second } counter drop\n",
			br, br, pol.Abuse.NewConnRatePerSec)
		fmt.Fprintf(&b, "    iifname %q oifname != %q ct state new add @conn_rate6 { ip6 saddr limit rate over %d/second } counter drop\n",
			br, br, pol.Abuse.NewConnRatePerSec)
	}
	if pol.Abuse.UDPPPSLimitPerTenant > 0 {
		fmt.Fprintf(&b, "    iifname %q oifname != %q meta l4proto udp add @udp_pps4 { ip saddr limit rate over %d/second } counter drop\n",
			br, br, pol.Abuse.UDPPPSLimitPerTenant)
		fmt.Fprintf(&b, "    iifname %q oifname != %q meta l4proto udp add @udp_pps6 { ip6 saddr limit rate over %d/second } counter drop\n",
			br, br, pol.Abuse.UDPPPSLimitPerTenant)
	}

	// 4. Conntrack offload & L7 DPI NFQUEUE dispatch (4 queues encode flow & packet direction unambiguously)
	needTCP, needUDP := enabledDPIL4(pol)
	dpiEnabled := needTCP || needUDP
	l4BypassRule := l4SkipExpr(needTCP, needUDP)
	qInOrig := cfg.QueueBase
	qOutOrig := cfg.QueueBase + 1
	qOutReply := cfg.QueueBase + 2
	qInReply := cfg.QueueBase + 3
	if dpiEnabled {
		fmt.Fprintf(&b, "    ct mark %d counter accept\n", cfg.ConnMarkAccept)
		fmt.Fprintf(&b, "    ct mark %d counter drop\n", cfg.ConnMarkDrop)
		fmt.Fprintf(&b, "    %s\n", l4BypassRule)
		fmt.Fprintf(&b, "    oifname %q iifname != %q ct direction original counter queue num %d bypass\n", br, br, qInOrig)
		fmt.Fprintf(&b, "    iifname %q oifname != %q ct direction original counter queue num %d bypass\n", br, br, qOutOrig)
		fmt.Fprintf(&b, "    oifname %q iifname != %q ct direction reply counter queue num %d bypass\n", br, br, qOutReply)
		fmt.Fprintf(&b, "    iifname %q oifname != %q ct direction reply counter queue num %d bypass\n", br, br, qInReply)
	} else {
		b.WriteString("    # no L7 protocol detectors enabled: skip NFQUEUE\n")
	}
	b.WriteString("  }\n")

	// 5. Host userspace proxy compatibility (narwhal-agent / docker-proxy / Podman):
	//    When a host process terminates inbound ports and dials containers over `br`, packets cross
	//    `output` (oifname br, ct direction original) and `input` (iifname br, ct direction reply)
	//    instead of `forward`. Container-initiated host services (e.g. DNS 53) have original in
	//    `input` and reply in `output`, so they bypass both chains untouched.
	if !cfg.DisableHostProxy {
		b.WriteString("\n  chain output {\n")
		b.WriteString("    type filter hook output priority filter + 10; policy accept;\n")
		fmt.Fprintf(&b, "    oifname != %q accept\n", br)
		b.WriteString("    ct direction reply accept\n")
		b.WriteString("    ct direction original ip daddr @quarantine4 counter drop\n")
		b.WriteString("    ct direction original ip6 daddr @quarantine6 counter drop\n")
		for _, r := range sorted {
			for _, line := range renderOutputPortRule(br, r) {
				fmt.Fprintf(&b, "    %s\n", line)
			}
		}
		if dpiEnabled {
			fmt.Fprintf(&b, "    ct direction original ct mark %d counter accept\n", cfg.ConnMarkAccept)
			fmt.Fprintf(&b, "    ct direction original ct mark %d counter drop\n", cfg.ConnMarkDrop)
			fmt.Fprintf(&b, "    %s\n", l4BypassRule)
			fmt.Fprintf(&b, "    oifname %q ct direction original counter queue num %d bypass\n", br, qInOrig)
		} else {
			b.WriteString("    # no L7 protocol detectors enabled: skip NFQUEUE\n")
		}
		b.WriteString("  }\n")

		b.WriteString("\n  chain input {\n")
		b.WriteString("    type filter hook input priority filter + 10; policy accept;\n")
		fmt.Fprintf(&b, "    iifname != %q accept\n", br)
		b.WriteString("    ct direction original accept\n")
		b.WriteString("    ct direction reply ip saddr @quarantine4 counter drop\n")
		b.WriteString("    ct direction reply ip6 saddr @quarantine6 counter drop\n")
		if dpiEnabled {
			fmt.Fprintf(&b, "    ct direction reply ct mark %d counter accept\n", cfg.ConnMarkAccept)
			fmt.Fprintf(&b, "    ct direction reply ct mark %d counter drop\n", cfg.ConnMarkDrop)
			fmt.Fprintf(&b, "    %s\n", l4BypassRule)
			fmt.Fprintf(&b, "    iifname %q ct direction reply counter queue num %d bypass\n", br, qInReply)
		} else {
			b.WriteString("    # no L7 protocol detectors enabled: skip NFQUEUE\n")
		}
		b.WriteString("  }\n")
	}

	b.WriteString("}\n")
	return b.String(), nil
}

func enabledDPIL4(pol model.Policy) (needTCP, needUDP bool) {
	for _, pr := range pol.Protocols {
		if !pr.Enabled || pr.Action == model.ActionAllow {
			continue
		}
		switch pr.ID {
		case model.ProtoFETTCP, model.ProtoVLESSPlain, model.ProtoTLSUntrusted, model.ProtoAirportPanel,
			model.ProtoSOCKS, model.ProtoHTTPProxy, model.ProtoWebSocket,
			model.ProtoTLSSNI, model.ProtoTLSAnomaly, model.ProtoSSH, model.ProtoHTTPPlain:
			needTCP = true
		case model.ProtoFETUDP, model.ProtoUDPProxy, model.ProtoQUICSNI, model.ProtoWireGuard:
			needUDP = true
		case model.ProtoOpenVPN, model.ProtoDNS, model.ProtoMining, model.ProtoBitTorrent:
			needTCP = true
			needUDP = true
		default:
			needTCP = true
			needUDP = true
		}
	}
	return needTCP, needUDP
}

func l4SkipExpr(needTCP, needUDP bool) string {
	switch {
	case needTCP && needUDP:
		return "meta l4proto != { tcp, udp } accept"
	case needTCP:
		return "meta l4proto != tcp accept"
	default:
		return "meta l4proto != udp accept"
	}
}

func renderPortRule(br string, r model.PortRule) ([]string, error) {
	dirs := []model.Direction{r.Direction}
	if r.Direction == model.DirBoth {
		dirs = []model.Direction{model.DirInbound, model.DirOutbound}
	}

	l4Protos := []string{r.L4Proto}
	if r.L4Proto == "both" {
		l4Protos = []string{"tcp", "udp"}
	}

	verdict := "drop"
	if r.Action == model.ActionAllow {
		verdict = "accept"
	}

	var lines []string
	for _, dir := range dirs {
		for _, l4 := range l4Protos {
			var parts []string
			if dir == model.DirInbound {
				parts = append(parts, fmt.Sprintf("oifname %q iifname != %q ct direction original", br, br))
			} else {
				parts = append(parts, fmt.Sprintf("iifname %q oifname != %q ct direction original", br, br))
			}

			// Tenant IP filter
			if r.TenantIP != "" {
				fam := ipFamily(r.TenantIP)
				field := "saddr"
				if dir == model.DirInbound {
					field = "daddr"
				}
				parts = append(parts, fmt.Sprintf("%s %s %s", fam, field, r.TenantIP))
			}

			// L4 protocol & port match
			switch l4 {
			case "tcp", "udp":
				if r.PortStart > 0 && r.Scope == model.PortScopeHostMapped {
					portExpr := formatPortExpr(r.PortStart, r.PortEnd)
					parts = append(parts, fmt.Sprintf("ct original protocol %s ct original proto-dst %s", l4, portExpr))
				} else {
					parts = append(parts, fmt.Sprintf("meta l4proto %s", l4))
					if r.PortStart > 0 {
						portExpr := formatPortExpr(r.PortStart, r.PortEnd)
						switch r.Scope {
						case model.PortScopeSrc:
							parts = append(parts, fmt.Sprintf("%s sport %s", l4, portExpr))
						default:
							parts = append(parts, fmt.Sprintf("%s dport %s", l4, portExpr))
						}
					}
				}
			case "icmp":
				parts = append(parts, "meta l4proto { icmp, ipv6-icmp }")
			case "all":
				// no L4 restriction
			}

			// Peer filter (CIDR or GeoIP)
			switch r.PeerType {
			case "cidr":
				if r.PeerCIDR != "" {
					fam := ipFamily(r.PeerCIDR)
					field := "daddr"
					if dir == model.DirInbound {
						field = "saddr"
					}
					parts = append(parts, fmt.Sprintf("%s %s %s", fam, field, r.PeerCIDR))
				}
				parts = append(parts, "counter "+verdict)
				lines = append(lines, strings.Join(parts, " "))
			case "geoip":
				if len(r.GeoIPCodes) == 0 {
					continue
				}
				field := "daddr"
				if dir == model.DirInbound {
					field = "saddr"
				}
				for _, rawCC := range r.GeoIPCodes {
					cc := strings.ToUpper(strings.TrimSpace(rawCC))
					if cc == "" {
						continue
					}
					p4 := append(append([]string(nil), parts...), fmt.Sprintf("ip %s @geo_%s_4", field, cc), "counter "+verdict)
					p6 := append(append([]string(nil), parts...), fmt.Sprintf("ip6 %s @geo_%s_6", field, cc), "counter "+verdict)
					lines = append(lines, strings.Join(p4, " "), strings.Join(p6, " "))
				}
			default:
				parts = append(parts, "counter "+verdict)
				lines = append(lines, strings.Join(parts, " "))
			}
		}
	}
	return lines, nil
}

// renderOutputPortRule adapts inbound container-side L4 rules for host userspace proxy traffic
// traversing `hook output` toward `br`. Host-mapped port and external peer CIDR/GeoIP filters
// remain forward-only because userspace proxies terminate external sockets before dialing `br`.
func renderOutputPortRule(br string, r model.PortRule) []string {
	if r.Direction != model.DirInbound && r.Direction != model.DirBoth {
		return nil
	}
	if r.Scope == model.PortScopeHostMapped {
		return nil
	}
	if r.PeerType != "" && r.PeerType != "any" {
		return nil
	}

	l4Protos := []string{r.L4Proto}
	if r.L4Proto == "both" {
		l4Protos = []string{"tcp", "udp"}
	}
	verdict := "drop"
	if r.Action == model.ActionAllow {
		verdict = "accept"
	}

	var lines []string
	for _, l4 := range l4Protos {
		parts := []string{fmt.Sprintf("oifname %q ct direction original", br)}
		if r.TenantIP != "" {
			parts = append(parts, fmt.Sprintf("%s daddr %s", ipFamily(r.TenantIP), r.TenantIP))
		}
		switch l4 {
		case "tcp", "udp":
			parts = append(parts, fmt.Sprintf("meta l4proto %s", l4))
			if r.PortStart > 0 {
				portExpr := formatPortExpr(r.PortStart, r.PortEnd)
				if r.Scope == model.PortScopeSrc {
					parts = append(parts, fmt.Sprintf("%s sport %s", l4, portExpr))
				} else {
					parts = append(parts, fmt.Sprintf("%s dport %s", l4, portExpr))
				}
			}
		case "icmp":
			parts = append(parts, "meta l4proto { icmp, ipv6-icmp }")
		case "all":
		}
		parts = append(parts, "counter "+verdict)
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines
}

func formatPortExpr(start, end uint16) string {
	if end == 0 || end == start {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func ipFamily(ipOrCIDR string) string {
	s := ipOrCIDR
	if ip, _, err := net.ParseCIDR(s); err == nil {
		if ip.To4() != nil {
			return "ip"
		}
		return "ip6"
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return "ip"
		}
		return "ip6"
	}
	return "ip"
}

func collectGeoIPCountries(rules []model.PortRule) []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range rules {
		if !r.Enabled || r.PeerType != "geoip" {
			continue
		}
		for _, cc := range r.GeoIPCodes {
			cc = strings.ToUpper(strings.TrimSpace(cc))
			if cc != "" && !seen[cc] {
				seen[cc] = true
				out = append(out, cc)
			}
		}
	}
	sort.Strings(out)
	return out
}

func splitCIDRStrings(nets []*net.IPNet) (v4, v6 []string) {
	for _, n := range nets {
		if n.IP.To4() != nil {
			v4 = append(v4, n.String())
		} else {
			v6 = append(v6, n.String())
		}
	}
	return v4, v6
}
