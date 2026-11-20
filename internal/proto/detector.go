package proto

import (
	"net"
	"slices"
	"strings"

	"snapgfw/internal/geo"
	"snapgfw/internal/model"
)

// Direction aliases model.Direction.
type Direction = model.Direction

const (
	DirInbound  = model.DirInbound
	DirOutbound = model.DirOutbound
)

// FlowMeta describes a network 5-tuple and direction relative to the container bridge.
type FlowMeta struct {
	L4Proto   string // "tcp" | "udp"
	Direction Direction
	TenantIP  net.IP
	PeerIP    net.IP
	SrcPort   uint16 // Initiator source port
	DstPort   uint16 // Initiator destination / guest port
	HostPort  uint16 // Optional host mapped port from runman portforwards
}

// MatchResult describes a protocol detector finding.
type MatchResult struct {
	Matched  bool
	Protocol model.ProtocolID
	Action   model.Action
	Detail   string
}

// CompiledRule holds pre-compiled matchers for one ProtocolRule.
type CompiledRule struct {
	Rule          model.ProtocolRule
	DomainMatcher *geo.DomainPolicyMatcher
	ExceptTenants *geo.IPMatcher
	ExceptPorts   map[uint16]bool
}

// CompiledPolicy is an immutable snapshot used lock-free by packet workers.
type CompiledPolicy struct {
	GlobalBypass   bool
	TrustedTenants *geo.IPMatcher
	Rules          map[model.ProtocolID]*CompiledRule
	NeedTCP        bool
	NeedUDP        bool
	NeedTrojan     bool
	GeoFallback    bool
}

// CompilePolicy builds a fast, immutable evaluation snapshot from a Policy.
func CompilePolicy(p model.Policy, geositePath string) *CompiledPolicy {
	cp := &CompiledPolicy{
		GlobalBypass: p.GlobalBypass,
		Rules:        make(map[model.ProtocolID]*CompiledRule, len(p.Protocols)),
	}
	if len(p.TrustedTenants) > 0 {
		cp.TrustedTenants = parseIPListMatcher(p.TrustedTenants)
	}
	// Preload all needed GeoSite categories in a single pass and share identical read-only
	// DomainPolicyMatcher instances across rules (e.g. tls_sni & quic_sni both using "cn")
	// to roughly halve geosite memory usage.
	var preloadedGeo map[string][]geo.DomainEntry
	if geositePath != "" && !p.GlobalBypass {
		catSet := make(map[string]struct{})
		for _, pr := range p.Protocols {
			if !pr.Enabled {
				continue
			}
			for _, rawCat := range pr.GeoSiteCats {
				base, attr, _ := strings.Cut(strings.TrimSpace(rawCat), "@")
				if base != "" {
					upper := strings.ToUpper(base)
					catSet[upper] = struct{}{}
					if upper == "CN" && attr == "" {
						catSet["GEOLOCATION-!CN"] = struct{}{}
					}
				}
			}
		}
		if len(catSet) > 0 {
			wanted := make([]string, 0, len(catSet))
			for c := range catSet {
				wanted = append(wanted, c)
			}
			if m, err := geo.LoadGeoSiteCats(geositePath, wanted); err == nil {
				preloadedGeo = m
			}
		}
	}
	type matcherEntry struct {
		matcher  *geo.DomainPolicyMatcher
		fallback bool
	}
	matcherCache := make(map[string]matcherEntry)

	for _, pr := range p.Protocols {
		cr := &CompiledRule{
			Rule:        pr,
			ExceptPorts: make(map[uint16]bool, len(pr.ExceptPorts)),
		}
		for _, port := range pr.ExceptPorts {
			cr.ExceptPorts[port] = true
		}
		if len(pr.ExceptTenants) > 0 {
			cr.ExceptTenants = parseIPListMatcher(pr.ExceptTenants)
		}
		if pr.Enabled && !p.GlobalBypass {
			matchDomains := pr.MatchDomains
			if pr.ID == model.ProtoMining {
				matchDomains = slices.Concat(BuiltinMiningPoolDomains, pr.MatchDomains)
			}
			if len(pr.GeoSiteCats) > 0 || len(matchDomains) > 0 || len(pr.ExcludeDomains) > 0 {
				cacheKey := domainMatcherKey(pr.GeoSiteCats, matchDomains, pr.ExcludeDomains)
				if hit, ok := matcherCache[cacheKey]; ok {
					cr.DomainMatcher = hit.matcher
					if hit.fallback {
						cp.GeoFallback = true
					}
				} else {
					dm, fb := geo.BuildDomainPolicyMatcherWithCache(geositePath, pr.GeoSiteCats, matchDomains, pr.ExcludeDomains, preloadedGeo)
					matcherCache[cacheKey] = matcherEntry{matcher: dm, fallback: fb}
					cr.DomainMatcher = dm
					if fb {
						cp.GeoFallback = true
					}
				}
			}
		}
		cp.Rules[pr.ID] = cr
		if pr.Enabled && !p.GlobalBypass {
			switch pr.ID {
			case model.ProtoFETTCP, model.ProtoSOCKS, model.ProtoHTTPProxy, model.ProtoWebSocket,
				model.ProtoTLSSNI, model.ProtoTLSAnomaly, model.ProtoSSH, model.ProtoHTTPPlain:
				cp.NeedTCP = true
			case model.ProtoTrojan:
				cp.NeedTCP = true
				cp.NeedTrojan = true
			case model.ProtoFETUDP, model.ProtoUDPProxy, model.ProtoQUICSNI, model.ProtoWireGuard:
				cp.NeedUDP = true
			case model.ProtoOpenVPN, model.ProtoDNS, model.ProtoMining, model.ProtoBitTorrent:
				cp.NeedTCP = true
				cp.NeedUDP = true
			}
		}
	}
	return cp
}

// IsTrustedTenant returns true if tenantIP is in the global TrustedTenants whitelist.
func (cp *CompiledPolicy) IsTrustedTenant(tenantIP net.IP) bool {
	if cp == nil || cp.GlobalBypass {
		return true
	}
	return cp.TrustedTenants != nil && cp.TrustedTenants.Contains(tenantIP)
}

// ActiveRule returns the CompiledRule if enabled and applicable to the flow's direction/port/tenant.
func (cp *CompiledPolicy) ActiveRule(id model.ProtocolID, meta FlowMeta) (*CompiledRule, bool) {
	if cp == nil || cp.GlobalBypass {
		return nil, false
	}
	cr := cp.Rules[id]
	if cr == nil || !cr.Rule.Enabled {
		return nil, false
	}
	if cr.Rule.Direction != model.DirBoth && cr.Rule.Direction != meta.Direction {
		return nil, false
	}
	if len(cr.ExceptPorts) > 0 {
		if cr.ExceptPorts[meta.DstPort] || cr.ExceptPorts[meta.SrcPort] || (meta.HostPort > 0 && cr.ExceptPorts[meta.HostPort]) {
			return nil, false
		}
	}
	if cr.ExceptTenants != nil && cr.ExceptTenants.Contains(meta.TenantIP) {
		return nil, false
	}
	return cr, true
}

func parseIPListMatcher(items []string) *geo.IPMatcher {
	var nets []*net.IPNet
	for _, item := range items {
		if _, n, err := net.ParseCIDR(item); err == nil {
			nets = append(nets, n)
		} else if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
				bits = 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return geo.NewIPMatcher(nets)
}

func domainMatcherKey(cats, matchDomains, excludeDomains []string) string {
	norm := func(in []string) string {
		if len(in) == 0 {
			return ""
		}
		cp := make([]string, len(in))
		for i, v := range in {
			cp[i] = strings.ToLower(strings.TrimSpace(v))
		}
		slices.Sort(cp)
		return strings.Join(cp, ",")
	}
	return norm(cats) + "|" + norm(matchDomains) + "|" + norm(excludeDomains)
}
