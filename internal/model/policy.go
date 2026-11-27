package model

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Action defines what happens when a rule matches.
type Action string

const (
	ActionAllow Action = "allow"
	ActionLog   Action = "log"
	ActionBlock Action = "block"
)

// Direction defines traffic initiation direction relative to the LXC/container bridge.
type Direction string

const (
	DirInbound  Direction = "in"   // External -> Container (tenant server)
	DirOutbound Direction = "out"  // Container -> External (tenant client)
	DirBoth     Direction = "both" // Either initiation direction
)

// WSMode controls how plaintext HTTP WebSocket connections are inspected.
type WSMode string

const (
	WSModeLogOnly        WSMode = "log_only"        // Only log WS upgrades
	WSModeTwoStageHighEn WSMode = "two_stage_high"  // Allow handshake, block if post-upgrade payload is high-entropy
	WSModeBlockAll       WSMode = "block_all"       // Block all plaintext HTTP WebSocket upgrades
)

// ProtocolID enumerates every L7 protocol/heuristic detector in the engine.
type ProtocolID string

const (
	ProtoFETTCP       ProtocolID = "fet_tcp"       // Shadowsocks / SS-2022 TCP / native VMess-TCP
	ProtoFETUDP       ProtocolID = "fet_udp"       // SS-UDP / SS-2022 UDP / VMess-UDP (with FP warning)
	ProtoUDPProxy     ProtocolID = "udp_proxy"     // QUIC / Hysteria2 / TUIC & inbound UDP proxy blocker
	ProtoVLESSPlain   ProtocolID = "vless_plain"   // Raw non-TLS VLESS TCP & plaintext VLESS-WS
	ProtoTLSUntrusted ProtocolID = "tls_untrusted" // Self-signed / untrusted CA / SNI-mismatched TLS (non-REALITY Trojan/VLESS/AnyTLS)
	ProtoAirportPanel ProtocolID = "airport_panel" // Commercial airport panels & backend APIs (V2Board / Xboard / SSPanel / PPanel)
	ProtoSOCKS        ProtocolID = "socks"         // SOCKS4 / 4a / 5
	ProtoHTTPProxy    ProtocolID = "http_proxy"    // HTTP CONNECT & absolute-URI forward proxy
	ProtoWebSocket    ProtocolID = "websocket"     // Plaintext WebSocket / two-stage high-entropy WS
	ProtoTLSSNI       ProtocolID = "tls_sni"       // TLS SNI domain filter (supports multi-record)
	ProtoQUICSNI      ProtocolID = "quic_sni"      // QUIC v1/v2 Initial decrypted SNI filter
	ProtoTLSAnomaly   ProtocolID = "tls_anomaly"   // ECH, fake TLS/HTTP obfs, or SNI-less TLS
	ProtoOpenVPN      ProtocolID = "openvpn"       // OpenVPN TCP/UDP with Session ID echo verification
	ProtoWireGuard    ProtocolID = "wireguard"     // WireGuard UDP inside container traffic
	ProtoTrojan       ProtocolID = "trojan"        // Trojan TLS-in-TLS length heuristic (~1% FP)
	ProtoSSH          ProtocolID = "ssh"           // SSH-2.0 banner
	ProtoHTTPPlain    ProtocolID = "http_plain"    // Plaintext HTTP host/method inspection
	ProtoDNS          ProtocolID = "dns"           // DNS domain & oversized DNS tunnel inspection
	ProtoMining       ProtocolID = "mining"        // Stratum mining TCP JSON-RPC & known mining pool SNI/DNS
	ProtoBitTorrent   ProtocolID = "bittorrent"    // BitTorrent TCP handshake & UDP DHT
)

// AllProtocolIDs defines canonical panel display order.
var AllProtocolIDs = []ProtocolID{
	ProtoFETTCP,
	ProtoFETUDP,
	ProtoUDPProxy,
	ProtoVLESSPlain,
	ProtoTLSUntrusted,
	ProtoAirportPanel,
	ProtoSOCKS,
	ProtoHTTPProxy,
	ProtoWebSocket,
	ProtoTLSSNI,
	ProtoQUICSNI,
	ProtoTLSAnomaly,
	ProtoOpenVPN,
	ProtoWireGuard,
	ProtoTrojan,
	ProtoSSH,
	ProtoHTTPPlain,
	ProtoDNS,
	ProtoMining,
	ProtoBitTorrent,
}

// ProtocolRule controls one L7 protocol detector independently.
type ProtocolRule struct {
	ID             ProtocolID `json:"id"`
	Name           string     `json:"name"`
	Category       string     `json:"category"`
	Description    string     `json:"description"`
	Warning        string     `json:"warning,omitempty"`
	Enabled        bool       `json:"enabled"`
	Action         Action     `json:"action"`                    // allow | log | block
	Direction      Direction  `json:"direction"`                 // in | out | both
	WSMode         WSMode     `json:"ws_mode,omitempty"`         // Only for ProtoWebSocket
	GeoSiteCats    []string   `json:"geosite_cats,omitempty"`    // e.g. ["cn"] for SNI/DNS/HTTP host
	MatchDomains   []string   `json:"match_domains,omitempty"`   // Additional blocked/logged domains
	ExcludeDomains []string   `json:"exclude_domains,omitempty"` // Domains exempted from match
	ExceptPorts    []uint16   `json:"except_ports,omitempty"`    // Ports skipped for this rule
	ExceptTenants  []string   `json:"except_tenants,omitempty"`  // Tenant IPs/CIDRs skipped
	Options        RuleOpts   `json:"options,omitempty"`
}

// RuleOpts holds protocol-specific fine-tuning parameters.
type RuleOpts struct {
	BlockECH        bool `json:"block_ech,omitempty"`        // tls_anomaly: flag/block ECH
	BlockNoSNI      bool `json:"block_no_sni,omitempty"`     // tls_anomaly: flag/block TLS without SNI
	BlockFakeObfs   bool `json:"block_fake_obfs,omitempty"`  // tls_anomaly: flag/block malformed TLS/HTTP obfs prefixes
	MinUDPPacketLen int  `json:"min_udp_len,omitempty"`      // fet_udp: ignore tiny keepalives below this byte length
	BlockAllUDP     bool `json:"block_all_udp,omitempty"`    // udp_proxy: block all non-DNS/NTP UDP on matched direction
	MaxDNSPayload   int  `json:"max_dns_payload,omitempty"`  // dns: flag DNS queries larger than N bytes (tunneling)
	AllowStdSSHPort bool `json:"allow_std_ssh_port,omitempty"` // ssh: exempt port 22 if enabled
}

// PortScope specifies which port is matched on NAT forwarded packets.
type PortScope string

const (
	PortScopeDst        PortScope = "dst"         // Packet destination port (for outbound: external port; for inbound: guest port)
	PortScopeSrc        PortScope = "src"         // Packet source port
	PortScopeHostMapped PortScope = "host_mapped" // Conntrack original dst port (host public port before DNAT)
)

// PortRule defines an L3/L4 nftables rule compiled directly into kernel nftables.
type PortRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"` // Higher runs earlier; ties preserve order
	Direction   Direction `json:"direction"` // in | out | both
	Scope       PortScope `json:"scope"`     // dst | src | host_mapped
	L4Proto     string    `json:"l4_proto"`  // tcp | udp | both | icmp | all
	PortStart   uint16    `json:"port_start"`
	PortEnd     uint16    `json:"port_end"` // 0 or == PortStart means single port; both 0 means all ports
	TenantIP    string    `json:"tenant_ip,omitempty"`    // Empty = global; CIDR or single IP (v4/v6)
	PeerType    string    `json:"peer_type,omitempty"`    // any | cidr | geoip
	PeerCIDR    string    `json:"peer_cidr,omitempty"`    // Peer IP/CIDR when peer_type == "cidr"
	GeoIPCodes  []string  `json:"geoip_codes,omitempty"`  // Country codes when peer_type == "geoip"
	Action      Action    `json:"action"`                 // block | allow
	Comment     string    `json:"comment,omitempty"`
}

// AbuseConfig configures per-tenant connection limits, PPS limits, and auto-quarantine.
type AbuseConfig struct {
	MaxConnsPerTenant      int  `json:"max_conns_per_tenant"`       // 0 = disabled; nft ct count limit per tenant IP
	NewConnRatePerSec      int  `json:"new_conn_rate_per_sec"`      // 0 = disabled; new connection rate per tenant IP
	UDPPPSLimitPerTenant   int  `json:"udp_pps_limit_per_tenant"`   // 0 = disabled; UDP packet rate limit per tenant IP
	AutoQuarantineEnabled  bool `json:"auto_quarantine_enabled"`    // Auto-ban tenant IP temporarily after repeated L7 hits
	QuarantineThreshold    int  `json:"quarantine_threshold"`       // Hits within window to trigger quarantine
	QuarantineWindowSec    int  `json:"quarantine_window_sec"`      // Sliding window in seconds
	QuarantineDurationSec  int  `json:"quarantine_duration_sec"`    // Quarantine duration in seconds
	FlushConntrackOnBlock  bool `json:"flush_conntrack_on_block"`   // Run conntrack -D for newly blocked ports/quarantined IPs
}

// NotifyConfig configures optional Telegram/Webhook alerting.
type NotifyConfig struct {
	WebhookURL     string `json:"webhook_url,omitempty"`
	TelegramToken  string `json:"telegram_token,omitempty"`
	TelegramChatID string `json:"telegram_chat_id,omitempty"`
	AlertOnBlock   bool   `json:"alert_on_block"`
	AlertOnBan     bool   `json:"alert_on_ban"`
	MinIntervalSec int    `json:"min_interval_sec"` // Per-tenant alert cooldown
}

// Policy is the single hot-reloadable ruleset managed by the panel and CLI.
type Policy struct {
	Version        int            `json:"version"`
	ActivePreset   string         `json:"active_preset"`
	GlobalBypass   bool           `json:"global_bypass"` // Emergency maintenance mode: bypass all DPI & L4 blocks
	TrustedTenants []string       `json:"trusted_tenants,omitempty"` // Tenant IPs/CIDRs exempted from DPI
	Protocols      []ProtocolRule `json:"protocols"`
	PortRules      []PortRule     `json:"port_rules"`
	Abuse          AbuseConfig    `json:"abuse"`
	Notify         NotifyConfig   `json:"notify"`
}

// Validate checks policy integrity before saving or applying.
func (p *Policy) Validate() error {
	if p == nil {
		return errors.New("policy is nil")
	}
	for _, t := range p.TrustedTenants {
		if err := validateIPOrCIDR(t); err != nil {
			return fmt.Errorf("invalid trusted_tenant %q: %w", t, err)
		}
	}
	seenProto := make(map[ProtocolID]bool)
	for i := range p.Protocols {
		pr := &p.Protocols[i]
		if pr.ID == "" {
			return fmt.Errorf("protocol rule %d missing id", i)
		}
		if seenProto[pr.ID] {
			return fmt.Errorf("duplicate protocol id %q", pr.ID)
		}
		seenProto[pr.ID] = true
		switch pr.Action {
		case ActionAllow, ActionLog, ActionBlock:
		default:
			return fmt.Errorf("protocol %q invalid action %q", pr.ID, pr.Action)
		}
		switch pr.Direction {
		case DirInbound, DirOutbound, DirBoth:
		default:
			return fmt.Errorf("protocol %q invalid direction %q", pr.ID, pr.Direction)
		}
		for _, t := range pr.ExceptTenants {
			if err := validateIPOrCIDR(t); err != nil {
				return fmt.Errorf("protocol %q invalid except_tenant %q: %w", pr.ID, t, err)
			}
		}
	}
	for i := range p.PortRules {
		r := &p.PortRules[i]
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("port rule %d missing id", i)
		}
		if r.PortEnd > 0 && r.PortStart > 0 && r.PortEnd < r.PortStart {
			return fmt.Errorf("port rule %q port_end < port_start", r.Name)
		}
		switch r.Direction {
		case DirInbound, DirOutbound, DirBoth:
		default:
			return fmt.Errorf("port rule %q invalid direction %q", r.Name, r.Direction)
		}
		switch r.Scope {
		case "", PortScopeDst, PortScopeSrc, PortScopeHostMapped:
			if r.Scope == "" {
				r.Scope = PortScopeDst
			}
		default:
			return fmt.Errorf("port rule %q invalid scope %q", r.Name, r.Scope)
		}
		switch strings.ToLower(r.L4Proto) {
		case "tcp", "udp", "both", "icmp", "all":
			r.L4Proto = strings.ToLower(r.L4Proto)
		default:
			return fmt.Errorf("port rule %q invalid l4_proto %q", r.Name, r.L4Proto)
		}
		switch r.Action {
		case ActionAllow, ActionBlock:
		default:
			return fmt.Errorf("port rule %q invalid action %q (only allow/block supported in L4)", r.Name, r.Action)
		}
		if r.TenantIP != "" {
			if err := validateIPOrCIDR(r.TenantIP); err != nil {
				return fmt.Errorf("port rule %q invalid tenant_ip %q: %w", r.Name, r.TenantIP, err)
			}
		}
		if r.PeerType == "cidr" && r.PeerCIDR != "" {
			if err := validateIPOrCIDR(r.PeerCIDR); err != nil {
				return fmt.Errorf("port rule %q invalid peer_cidr %q: %w", r.Name, r.PeerCIDR, err)
			}
		}
	}
	return nil
}

func validateIPOrCIDR(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("empty address")
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err
	}
	if net.ParseIP(s) == nil {
		return errors.New("not a valid IP or CIDR")
	}
	return nil
}

// ProtocolRuleMap returns a quick lookup map by ProtocolID.
func (p *Policy) ProtocolRuleMap() map[ProtocolID]ProtocolRule {
	m := make(map[ProtocolID]ProtocolRule, len(p.Protocols))
	for _, r := range p.Protocols {
		m[r.ID] = r
	}
	return m
}
