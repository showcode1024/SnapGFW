package model

// PresetInfo describes a selectable one-click policy template in the panel.
type PresetInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Summary     string `json:"summary"`
	Recommended bool   `json:"recommended,omitempty"`
}

// ListPresets returns available built-in one-click strategy presets.
func ListPresets() []PresetInfo {
	return []PresetInfo{
		{
			ID:          "anti_blacklist",
			Name:        "防招黑模式（NAT VPS 推荐）",
			Summary:     "入站阻断 SS/SS-2022/VMess-TCP、SOCKS、HTTP 代理、高熵 WS、OpenVPN 及国内 SNI 伪装(TLS+QUIC)，出站封禁 SMTP 发信；放行海外正常 SNI 的 HTTPS / Reality 与正常业务。",
			Recommended: true,
		},
		{
			ID:      "strict_block",
			Name:    "严格全封代理模式（建站/纯业务）",
			Summary: "除常规建站 HTTPS/HTTP/SSH/DNS 外，拦截全部可识别代理与 VPN 协议（含 WireGuard、UDP 全加密、Trojan 启发式、ECH、BT/P2P）与非标准端口转发。",
		},
		{
			ID:      "audit_only",
			Name:    "纯审计观察模式（Dry-Run 零阻断）",
			Summary: "开启全部协议检测器但动作全部设为仅记录告警日志，不阻断任何流量，适合上线初期摸底租户行为。",
		},
		{
			ID:      "anti_abuse",
			Name:    "防滥用与版权加固模式",
			Summary: "在防招黑基础上增加：拦截 BitTorrent/DHT P2P、启用单实例并发连接限制、新建速率限制、UDP PPS 限速及多次违规自动临时隔离。",
		},
	}
}

// BaseProtocolCatalog returns the full protocol matrix with default metadata.
func BaseProtocolCatalog() []ProtocolRule {
	return []ProtocolRule{
		{
			ID:          ProtoFETTCP,
			Name:        "全加密 TCP 代理 (SS / SS-2022 / VMess-TCP)",
			Category:    "全加密代理",
			Description: "基于比特熵分布、可打印 ASCII 豁免与真实协议握手校验，阻断 Shadowsocks、SS-2022 TCP 及原生 VMess-TCP（已修复 fake prefix 绕过）。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
		},
		{
			ID:          ProtoFETUDP,
			Name:        "全加密 UDP 流量 (SS-UDP / SS-2022 UDP / VMess-UDP)",
			Category:    "全加密代理",
			Description: "排除 DNS / QUIC / WireGuard / OpenVPN / STUN / NTP 等已知合法 UDP 协议后，检测剩余高熵加密 UDP 载荷。",
			Warning:     "部分加密游戏联机、P2P 加速或私有 UDP 协议同样呈高熵特征，建议按需开启或配合白名单端口使用。",
			Enabled:     false,
			Action:      ActionLog,
			Direction:   DirInbound,
			Options:     RuleOpts{MinUDPPacketLen: 48},
		},
		{
			ID:          ProtoSOCKS,
			Name:        "明文 SOCKS4 / 4a / 5 代理",
			Category:    "明文代理",
			Description: "校验 SOCKS 版本、认证方法数与地址结构，精准识别明文 SOCKS 代理并避免二进制首字节误撞。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
		},
		{
			ID:          ProtoHTTPProxy,
			Name:        "明文 HTTP 代理 (CONNECT / 正向代理)",
			Category:    "明文代理",
			Description: "拦截明文 HTTP CONNECT 隧道代理及绝对 URL 正向 HTTP 代理。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
		},
		{
			ID:          ProtoWebSocket,
			Name:        "明文 HTTP WebSocket (VMess-WS / obfs)",
			Category:    "明文代理",
			Description: "支持全封、仅告警，或「两阶段高熵检测」（放行正常业务 WS，只阻断握手后发送高熵密文帧的 WS 隧道）。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
			WSMode:      WSModeTwoStageHighEn,
		},
		{
			ID:          ProtoTLSSNI,
			Name:        "TLS SNI 域名策略 (支持跨 Record 分片)",
			Category:    "SNI 与伪装",
			Description: "重组并解析多 TLS Record ClientHello 提取 SNI，匹配 GeoSite 分类（如 cn）及自定义黑/白名单域名。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
			GeoSiteCats: []string{"cn"},
		},
		{
			ID:          ProtoQUICSNI,
			Name:        "QUIC SNI 域名策略 (Hysteria2 / TUIC / HTTP3)",
			Category:    "SNI 与伪装",
			Description: "实现 RFC 9001 QUIC v1/v2 Initial 包解密及 CRYPTO 帧重组提取 SNI，匹配 GeoSite 与自定义域名。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
			GeoSiteCats: []string{"cn"},
		},
		{
			ID:          ProtoTLSAnomaly,
			Name:        "TLS 异常与伪装特征 (Fake Obfs / ECH / 无 SNI)",
			Category:    "SNI 与伪装",
			Description: "捕获伪造 TLS/HTTP 首包头的混淆流量（如 simple-obfs），并可选识别 ECH 或无 SNI 的纯 IP TLS 连接。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
			Options:     RuleOpts{BlockFakeObfs: true, BlockECH: false, BlockNoSNI: false},
		},
		{
			ID:          ProtoOpenVPN,
			Name:        "OpenVPN (TCP / UDP)",
			Category:    "VPN 协议",
			Description: "校验双向 HardReset 与 8 字节 Session ID 回显，精确拦截裸 OpenVPN 且不会误伤正常 DNS 解析。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
		},
		{
			ID:          ProtoWireGuard,
			Name:        "WireGuard (UDP)",
			Category:    "VPN 协议",
			Description: "识别容器实例内部建立的 WireGuard 握手与数据包（宿主机 runman-agent 的 rw* 独立 IP 隧道不受影响）。",
			Enabled:     true,
			Action:      ActionLog,
			Direction:   DirBoth,
		},
		{
			ID:          ProtoTrojan,
			Name:        "Trojan 启发式特征 (TLS-in-TLS 包长序列)",
			Category:    "启发式检测",
			Description: "基于 TLS 握手后前 4 段密文交互长度进行启发式判断。",
			Warning:     "正常 HTTPS 与合规 Reality 存在约 1% 误杀率，强烈建议保持「仅告警」作为风险参考，不直接阻断。",
			Enabled:     true,
			Action:      ActionLog,
			Direction:   DirInbound,
		},
		{
			ID:          ProtoSSH,
			Name:        "SSH 协议识别 (SSH-2.0)",
			Category:    "业务与审计",
			Description: "识别 SSH 握手。可用于审计或封禁非标准端口上的 SSH 隧道转发。",
			Enabled:     false,
			Action:      ActionLog,
			Direction:   DirBoth,
			Options:     RuleOpts{AllowStdSSHPort: true},
		},
		{
			ID:          ProtoHTTPPlain,
			Name:        "明文 HTTP 请求审计 / 域名控制",
			Category:    "业务与审计",
			Description: "解析明文 HTTP Host，可配合 GeoSite 或自定义域名拦截违规明文站点访问。",
			Enabled:     false,
			Action:      ActionLog,
			Direction:   DirBoth,
		},
		{
			ID:          ProtoDNS,
			Name:        "DNS 查询审计 / 超大 DNS 隧道检测",
			Category:    "业务与审计",
			Description: "解析 UDP/TCP DNS 请求域名，支持按域名黑名单阻断解析，或检测超大载荷 DNS 隧道。",
			Enabled:     false,
			Action:      ActionLog,
			Direction:   DirOutbound,
			Options:     RuleOpts{MaxDNSPayload: 512},
		},
		{
			ID:          ProtoBitTorrent,
			Name:        "BitTorrent / DHT P2P 特征",
			Category:    "版权与滥用",
			Description: "检测 TCP BitTorrent 握手与 UDP DHT bencode 节点报文，防止 BT 下载引发版权 DMCA 投诉。",
			Enabled:     false,
			Action:      ActionBlock,
			Direction:   DirBoth,
		},
	}
}

// BuildPreset builds a complete Policy from a named preset template.
func BuildPreset(presetID string) Policy {
	protos := BaseProtocolCatalog()
	setProto := func(id ProtocolID, enabled bool, action Action, dir Direction, fn func(*ProtocolRule)) {
		for i := range protos {
			if protos[i].ID == id {
				protos[i].Enabled = enabled
				protos[i].Action = action
				protos[i].Direction = dir
				if fn != nil {
					fn(&protos[i])
				}
				return
			}
		}
	}

	smtpRule := PortRule{
		ID:        "preset-block-smtp-out",
		Name:      "禁止出站 SMTP 发信 (防垃圾邮件)",
		Enabled:   true,
		Priority:  100,
		Direction: DirOutbound,
		Scope:     PortScopeDst,
		L4Proto:   "tcp",
		PortStart: 25,
		PortEnd:   25,
		PeerType:  "any",
		Action:    ActionBlock,
		Comment:   "25 端口高危发信",
	}
	smtpsRules := []PortRule{
		smtpRule,
		{
			ID:        "preset-block-smtps-465",
			Name:      "禁止出站 SMTPS 465",
			Enabled:   true,
			Priority:  100,
			Direction: DirOutbound,
			Scope:     PortScopeDst,
			L4Proto:   "tcp",
			PortStart: 465,
			PortEnd:   465,
			PeerType:  "any",
			Action:    ActionBlock,
		},
		{
			ID:        "preset-block-submission-587",
			Name:      "禁止出站 Submission 587",
			Enabled:   true,
			Priority:  100,
			Direction: DirOutbound,
			Scope:     PortScopeDst,
			L4Proto:   "tcp",
			PortStart: 587,
			PortEnd:   587,
			PeerType:  "any",
			Action:    ActionBlock,
		},
	}

	switch presetID {
	case "strict_block":
		for i := range protos {
			switch protos[i].ID {
			case ProtoSSH, ProtoHTTPPlain, ProtoDNS:
				protos[i].Enabled = false
			case ProtoTLSAnomaly:
				protos[i].Enabled = true
				protos[i].Action = ActionBlock
				protos[i].Direction = DirBoth
				protos[i].Options = RuleOpts{BlockFakeObfs: true, BlockECH: true, BlockNoSNI: true}
			default:
				protos[i].Enabled = true
				protos[i].Action = ActionBlock
				protos[i].Direction = DirBoth
				if protos[i].ID == ProtoWebSocket {
					protos[i].WSMode = WSModeBlockAll
				}
			}
		}
		return Policy{
			Version:      1,
			ActivePreset: "strict_block",
			Protocols:    protos,
			PortRules:    smtpsRules,
			Abuse: AbuseConfig{
				MaxConnsPerTenant:     2048,
				NewConnRatePerSec:     200,
				UDPPPSLimitPerTenant:  3000,
				AutoQuarantineEnabled: true,
				QuarantineThreshold:   8,
				QuarantineWindowSec:   300,
				QuarantineDurationSec: 900,
				FlushConntrackOnBlock: true,
			},
			Notify: NotifyConfig{AlertOnBan: true, MinIntervalSec: 60},
		}

	case "audit_only":
		for i := range protos {
			protos[i].Enabled = true
			protos[i].Action = ActionLog
			if protos[i].ID == ProtoWebSocket {
				protos[i].WSMode = WSModeLogOnly
			}
		}
		return Policy{
			Version:      1,
			ActivePreset: "audit_only",
			Protocols:    protos,
			PortRules:    nil,
			Abuse: AbuseConfig{
				AutoQuarantineEnabled: false,
				QuarantineThreshold:   10,
				QuarantineWindowSec:   300,
				QuarantineDurationSec: 600,
			},
			Notify: NotifyConfig{MinIntervalSec: 60},
		}

	case "anti_abuse":
		setProto(ProtoBitTorrent, true, ActionBlock, DirBoth, nil)
		setProto(ProtoWireGuard, true, ActionBlock, DirBoth, nil)
		return Policy{
			Version:      1,
			ActivePreset: "anti_abuse",
			Protocols:    protos,
			PortRules:    smtpsRules,
			Abuse: AbuseConfig{
				MaxConnsPerTenant:     3000,
				NewConnRatePerSec:     250,
				UDPPPSLimitPerTenant:  4000,
				AutoQuarantineEnabled: true,
				QuarantineThreshold:   6,
				QuarantineWindowSec:   300,
				QuarantineDurationSec: 900,
				FlushConntrackOnBlock: true,
			},
			Notify: NotifyConfig{AlertOnBan: true, MinIntervalSec: 60},
		}

	default: // "anti_blacklist"
		return Policy{
			Version:      1,
			ActivePreset: "anti_blacklist",
			Protocols:    protos,
			PortRules:    smtpsRules,
			Abuse: AbuseConfig{
				MaxConnsPerTenant:     4096,
				NewConnRatePerSec:     300,
				UDPPPSLimitPerTenant:  5000,
				AutoQuarantineEnabled: false,
				QuarantineThreshold:   10,
				QuarantineWindowSec:   300,
				QuarantineDurationSec: 600,
				FlushConntrackOnBlock: true,
			},
			Notify: NotifyConfig{AlertOnBan: true, MinIntervalSec: 60},
		}
	}
}
