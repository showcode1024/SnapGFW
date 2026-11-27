package model

import "fmt"

// PresetInfo describes a selectable policy template available for optional import.
type PresetInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Summary     string `json:"summary"`
	Recommended bool   `json:"recommended,omitempty"`
}

// ListPresets returns the unified recommended template available for one-click import.
func ListPresets() []PresetInfo {
	return []PresetInfo{
		{
			ID:          "anti_abuse",
			Name:        "防滥用",
			Summary:     "合集防招黑与防滥用：拦截 SS/SS-2022/VMess、SOCKS、HTTP 代理、高熵 WS、OpenVPN、国内 SNI 伪装、Stratum 挖矿/矿池、BT/P2P，出站封禁 SMTP 发信与常见矿池端口并启用连接限速；导入后可自由编辑。",
			Recommended: true,
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
			ID:          ProtoUDPProxy,
			Name:        "Hy2 / TUIC / UDP 代理拦截",
			Category:    "全加密代理",
			Description: "阻断入站 QUIC (Hysteria2 / TUIC / HTTP3)、Salamander 混淆及非标准入站 UDP 代理，自动豁免 DNS 与 NTP；不影响容器出站访问与正常 TCP HTTPS 建站。",
			Warning:     "如容器需要对外提供游戏服、WebRTC 或自定义 UDP 服务，可关闭「拦截全部非标准 UDP」或配置排除端口。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
			Options:     RuleOpts{BlockAllUDP: true},
		},
		{
			ID:          ProtoVLESSPlain,
			Name:        "裸 VLESS / 明文 VLESS-WS (非 REALITY)",
			Category:    "全加密代理",
			Description: "被动解析无 TLS 的裸 VLESS TCP 协议头及明文 WebSocket 内的 VLESS 帧，零延迟拦截且完全不影响 VLESS+REALITY / AnyTLS+REALITY。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
		},
		{
			ID:          ProtoTLSUntrusted,
			Name:        "自签/无效证书 TLS (非 REALITY Trojan/VLESS/AnyTLS)",
			Category:    "SNI 与伪装",
			Description: "结合 TLS 1.2 被动证书校验与宿主机异步 TLS 证书探测（策略 A），拦截自签证书、不可信 CA、过期或与 SNI 不匹配的入站 TLS 代理（如自签 Trojan / VLESS+TLS / AnyTLS）；REALITY 会透明转发探测至目标官网返回真证书，因此零误杀 VLESS+REALITY 与 AnyTLS+REALITY。",
			Warning:     "仅拦截无效/自签证书，探测超时或失败时默认放行。如容器使用自签证书或 Cloudflare Origin 源站证书建站，请将该端口或租户加入排除列表。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
		},
		{
			ID:          ProtoAirportPanel,
			Name:        "机场面板与对接 (V2Board / Xboard / SSPanel / PPanel)",
			Category:    "版权与滥用",
			Description: "识别并阻断商业机场面板（V2Board / Xboard / SSPanel / PPanel）的明文管理、订阅及节点对接路径（UniProxy / mod_mu 等），并对直连暴露的入站 HTTPS 端口异步探测首页机场指纹；严格放行 3x-ui / x-ui / s-ui 等个人节点面板与 REALITY 流量。",
			Warning:     "HTTPS 首页指纹探测仅对直连暴露端口有效；若机场面板前置 Cloudflare 且限制仅 CF 回源，网络层无法探测其加密页面。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirBoth,
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
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirInbound,
			GeoSiteCats: []string{"cn"},
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
			ID:          ProtoMining,
			Name:        "挖矿协议 / 矿池 (Stratum / Pool)",
			Category:    "算力与滥用",
			Description: "识别明文 Stratum TCP 挖矿协议 (mining.subscribe/authorize/XMRig login) 及常见 TLS/DNS 矿池连接。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirOutbound,
		},
		{
			ID:          ProtoBitTorrent,
			Name:        "BitTorrent / DHT P2P 特征",
			Category:    "版权与滥用",
			Description: "检测 TCP BitTorrent 握手与 UDP DHT bencode 节点报文，防止 BT 下载引发版权 DMCA 投诉。",
			Enabled:     true,
			Action:      ActionBlock,
			Direction:   DirBoth,
		},
	}
}

// DefaultPolicy returns a clean baseline policy with zero active blocks or limits.
func DefaultPolicy() Policy {
	protos := BaseProtocolCatalog()
	for i := range protos {
		protos[i].Enabled = false
	}
	return Policy{
		Version:      1,
		ActivePreset: "custom",
		Protocols:    protos,
		Abuse: AbuseConfig{
			QuarantineThreshold:   10,
			QuarantineWindowSec:   300,
			QuarantineDurationSec: 600,
			FlushConntrackOnBlock: true,
		},
		Notify: NotifyConfig{MinIntervalSec: 60},
	}
}

// LookupPreset builds an editable Policy from the supported "anti_abuse" template.
func LookupPreset(presetID string) (Policy, error) {
	if presetID != "anti_abuse" {
		return Policy{}, fmt.Errorf("unknown preset %q (available: anti_abuse)", presetID)
	}
	protos := BaseProtocolCatalog()
	defaultPortRules := []PortRule{
		{
			ID:        "preset-block-smtp-out",
			Name:      "禁止出站 SMTP 25",
			Enabled:   true,
			Priority:  100,
			Direction: DirOutbound,
			Scope:     PortScopeDst,
			L4Proto:   "tcp",
			PortStart: 25,
			PortEnd:   25,
			PeerType:  "any",
			Action:    ActionBlock,
		},
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
		{
			ID:        "preset-block-pool-3333",
			Name:      "禁止矿池常见端口 3333",
			Enabled:   true,
			Priority:  95,
			Direction: DirOutbound,
			Scope:     PortScopeDst,
			L4Proto:   "tcp",
			PortStart: 3333,
			PortEnd:   3333,
			PeerType:  "any",
			Action:    ActionBlock,
		},
		{
			ID:        "preset-block-pool-14444",
			Name:      "禁止矿池常见端口 14444",
			Enabled:   true,
			Priority:  95,
			Direction: DirOutbound,
			Scope:     PortScopeDst,
			L4Proto:   "tcp",
			PortStart: 14444,
			PortEnd:   14444,
			PeerType:  "any",
			Action:    ActionBlock,
		},
	}
	return Policy{
		Version:      1,
		ActivePreset: "anti_abuse",
		Protocols:    protos,
		PortRules:    defaultPortRules,
		Abuse: AbuseConfig{
			MaxConnsPerTenant:     1800,
			NewConnRatePerSec:     300,
			UDPPPSLimitPerTenant:  3000,
			AutoQuarantineEnabled: false,
			QuarantineThreshold:   10,
			QuarantineWindowSec:   300,
			QuarantineDurationSec: 600,
			FlushConntrackOnBlock: true,
		},
		Notify: NotifyConfig{AlertOnBan: true, MinIntervalSec: 60},
	}, nil
}

// BuildPreset builds the unified anti_abuse policy.
func BuildPreset(presetID string) Policy {
	pol, err := LookupPreset(presetID)
	if err != nil {
		return DefaultPolicy()
	}
	return pol
}
