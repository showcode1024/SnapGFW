package proto

import (
	"encoding/binary"
	"fmt"

	"snapgfw/internal/model"
)

// Decision is the stream-level verdict emitted by an evaluator session.
type Decision int

const (
	DecisionContinue Decision = iota // Keep inspecting subsequent packets
	DecisionAllow                    // Offload stream in kernel (ACCEPT_MARK)
	DecisionBlock                    // Block stream in kernel (DROP_MARK)
)

// EvalOutcome combines the stream Decision with zero or more audit matches.
type EvalOutcome struct {
	Decision Decision
	Events   []MatchResult
}

// TCPSession holds bounded per-stream protocol state for one pending TCP connection.
type TCPSession struct {
	meta          FlowMeta
	cp            *CompiledPolicy
	maxPrefix     int
	clientBuf     []byte
	serverBuf     []byte
	done          bool
	tlsDone       bool
	httpDone      bool
	wsInspecting  bool
	wsOffset      int
	ovpn          OpenVPNTracker
	trojan        TrojanTracker
	trojanActive  bool
}

// NewTCPSession creates a bounded TCP protocol evaluation session.
func NewTCPSession(meta FlowMeta, cp *CompiledPolicy, maxPrefix int) *TCPSession {
	if maxPrefix <= 0 {
		maxPrefix = 16384
	}
	_, trojanActive := cp.ActiveRule(modelProtoTrojan, meta)
	return &TCPSession{
		meta:         meta,
		cp:           cp,
		maxPrefix:    maxPrefix,
		trojanActive: trojanActive,
	}
}

const modelProtoTrojan = "trojan"

// Feed processes a contiguous TCP payload chunk in either direction (`rev == true` is server->client).
func (s *TCPSession) Feed(rev bool, data []byte) EvalOutcome {
	if s.done || s.cp == nil || s.cp.GlobalBypass || !s.cp.NeedTCP || s.cp.IsTrustedTenant(s.meta.TenantIP) {
		s.done = true
		return EvalOutcome{Decision: DecisionAllow}
	}
	if len(data) == 0 {
		return EvalOutcome{Decision: DecisionContinue}
	}

	if rev {
		if len(s.serverBuf) < 8192 {
			rem := 8192 - len(s.serverBuf)
			s.serverBuf = append(s.serverBuf, data[:min(len(data), rem)]...)
		}
	} else {
		if len(s.clientBuf) < s.maxPrefix {
			rem := s.maxPrefix - len(s.clientBuf)
			s.clientBuf = append(s.clientBuf, data[:min(len(data), rem)]...)
		}
	}

	// If we are in post-TLS Trojan flight-length tracking mode, feed chunk directly.
	if s.tlsDone && s.trojanActive {
		matched, tDone := s.trojan.Feed(rev, data)
		if matched {
			if cr, ok := s.cp.ActiveRule("trojan", s.meta); ok {
				ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: "tls-in-tls seq"}
				s.done = true
				if cr.Rule.Action == "block" {
					return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
				}
				return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
			}
		}
		if tDone || len(s.clientBuf)+len(s.serverBuf) >= s.maxPrefix*2 {
			s.done = true
			return EvalOutcome{Decision: DecisionAllow}
		}
		return EvalOutcome{Decision: DecisionContinue}
	}

	// If in two-stage WebSocket payload inspection mode, unmask client WS frames and inspect entropy.
	if s.wsInspecting {
		if rev {
			return EvalOutcome{Decision: DecisionContinue}
		}
		wsTail := s.clientBuf[min(s.wsOffset, len(s.clientBuf)):]
		unmasked, needMore, invalid := ExtractWSClientPayload(wsTail, 32)
		if invalid {
			return s.emitSingle("websocket", "invalid/unmasked ws frame", true)
		}
		if needMore {
			if len(s.clientBuf) >= s.maxPrefix {
				s.done = true
				return EvalOutcome{Decision: DecisionAllow}
			}
			return EvalOutcome{Decision: DecisionContinue}
		}
		if AnalyzeFET(unmasked).LooksEncrypted {
			return s.emitSingle("websocket", fmt.Sprintf("ws encrypted payload (%dB)", len(unmasked)), true)
		}
		s.done = true
		return EvalOutcome{Decision: DecisionAllow}
	}

	// Wait until client sends at least 1 byte before running client-initiated detectors.
	if len(s.clientBuf) == 0 {
		return EvalOutcome{Decision: DecisionContinue}
	}

	c := s.clientBuf

	// 1. BitTorrent TCP handshake
	if btMatch, btNeed := DetectBitTorrentTCP(c); btMatch {
		return s.emitSingle("bittorrent", "bt handshake", true)
	} else if btNeed && len(c) < 20 {
		return EvalOutcome{Decision: DecisionContinue}
	}

	// 2. SSH banner
	switch sshRes, banner := DetectSSH(c); sshRes {
	case SSHNeedMore:
		return EvalOutcome{Decision: DecisionContinue}
	case SSHMatched:
		if cr, ok := s.cp.ActiveRule("ssh", s.meta); ok {
			if !(cr.Rule.Options.AllowStdSSHPort && (s.meta.DstPort == 22 || s.meta.HostPort == 22)) {
				ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: banner}
				s.done = true
				dec := DecisionAllow
				if cr.Rule.Action == "block" {
					dec = DecisionBlock
				}
				return EvalOutcome{Decision: dec, Events: []MatchResult{ev}}
			}
		}
		s.done = true
		return EvalOutcome{Decision: DecisionAllow}
	}

	// 3. Strict SOCKS4/4a/5
	switch socksRes, detail := DetectSOCKS(c, s.serverBuf); socksRes {
	case SOCKSNeedMore:
		return EvalOutcome{Decision: DecisionContinue}
	case SOCKSMatched:
		return s.emitSingle("socks", detail, true)
	}

	// 4. TCP DNS (port 53, 2-byte length prefix + DNS packet)
	if s.meta.DstPort == 53 && len(c) >= 14 {
		dnsLen := int(binary.BigEndian.Uint16(c[0:2]))
		if dnsLen >= 12 && len(c) >= 2+dnsLen {
			if dnsInfo, ok := ParseDNSPacket(c[2 : 2+dnsLen]); ok {
				return s.evalDNS(dnsInfo)
			}
		}
	}

	// 5. TLS ClientHello (supports multi-record fragmentation)
	if !s.tlsDone {
		ch, tlsSt := ParseTLSClientHello(c)
		switch tlsSt {
		case TLSNeedMore:
			if len(c) >= s.maxPrefix {
				s.done = true
				return EvalOutcome{Decision: DecisionAllow}
			}
			return EvalOutcome{Decision: DecisionContinue}
		case TLSValid:
			s.tlsDone = true
			var events []MatchResult
			blocked := false
			if cr, ok := s.cp.ActiveRule("tls_sni", s.meta); ok && ch.SNI != "" {
				if cr.DomainMatcher != nil && cr.DomainMatcher.Match(ch.SNI) {
					events = append(events, MatchResult{
						Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
						Detail: "sni=" + ch.SNI,
					})
					if cr.Rule.Action == "block" {
						blocked = true
					} else if cr.Rule.Action == "allow" {
						s.done = true
						return EvalOutcome{Decision: DecisionAllow, Events: events}
					}
				}
			}
			if !blocked {
				if cr, ok := s.cp.ActiveRule("mining", s.meta); ok && ch.SNI != "" && cr.DomainMatcher != nil {
					if cr.DomainMatcher.Match(ch.SNI) {
						events = append(events, MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
							Detail: "pool sni=" + ch.SNI,
						})
						if cr.Rule.Action == "block" {
							blocked = true
						}
					}
				}
			}
			if !blocked {
				if cr, ok := s.cp.ActiveRule("tls_anomaly", s.meta); ok {
					var reason string
					if cr.Rule.Options.BlockECH && (ch.HasECH || ch.HasESNI) {
						reason = "ech/esni"
					} else if cr.Rule.Options.BlockNoSNI && ch.SNI == "" {
						reason = "tls-no-sni"
					}
					if reason != "" {
						events = append(events, MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
							Detail: reason,
						})
						if cr.Rule.Action == "block" {
							blocked = true
						}
					}
				}
			}
			if blocked {
				s.done = true
				return EvalOutcome{Decision: DecisionBlock, Events: events}
			}
			if s.trojanActive {
				// Seed TrojanTracker with the TLS handshake chunks seen so far
				if matched, tDone := s.trojan.Feed(false, c); matched {
					if cr, ok := s.cp.ActiveRule("trojan", s.meta); ok {
						events = append(events, MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: "tls-in-tls seq"})
						s.done = true
						if cr.Rule.Action == "block" {
							return EvalOutcome{Decision: DecisionBlock, Events: events}
						}
						return EvalOutcome{Decision: DecisionAllow, Events: events}
					}
				} else if !tDone {
					return EvalOutcome{Decision: DecisionContinue, Events: events}
				}
			}
			s.done = true
			return EvalOutcome{Decision: DecisionAllow, Events: events}

		case TLSMalformed:
			if cr, ok := s.cp.ActiveRule("tls_anomaly", s.meta); ok && cr.Rule.Options.BlockFakeObfs {
				return s.emitSingle("tls_anomaly", "fake/malformed tls header", true)
			}
			// Fall through to FET rather than granting free pass!
		}
	}

	// 6. HTTP/1.x (CONNECT proxy, absolute URI proxy, WebSocket, plain HTTP)
	if !s.httpDone && HasHTTPPrefix(c) {
		httpInfo, httpSt := ParseHTTPRequest(c)
		switch httpSt {
		case HTTPNeedMore:
			return EvalOutcome{Decision: DecisionContinue}
		case HTTPValid:
			s.httpDone = true
			var events []MatchResult
			if httpInfo.IsProxy {
				if cr, ok := s.cp.ActiveRule("http_proxy", s.meta); ok {
					events = append(events, MatchResult{
						Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
						Detail: fmt.Sprintf("%s %s", httpInfo.Method, httpInfo.Target),
					})
					s.done = true
					if cr.Rule.Action == "block" {
						return EvalOutcome{Decision: DecisionBlock, Events: events}
					}
					return EvalOutcome{Decision: DecisionAllow, Events: events}
				}
			}
			if httpInfo.IsWebSocket {
				if cr, ok := s.cp.ActiveRule("websocket", s.meta); ok {
					switch cr.Rule.WSMode {
					case "block_all":
						events = append(events, MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
							Detail: "ws upgrade host=" + httpInfo.Host,
						})
						s.done = true
						if cr.Rule.Action == "block" {
							return EvalOutcome{Decision: DecisionBlock, Events: events}
						}
						return EvalOutcome{Decision: DecisionAllow, Events: events}
					case "two_stage_high":
						s.wsInspecting = true
						s.wsOffset = httpInfo.HeaderEndOffset
						// If client already pipelined WS payload right after HTTP headers, inspect immediately.
						if len(c) > s.wsOffset {
							unmasked, needMore, invalid := ExtractWSClientPayload(c[s.wsOffset:], 32)
							if invalid {
								return s.emitSingle("websocket", "invalid ws frame", true)
							}
							if !needMore {
								if AnalyzeFET(unmasked).LooksEncrypted {
									return s.emitSingle("websocket", "ws encrypted payload", true)
								}
								s.done = true
								return EvalOutcome{Decision: DecisionAllow}
							}
						}
						return EvalOutcome{Decision: DecisionContinue}
					default: // log_only
						events = append(events, MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: "log",
							Detail: "ws upgrade host=" + httpInfo.Host,
						})
						s.done = true
						return EvalOutcome{Decision: DecisionAllow, Events: events}
					}
				}
			}
			if cr, ok := s.cp.ActiveRule("http_plain", s.meta); ok && httpInfo.Host != "" {
				if cr.DomainMatcher == nil || cr.DomainMatcher.Match(httpInfo.Host) {
					events = append(events, MatchResult{
						Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
						Detail: fmt.Sprintf("%s host=%s", httpInfo.Method, httpInfo.Host),
					})
					s.done = true
					if cr.Rule.Action == "block" {
						return EvalOutcome{Decision: DecisionBlock, Events: events}
					}
					return EvalOutcome{Decision: DecisionAllow, Events: events}
				}
			}
			s.done = true
			return EvalOutcome{Decision: DecisionAllow, Events: events}

		case HTTPInvalid:
			if cr, ok := s.cp.ActiveRule("tls_anomaly", s.meta); ok && cr.Rule.Options.BlockFakeObfs {
				return s.emitSingle("tls_anomaly", "fake http obfs prefix", true)
			}
			// Fall through to FET!
		}
	}

	// 6.5 Raw Stratum TCP mining handshake (newline-delimited JSON-RPC starting with '{')
	if _, miningActive := s.cp.ActiveRule("mining", s.meta); miningActive && c[0] == '{' {
		switch stRes, detail := DetectStratumTCP(c); stRes {
		case MiningNeedMore:
			return EvalOutcome{Decision: DecisionContinue}
		case MiningMatched:
			return s.emitSingle("mining", detail, true)
		}
	}

	// 7. OpenVPN TCP (wait up to 1 server reply if initial packet looks like length-prefixed HardReset)
	if _, ovpnActive := s.cp.ActiveRule("openvpn", s.meta); ovpnActive {
		ovMatched, ovDone := s.ovpn.FeedTCP(c, s.serverBuf)
		if ovMatched {
			return s.emitSingle("openvpn", "openvpn-tcp handshake", true)
		}
		if !ovDone {
			// Check FET simultaneously if client already sent >= 16 bytes that look encrypted,
			// unless it's clearly a short OpenVPN HardReset (14-120B).
			if len(s.serverBuf) == 0 && len(c) < 256 {
				return EvalOutcome{Decision: DecisionContinue}
			}
		}
	}

	// 8. FET (Fully Encrypted Traffic: Shadowsocks / SS-2022 / VMess-TCP)
	if cr, ok := s.cp.ActiveRule("fet_tcp", s.meta); ok {
		if len(c) < 6 {
			return EvalOutcome{Decision: DecisionContinue}
		}
		fet := AnalyzeFET(c)
		if fet.LooksEncrypted {
			ev := MatchResult{
				Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
				Detail: fmt.Sprintf("popcount=%.2f len=%d", fet.AvgPopCount, len(c)),
			}
			s.done = true
			if cr.Rule.Action == "block" {
				return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
			}
			return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
		}
	}

	s.done = true
	return EvalOutcome{Decision: DecisionAllow}
}

func (s *TCPSession) emitSingle(id model.ProtocolID, detail string, allowIfNotBlock bool) EvalOutcome {
	cr, ok := s.cp.ActiveRule(id, s.meta)
	s.done = true
	if !ok {
		return EvalOutcome{Decision: DecisionAllow}
	}
	ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: detail}
	if cr.Rule.Action == model.ActionBlock {
		return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
	}
	return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
}

func (s *TCPSession) evalDNS(info DNSInfo) EvalOutcome {
	s.done = true
	var events []MatchResult
	if cr, ok := s.cp.ActiveRule("dns", s.meta); ok {
		if cr.Rule.Options.MaxDNSPayload > 0 && info.PayloadSize > cr.Rule.Options.MaxDNSPayload {
			events = append(events, MatchResult{
				Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
				Detail: fmt.Sprintf("oversized dns=%dB", info.PayloadSize),
			})
			if cr.Rule.Action == "block" {
				return EvalOutcome{Decision: DecisionBlock, Events: events}
			}
			return EvalOutcome{Decision: DecisionAllow, Events: events}
		}
		if cr.DomainMatcher != nil {
			for _, q := range info.Questions {
				if cr.DomainMatcher.Match(q) {
					events = append(events, MatchResult{
						Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
						Detail: "dns=" + q,
					})
					if cr.Rule.Action == "block" {
						return EvalOutcome{Decision: DecisionBlock, Events: events}
					}
					return EvalOutcome{Decision: DecisionAllow, Events: events}
				}
			}
		}
	}
	if cr, ok := s.cp.ActiveRule("mining", s.meta); ok && cr.DomainMatcher != nil {
		for _, q := range info.Questions {
			if cr.DomainMatcher.Match(q) {
				events = append(events, MatchResult{
					Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
					Detail: "pool dns=" + q,
				})
				if cr.Rule.Action == "block" {
					return EvalOutcome{Decision: DecisionBlock, Events: events}
				}
				return EvalOutcome{Decision: DecisionAllow, Events: events}
			}
		}
	}
	return EvalOutcome{Decision: DecisionAllow}
}

// UDPSession holds bounded per-stream protocol state for one pending UDP 5-tuple.
type UDPSession struct {
	meta        FlowMeta
	cp          *CompiledPolicy
	maxPkts     int
	pktCount    int
	knownDNS    bool
	quic        QUICStream
	quicFailed  int
	ovpn        OpenVPNTracker
	wg          WireGuardTracker
	done        bool
}

// NewUDPSession creates a bounded UDP protocol evaluation session.
func NewUDPSession(meta FlowMeta, cp *CompiledPolicy, maxPkts int) *UDPSession {
	if maxPkts <= 0 {
		maxPkts = 6
	}
	return &UDPSession{
		meta:    meta,
		cp:      cp,
		maxPkts: maxPkts,
	}
}

// Feed processes one UDP datagram (`rev == true` is server->client).
func (u *UDPSession) Feed(rev bool, data []byte) EvalOutcome {
	if u.done || u.cp == nil || u.cp.GlobalBypass || !u.cp.NeedUDP || u.cp.IsTrustedTenant(u.meta.TenantIP) {
		u.done = true
		return EvalOutcome{Decision: DecisionAllow}
	}
	if len(data) == 0 {
		return EvalOutcome{Decision: DecisionContinue}
	}

	// 1. Standard DNS check FIRST (guarantees 0 false positives on DNS for OpenVPN/FET-UDP!)
	if dnsInfo, isDNS := ParseDNSPacket(data); isDNS {
		u.knownDNS = true
		if cr, ok := u.cp.ActiveRule("dns", u.meta); ok && !dnsInfo.IsResponse {
			if cr.Rule.Options.MaxDNSPayload > 0 && dnsInfo.PayloadSize > cr.Rule.Options.MaxDNSPayload {
				ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: fmt.Sprintf("oversized dns=%dB", dnsInfo.PayloadSize)}
				if cr.Rule.Action == "block" {
					u.done = true
					return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
				}
				u.done = true
				return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
			}
			if cr.DomainMatcher != nil {
				for _, q := range dnsInfo.Questions {
					if cr.DomainMatcher.Match(q) {
						ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: "dns=" + q}
						if cr.Rule.Action == "block" {
							u.done = true
							return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
						}
						u.done = true
						return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
					}
				}
			}
		}
		if cr, ok := u.cp.ActiveRule("mining", u.meta); ok && !dnsInfo.IsResponse && cr.DomainMatcher != nil {
			for _, q := range dnsInfo.Questions {
				if cr.DomainMatcher.Match(q) {
					ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: "pool dns=" + q}
					u.done = true
					if cr.Rule.Action == "block" {
						return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
					}
					return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
				}
			}
		}
		u.done = true
		return EvalOutcome{Decision: DecisionAllow}
	}

	if !rev {
		u.pktCount++
	}

	// 2. QUIC Initial SNI check
	if !rev && (IsQUICInitialCandidate(data) || u.quic.dcid != nil) {
		ch, qDone, validInitial := u.quic.Feed(data)
		if validInitial {
			if qDone {
				u.done = true
				var events []MatchResult
				if cr, ok := u.cp.ActiveRule("quic_sni", u.meta); ok && ch.SNI != "" {
					if cr.DomainMatcher != nil && cr.DomainMatcher.Match(ch.SNI) {
						events = append(events, MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
							Detail: "quic sni=" + ch.SNI,
						})
						if cr.Rule.Action == "block" {
							return EvalOutcome{Decision: DecisionBlock, Events: events}
						}
						return EvalOutcome{Decision: DecisionAllow, Events: events}
					}
				}
				if cr, ok := u.cp.ActiveRule("mining", u.meta); ok && ch.SNI != "" && cr.DomainMatcher != nil {
					if cr.DomainMatcher.Match(ch.SNI) {
						events = append(events, MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
							Detail: "pool quic sni=" + ch.SNI,
						})
						if cr.Rule.Action == "block" {
							return EvalOutcome{Decision: DecisionBlock, Events: events}
						}
						return EvalOutcome{Decision: DecisionAllow, Events: events}
					}
				}
				if cr, ok := u.cp.ActiveRule("tls_anomaly", u.meta); ok {
					var reason string
					if cr.Rule.Options.BlockECH && (ch.HasECH || ch.HasESNI) {
						reason = "quic ech/esni"
					} else if cr.Rule.Options.BlockNoSNI && ch.SNI == "" {
						reason = "quic-no-sni"
					}
					if reason != "" {
						events = append(events, MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: reason,
						})
						if cr.Rule.Action == "block" {
							return EvalOutcome{Decision: DecisionBlock, Events: events}
						}
					}
				}
				if cr, ok := u.cp.ActiveRule("udp_proxy", u.meta); ok {
					detail := "quic/hy2/tuic"
					if ch.SNI != "" {
						detail = "quic/hy2/tuic sni=" + ch.SNI
					}
					events = append(events, MatchResult{
						Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: detail,
					})
					if cr.Rule.Action == "block" {
						return EvalOutcome{Decision: DecisionBlock, Events: events}
					}
				}
				return EvalOutcome{Decision: DecisionAllow, Events: events}
			}
			if u.pktCount >= u.maxPkts {
				u.done = true
				return EvalOutcome{Decision: DecisionAllow}
			}
			return EvalOutcome{Decision: DecisionContinue}
		}
		u.quicFailed++
	}

	// 3. BitTorrent DHT UDP
	if !rev {
		if matched, detail := DetectBitTorrentUDP(data); matched {
			u.done = true
			if cr, ok := u.cp.ActiveRule("bittorrent", u.meta); ok {
				ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: detail}
				if cr.Rule.Action == "block" {
					return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
				}
				return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
			}
			return EvalOutcome{Decision: DecisionAllow}
		}
	}

	// 4. OpenVPN UDP (with strict Session ID echo verification)
	if cr, ok := u.cp.ActiveRule("openvpn", u.meta); ok {
		ovMatch, ovDone := u.ovpn.FeedPacket(rev, data)
		if ovMatch {
			u.done = true
			ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: "openvpn-udp"}
			if cr.Rule.Action == "block" {
				return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
			}
			return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
		}
		if !ovDone && u.pktCount < u.maxPkts {
			return EvalOutcome{Decision: DecisionContinue}
		}
	}

	// 5. WireGuard UDP
	_, udpProxyActive := u.cp.ActiveRule("udp_proxy", u.meta)
	if cr, ok := u.cp.ActiveRule("wireguard", u.meta); ok {
		wgMatch, wgDone := u.wg.Feed(rev, data)
		if wgMatch {
			u.done = true
			ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: "wireguard-udp"}
			if cr.Rule.Action == "block" {
				return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
			}
			return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
		}
		wgCandidate := len(data) >= 4 && data[1] == 0 && data[2] == 0 && data[3] == 0 && data[0] >= 1 && data[0] <= 4
		if !wgDone && u.pktCount < u.maxPkts && (!udpProxyActive || wgCandidate) {
			return EvalOutcome{Decision: DecisionContinue}
		}
	}

	// 6. Optional FET UDP (SS-UDP / SS-2022 UDP / VMess-UDP)
	// Exclude known standard UDP protocols (DNS, STUN, DTLS, NTP, QUIC Initial).
	if !rev {
		if cr, ok := u.cp.ActiveRule("fet_udp", u.meta); ok {
			minLen := cr.Rule.Options.MinUDPPacketLen
			if minLen <= 0 {
				minLen = 48
			}
			if !u.knownDNS && !IsLikelySTUN(data) && !IsLikelyDTLS(data) && !IsLikelyNTP(data, u.meta.SrcPort, u.meta.DstPort) && !IsQUICInitialCandidate(data) {
				if len(data) >= minLen {
					fet := AnalyzeFET(data)
					if fet.LooksEncrypted {
						u.done = true
						ev := MatchResult{
							Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action,
							Detail: fmt.Sprintf("udp popcount=%.2f len=%d", fet.AvgPopCount, len(data)),
						}
						if cr.Rule.Action == "block" {
							return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
						}
						return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
					}
				}
			}
		}
	}

	// 7. Dedicated UDP Proxy blocker (QUIC / Hysteria2 / TUIC / Salamander obfs / non-standard UDP proxies)
	if !rev {
		if cr, ok := u.cp.ActiveRule("udp_proxy", u.meta); ok {
			if !u.knownDNS && !IsLikelyNTP(data, u.meta.SrcPort, u.meta.DstPort) {
				var detail string
				switch {
				case IsQUICInitialCandidate(data):
					detail = "quic/hy2/tuic"
				case len(data) >= 32 && !IsLikelySTUN(data) && !IsLikelyDTLS(data):
					if fet := AnalyzeFET(data); fet.LooksEncrypted {
						detail = fmt.Sprintf("udp-proxy/obfs popcount=%.2f len=%d", fet.AvgPopCount, len(data))
					} else if cr.Rule.Options.BlockAllUDP {
						detail = fmt.Sprintf("udp-proxy port=%d len=%d", u.meta.DstPort, len(data))
					}
				case cr.Rule.Options.BlockAllUDP:
					detail = fmt.Sprintf("udp-proxy port=%d len=%d", u.meta.DstPort, len(data))
				}
				if detail != "" {
					u.done = true
					ev := MatchResult{Matched: true, Protocol: cr.Rule.ID, Action: cr.Rule.Action, Detail: detail}
					if cr.Rule.Action == "block" {
						return EvalOutcome{Decision: DecisionBlock, Events: []MatchResult{ev}}
					}
					return EvalOutcome{Decision: DecisionAllow, Events: []MatchResult{ev}}
				}
			}
		}
	}

	if u.pktCount >= u.maxPkts || (u.ovpn.state < 0 && !IsQUICInitialCandidate(data) && u.quic.dcid == nil) {
		u.done = true
		return EvalOutcome{Decision: DecisionAllow}
	}
	return EvalOutcome{Decision: DecisionContinue}
}
