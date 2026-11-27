package engine

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"snapgfw/internal/proto"
)

const (
	tlsProbeMaxCache      = 2048
	tlsProbeMaxConcurrent = 4
	tlsProbeDialTimeout   = 1200 * time.Millisecond
	tlsProbeHSTimeout     = 3500 * time.Millisecond
	tlsProbeHTTPTimeout   = 2000 * time.Millisecond
	tlsProbeHTTPMaxBytes  = 16384
	tlsProbeTrustedTTL    = 15 * time.Minute
	tlsProbeUntrustedTTL  = 10 * time.Minute
	tlsProbeUnknownTTL    = 30 * time.Second
)

type tlsProbeKey struct {
	tenantIP string
	dstPort  uint16
	sni      string
}

type tlsProbeEntry struct {
	result        proto.TLSProbeResult
	airportProbed bool
	expiresAt     time.Time
}

type probeEndpoint struct {
	localIP   string
	localPort uint16
	dstIP     string
	dstPort   uint16
}

// TLSCertProber implements Strategy A (non-blocking cached active TLS certificate verification)
// plus optional HTTPS commercial airport panel homepage fingerprinting on the same connection.
//
// When a standard TLS ClientHello (without REALITY auth SessionID) is sent to a container port:
//   - VLESS+REALITY / AnyTLS+REALITY transparently relay the handshake to the real destination
//     site and present a genuine CA-signed certificate + benign homepage -> Trusted / Clean.
//   - 3x-ui / x-ui / s-ui personal panels with valid CA certs -> Trusted / Clean.
//   - Self-signed, untrusted-CA, expired, or SNI-mismatched Trojan/VLESS+TLS/AnyTLS servers ->
//     CertStatus=Untrusted.
//   - Direct-exposed HTTPS V2Board / Xboard / SSPanel / PPanel servers ->
//     AirportStatus=Untrusted.
//   - Network errors, timeouts, or missing certs -> fail-open (Unknown).
type TLSCertProber struct {
	mu               sync.RWMutex
	cache            map[tlsProbeKey]tlsProbeEntry
	pending          map[tlsProbeKey]struct{}
	sem              chan struct{}
	inFlightMu       sync.RWMutex
	inFlight         map[probeEndpoint]struct{}
	roots            *x509.CertPool
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	httpTimeout      time.Duration
	trustedTTL       time.Duration
	untrustedTTL     time.Duration
	unknownTTL       time.Duration
	disabled         bool
}

// NewTLSCertProber creates a bounded Strategy-A certificate and HTTPS airport prober.
func NewTLSCertProber() *TLSCertProber {
	return &TLSCertProber{
		cache:            make(map[tlsProbeKey]tlsProbeEntry, 64),
		pending:          make(map[tlsProbeKey]struct{}, 16),
		sem:              make(chan struct{}, tlsProbeMaxConcurrent),
		inFlight:         make(map[probeEndpoint]struct{}, 8),
		dialTimeout:      tlsProbeDialTimeout,
		handshakeTimeout: tlsProbeHSTimeout,
		httpTimeout:      tlsProbeHTTPTimeout,
		trustedTTL:       tlsProbeTrustedTTL,
		untrustedTTL:     tlsProbeUntrustedTTL,
		unknownTTL:       tlsProbeUnknownTTL,
	}
}

// SetRoots overrides the trusted CA pool (used in deterministic tests).
func (p *TLSCertProber) SetRoots(roots *x509.CertPool) {
	p.mu.Lock()
	p.roots = roots
	p.mu.Unlock()
}

// SetDisabled disables background probing (useful in unit tests without live listeners).
func (p *TLSCertProber) SetDisabled(v bool) {
	p.mu.Lock()
	p.disabled = v
	p.mu.Unlock()
}

// IsOwnProbe returns true if the inbound TCP flow belongs to an active host-side probe socket
// so the DPI engine offloads it immediately without logging or self-blocking.
func (p *TLSCertProber) IsOwnProbe(meta proto.FlowMeta) bool {
	if p == nil || meta.Direction != proto.DirInbound || meta.L4Proto != "tcp" || meta.PeerIP == nil || meta.TenantIP == nil {
		return false
	}
	ep := probeEndpoint{
		localIP:   meta.PeerIP.String(),
		localPort: meta.SrcPort,
		dstIP:     meta.TenantIP.String(),
		dstPort:   meta.DstPort,
	}
	p.inFlightMu.RLock()
	_, ok := p.inFlight[ep]
	p.inFlightMu.RUnlock()
	return ok
}

// LookupAndTrigger returns the cached certificate & airport panel verdict without blocking.
// On cache miss (or when airport probing is newly requested), it queues a bounded async probe.
func (p *TLSCertProber) LookupAndTrigger(tenantIP net.IP, dstPort uint16, sni string, checkAirport bool) proto.TLSProbeResult {
	if p == nil || tenantIP == nil || dstPort == 0 {
		return proto.TLSProbeResult{}
	}
	key := tlsProbeKey{
		tenantIP: tenantIP.String(),
		dstPort:  dstPort,
		sni:      strings.ToLower(strings.TrimSpace(sni)),
	}
	now := time.Now()

	p.mu.RLock()
	if p.disabled {
		p.mu.RUnlock()
		return proto.TLSProbeResult{}
	}
	if ent, ok := p.cache[key]; ok && now.Before(ent.expiresAt) {
		if !checkAirport || ent.airportProbed {
			p.mu.RUnlock()
			return ent.result
		}
		// Return cached cert result immediately while scheduling an upgraded probe with airport check.
		cachedRes := ent.result
		_, alreadyPending := p.pending[key]
		p.mu.RUnlock()
		if !alreadyPending {
			p.enqueueAsync(key, true)
		}
		return cachedRes
	}
	_, alreadyPending := p.pending[key]
	p.mu.RUnlock()

	if !alreadyPending {
		p.enqueueAsync(key, checkAirport)
	}
	return proto.TLSProbeResult{}
}

func (p *TLSCertProber) enqueueAsync(key tlsProbeKey, checkAirport bool) {
	select {
	case p.sem <- struct{}{}:
	default:
		return
	}

	p.mu.Lock()
	if p.disabled {
		p.mu.Unlock()
		<-p.sem
		return
	}
	if _, ok := p.pending[key]; ok {
		p.mu.Unlock()
		<-p.sem
		return
	}
	p.pending[key] = struct{}{}
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			delete(p.pending, key)
			p.mu.Unlock()
			<-p.sem
		}()
		p.probeAndCache(key, checkAirport)
	}()
}

// ProbeSync runs a single probe synchronously and stores the verdict in cache (useful in tests).
func (p *TLSCertProber) ProbeSync(tenantIP net.IP, dstPort uint16, sni string, checkAirport bool) proto.TLSProbeResult {
	if p == nil || tenantIP == nil || dstPort == 0 {
		return proto.TLSProbeResult{}
	}
	key := tlsProbeKey{
		tenantIP: tenantIP.String(),
		dstPort:  dstPort,
		sni:      strings.ToLower(strings.TrimSpace(sni)),
	}
	return p.probeAndCache(key, checkAirport)
}

func (p *TLSCertProber) probeAndCache(key tlsProbeKey, checkAirport bool) proto.TLSProbeResult {
	p.mu.RLock()
	roots := p.roots
	dialTO := p.dialTimeout
	hsTO := p.handshakeTimeout
	httpTO := p.httpTimeout
	trustedTTL := p.trustedTTL
	untrustedTTL := p.untrustedTTL
	unknownTTL := p.unknownTTL
	p.mu.RUnlock()

	addr := net.JoinHostPort(key.tenantIP, strconv.Itoa(int(key.dstPort)))
	rawConn, err := net.DialTimeout("tcp", addr, dialTO)
	if err != nil {
		p.storeCache(key, proto.TLSProbeResult{}, checkAirport, unknownTTL)
		return proto.TLSProbeResult{}
	}
	defer rawConn.Close()

	// Register this probe socket BEFORE sending TLS ClientHello so host-proxy NFQUEUE hooks
	// bypass our own probe stream cleanly.
	if laddr, ok := rawConn.LocalAddr().(*net.TCPAddr); ok && laddr.IP != nil {
		ep := probeEndpoint{
			localIP:   laddr.IP.String(),
			localPort: uint16(laddr.Port),
			dstIP:     key.tenantIP,
			dstPort:   key.dstPort,
		}
		p.inFlightMu.Lock()
		p.inFlight[ep] = struct{}{}
		p.inFlightMu.Unlock()
		defer func() {
			p.inFlightMu.Lock()
			delete(p.inFlight, ep)
			p.inFlightMu.Unlock()
		}()
	}

	_ = rawConn.SetDeadline(time.Now().Add(hsTO))

	nextProtos := []string{"h2", "http/1.1"}
	if checkAirport {
		// Prefer HTTP/1.1 so homepage HTML can be read directly without an H2 framing stack.
		nextProtos = []string{"http/1.1"}
	}
	tlsCfg := &tls.Config{
		ServerName:         key.sni,
		InsecureSkipVerify: true, // Verified explicitly via proto.VerifyCertChain below
		MinVersion:         tls.VersionTLS12,
		NextProtos:         nextProtos,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	defer tlsConn.Close()

	hsErr := tlsConn.Handshake()
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		// Timeout, EOF, reset, or non-TLS port: always fail-open.
		p.storeCache(key, proto.TLSProbeResult{}, checkAirport, unknownTTL)
		return proto.TLSProbeResult{}
	}

	var res proto.TLSProbeResult
	if roots != nil || proto.SystemRootsAvailable() {
		if trusted, reason := proto.VerifyCertChain(certs, key.sni, roots, time.Now()); trusted {
			res.CertStatus = proto.TLSProbeTrusted
		} else {
			res.CertStatus = proto.TLSProbeUntrusted
			res.CertReason = reason
		}
	}

	// Reuse the already-established TLS connection to check for hosted commercial airport panels.
	if checkAirport && hsErr == nil {
		_ = tlsConn.SetDeadline(time.Now().Add(httpTO))
		host := key.sni
		if host == "" {
			host = key.tenantIP
		}
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", host)
		if _, werr := io.WriteString(tlsConn, req); werr == nil {
			buf := make([]byte, tlsProbeHTTPMaxBytes)
			total := 0
			for total < len(buf) {
				n, rerr := tlsConn.Read(buf[total:])
				if n > 0 {
					total += n
					if matched, detail := proto.DetectAirportHTTPResponse(buf[:total]); matched {
						res.AirportStatus = proto.TLSProbeUntrusted
						res.AirportReason = "https " + detail
						break
					}
				}
				if rerr != nil {
					break
				}
			}
			if res.AirportStatus == proto.TLSProbeUnknown && total > 0 {
				res.AirportStatus = proto.TLSProbeTrusted // Clean homepage / non-airport service
			}
		}
	}

	ttl := trustedTTL
	if res.CertStatus == proto.TLSProbeUntrusted || res.AirportStatus == proto.TLSProbeUntrusted {
		ttl = untrustedTTL
	} else if res.CertStatus == proto.TLSProbeUnknown && (!checkAirport || res.AirportStatus == proto.TLSProbeUnknown) {
		ttl = unknownTTL
	}
	p.storeCache(key, res, checkAirport, ttl)
	return res
}

func (p *TLSCertProber) storeCache(key tlsProbeKey, res proto.TLSProbeResult, airportProbed bool, ttl time.Duration) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cache) >= tlsProbeMaxCache {
		for k, v := range p.cache {
			if !now.Before(v.expiresAt) {
				delete(p.cache, k)
			}
		}
		if len(p.cache) >= tlsProbeMaxCache {
			var oldestKey tlsProbeKey
			var oldestExp time.Time
			first := true
			for k, v := range p.cache {
				if first || v.expiresAt.Before(oldestExp) {
					oldestKey = k
					oldestExp = v.expiresAt
					first = false
				}
			}
			delete(p.cache, oldestKey)
		}
	}
	p.cache[key] = tlsProbeEntry{
		result:        res,
		airportProbed: airportProbed,
		expiresAt:     now.Add(ttl),
	}
}
