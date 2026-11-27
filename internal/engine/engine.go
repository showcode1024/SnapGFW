package engine

import (
	"container/list"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"snapgfw/internal/config"
	"snapgfw/internal/model"
	"snapgfw/internal/proto"
	"snapgfw/internal/runman"
	"snapgfw/internal/store"
)

// Stats holds lock-free engine telemetry exposed in the Web UI.
type Stats struct {
	PacketsTotal    uint64 `json:"packets_total"`
	TCPPackets      uint64 `json:"tcp_packets"`
	UDPPackets      uint64 `json:"udp_packets"`
	OffloadedAccept uint64 `json:"offloaded_accept"`
	OffloadedDrop   uint64 `json:"offloaded_drop"`
	QueueDropped    uint64 `json:"queue_dropped"`
	PendingStreams  int64  `json:"pending_streams"`
	WorkerCount     int    `json:"worker_count"`
}

// Engine coordinates multi-worker DPI packet inspection, policy hot-reloads, and telemetry.
type Engine struct {
	cfg        config.Config
	audit      *store.AuditStore
	discovery  *runman.Discovery
	quarantine *QuarantineManager
	prober     *TLSCertProber

	policyPtr atomic.Pointer[policySnapshot]
	workers   []*worker

	packetsTotal    atomic.Uint64
	tcpPackets      atomic.Uint64
	udpPackets      atomic.Uint64
	offloadedAccept atomic.Uint64
	offloadedDrop   atomic.Uint64
	queueDropped    atomic.Uint64
	pendingStreams  atomic.Int64
}

type policySnapshot struct {
	raw      model.Policy
	compiled *proto.CompiledPolicy
}

// New creates a multi-worker DPI Engine.
func New(cfg config.Config, initialPolicy model.Policy, audit *store.AuditStore, discovery *runman.Discovery, quarantine *QuarantineManager) *Engine {
	cfg.Normalize()
	e := &Engine{
		cfg:        cfg,
		audit:      audit,
		discovery:  discovery,
		quarantine: quarantine,
		prober:     NewTLSCertProber(),
	}
	e.UpdatePolicy(initialPolicy)

	e.workers = make([]*worker, cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		e.workers[i] = newWorker(i, e)
	}
	return e
}

// UpdatePolicy compiles and atomically swaps the active DPI policy without blocking workers.
func (e *Engine) UpdatePolicy(pol model.Policy) {
	compiled := proto.CompilePolicy(pol, e.cfg.GeoSitePath)
	e.policyPtr.Store(&policySnapshot{
		raw:      pol,
		compiled: compiled,
	})
}

// Prober returns the engine's Strategy-A TLS certificate prober.
func (e *Engine) Prober() *TLSCertProber { return e.prober }

// GeoFallback returns true if built-in CN domains are active because geosite.dat was absent.
func (e *Engine) GeoFallback() bool {
	snap := e.policyPtr.Load()
	return snap != nil && snap.compiled != nil && snap.compiled.GeoFallback
}

// Stats returns a point-in-time metrics snapshot.
func (e *Engine) Stats() Stats {
	return Stats{
		PacketsTotal:    e.packetsTotal.Load(),
		TCPPackets:      e.tcpPackets.Load(),
		UDPPackets:      e.udpPackets.Load(),
		OffloadedAccept: e.offloadedAccept.Load(),
		OffloadedDrop:   e.offloadedDrop.Load(),
		QueueDropped:    e.queueDropped.Load(),
		PendingStreams:  e.pendingStreams.Load(),
		WorkerCount:     len(e.workers),
	}
}

// Run starts all workers and consumes packets from source until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, source PacketSource) error {
	var wg sync.WaitGroup
	wCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		wg.Wait()
	}()

	for _, w := range e.workers {
		wg.Add(1)
		go func(wk *worker) {
			defer wg.Done()
			wk.run(wCtx)
		}(w)
	}

	return source.Start(wCtx, func(ev PacketEvent) {
		e.Dispatch(ev)
	})
}

// Dispatch routes a packet event to its shard worker based on StreamID.
func (e *Engine) Dispatch(ev PacketEvent) {
	e.packetsTotal.Add(1)
	idx := int(ev.StreamID % uint32(len(e.workers)))
	w := e.workers[idx]
	select {
	case w.ch <- ev:
	default:
		// Never deadlock netlink readers under extreme burst; fail-open single packet.
		e.queueDropped.Add(1)
		if ev.SetVerdict != nil {
			_ = ev.SetVerdict(VerdictAccept)
		}
	}
}

// ProcessSync directly processes one packet on the caller goroutine (useful in deterministic tests).
func (e *Engine) ProcessSync(ev PacketEvent) Verdict {
	e.packetsTotal.Add(1)
	idx := int(ev.StreamID % uint32(len(e.workers)))
	return e.workers[idx].handleEvent(ev)
}

type streamEntry struct {
	streamID uint32
	l4Proto  uint8
	meta     proto.FlowMeta
	lastSeen time.Time
	pktCount int
	verdict  Verdict
	finished bool
	tcpC2S   tcpHalfReassembler
	tcpS2C   tcpHalfReassembler
	tcpSess  *proto.TCPSession
	udpSess  *proto.UDPSession
	lruElem  *list.Element
}

type logDedupeKey struct {
	tenant   string
	protocol string
	action   string
}

type worker struct {
	id          int
	engine      *Engine
	ch          chan PacketEvent
	streams     map[uint32]*streamEntry
	lru         *list.List
	maxPending  int
	idleTTL     time.Duration
	burstWindow time.Duration
	logDedupe   map[logDedupeKey]time.Time
	recentDrops map[uint32]time.Time
}

func newWorker(id int, eng *Engine) *worker {
	return &worker{
		id:          id,
		engine:      eng,
		ch:          make(chan PacketEvent, eng.cfg.WorkerQueueSize),
		streams:     make(map[uint32]*streamEntry, 128),
		lru:         list.New(),
		maxPending:  eng.cfg.MaxPendingPerWkr,
		idleTTL:     time.Duration(eng.cfg.StreamIdleSec) * time.Second,
		burstWindow: time.Duration(eng.cfg.AuditBurstSec) * time.Second,
		logDedupe:   make(map[logDedupeKey]time.Time, 32),
		recentDrops: make(map[uint32]time.Time, 64),
	}
}

func (w *worker) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-w.ch:
			v := w.handleEvent(ev)
			if ev.SetVerdict != nil {
				_ = ev.SetVerdict(v)
			}
		case now := <-ticker.C:
			w.reapIdle(now)
		}
	}
}

func (w *worker) reapIdle(now time.Time) {
	cutoff := now.Add(-w.idleTTL)
	for {
		back := w.lru.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*streamEntry)
		if ent.lastSeen.After(cutoff) {
			break // LRU is ordered by recency
		}
		w.removeEntry(ent)
	}
	if w.burstWindow > 0 && len(w.logDedupe) > 0 {
		expireAt := now.Add(-w.burstWindow * 2)
		for k, ts := range w.logDedupe {
			if ts.Before(expireAt) {
				delete(w.logDedupe, k)
			}
		}
	}
	if len(w.recentDrops) > 0 {
		dropExpire := now.Add(-15 * time.Second)
		for id, ts := range w.recentDrops {
			if ts.Before(dropExpire) {
				delete(w.recentDrops, id)
			}
		}
	}
}

func (w *worker) removeEntry(ent *streamEntry) {
	if ent.lruElem != nil {
		w.lru.Remove(ent.lruElem)
		ent.lruElem = nil
	}
	delete(w.streams, ent.streamID)
	w.engine.pendingStreams.Add(-1)
}

func (w *worker) handleEvent(ev PacketEvent) Verdict {
	pkt, ok := ParseIPPacket(ev.Data)
	if !ok || pkt.IsFrag || (pkt.L4Proto != 6 && pkt.L4Proto != 17) {
		w.engine.offloadedAccept.Add(1)
		return VerdictAcceptStream
	}
	if pkt.L4Proto == 6 {
		w.engine.tcpPackets.Add(1)
	} else {
		w.engine.udpPackets.Add(1)
	}

	snap := w.engine.policyPtr.Load()
	if snap == nil || snap.compiled.GlobalBypass {
		w.engine.offloadedAccept.Add(1)
		return VerdictAcceptStream
	}

	// Fast exit for empty non-SYN TCP ACKs when stream isn't already tracked.
	ent := w.streams[ev.StreamID]
	if ent != nil && ent.l4Proto != pkt.L4Proto {
		// Conntrack ID recycled by kernel for a new flow
		w.removeEntry(ent)
		ent = nil
	}

	if ent == nil {
		// Prevent already-queued packets (e.g. pipelined data or immediate FIN/ACK right behind
		// a dropped packet in NFQUEUE) from hitting mid-stream offload and overwriting ct mark DROP
		// back to ACCEPT. A fresh TCP SYN clears any recycled conntrack ID.
		if pkt.L4Proto == 6 && (pkt.TCPFlags&TCPFlagSYN != 0) && !ev.Reverse {
			delete(w.recentDrops, ev.StreamID)
		} else if ts, dropped := w.recentDrops[ev.StreamID]; dropped {
			if time.Since(ts) < 15*time.Second {
				return VerdictDropStream
			}
			delete(w.recentDrops, ev.StreamID)
		}

		meta := buildFlowMeta(ev, pkt, w.engine.discovery)
		if w.engine.prober != nil && w.engine.prober.IsOwnProbe(meta) {
			w.engine.offloadedAccept.Add(1)
			return VerdictAcceptStream
		}
		if snap.compiled.IsTrustedTenant(meta.TenantIP) {
			w.engine.offloadedAccept.Add(1)
			return VerdictAcceptStream
		}
		if pkt.L4Proto == 6 && !snap.compiled.NeedTCP {
			w.engine.offloadedAccept.Add(1)
			return VerdictAcceptStream
		}
		if pkt.L4Proto == 17 && !snap.compiled.NeedUDP {
			w.engine.offloadedAccept.Add(1)
			return VerdictAcceptStream
		}
		// Mid-stream TCP packet without SYN (e.g., pre-existing SSH/HTTPS session before SnapGFW started):
		// avoid false-triggering FET on mid-stream ciphertext; offload cleanly without overwriting ct mark on empty FIN/ACK.
		if pkt.L4Proto == 6 && (pkt.TCPFlags&TCPFlagSYN == 0) {
			if len(pkt.Payload) == 0 {
				return VerdictAccept
			}
			w.engine.offloadedAccept.Add(1)
			return VerdictAcceptStream
		}

		// Evict oldest entry if pending table is at cap
		for len(w.streams) >= w.maxPending {
			back := w.lru.Back()
			if back == nil {
				break
			}
			w.removeEntry(back.Value.(*streamEntry))
		}

		ent = &streamEntry{
			streamID: ev.StreamID,
			l4Proto:  pkt.L4Proto,
			meta:     meta,
			lastSeen: time.Now(),
		}
		if pkt.L4Proto == 6 {
			ent.tcpC2S = newTCPHalfReassembler(w.engine.cfg.TCPPrefixLimit)
			ent.tcpS2C = newTCPHalfReassembler(12288)
			ent.tcpSess = proto.NewTCPSession(meta, snap.compiled, w.engine.cfg.TCPPrefixLimit)
			ent.tcpSess.SetTLSCertProber(w.engine.prober)
		} else {
			ent.udpSess = proto.NewUDPSession(meta, snap.compiled, w.engine.cfg.UDPMaxPackets)
		}
		ent.lruElem = w.lru.PushFront(ent)
		w.streams[ev.StreamID] = ent
		w.engine.pendingStreams.Add(1)
	} else {
		ent.lastSeen = time.Now()
		w.lru.MoveToFront(ent.lruElem)
		if w.engine.prober != nil && w.engine.prober.IsOwnProbe(ent.meta) {
			w.finishEntry(ent, VerdictAcceptStream)
			return VerdictAcceptStream
		}
	}

	if ent.finished {
		return ent.verdict
	}
	ent.pktCount++

	var outcome proto.EvalOutcome
	if pkt.L4Proto == 6 {
		var chunk []byte
		var midStream bool
		if ev.Reverse {
			chunk, midStream = ent.tcpS2C.Push(pkt.TCPSeq, pkt.TCPFlags, pkt.Payload)
		} else {
			chunk, midStream = ent.tcpC2S.Push(pkt.TCPSeq, pkt.TCPFlags, pkt.Payload)
		}
		if midStream {
			// Server replied before client SYN or missing stream start
			w.finishEntry(ent, VerdictAcceptStream)
			return VerdictAcceptStream
		}
		if len(chunk) == 0 {
			if pkt.TCPFlags&(TCPFlagFIN|TCPFlagRST) != 0 || (ent.tcpC2S.Capped() && ent.tcpS2C.Capped()) || ent.pktCount >= 64 {
				w.finishEntry(ent, VerdictAcceptStream)
				return VerdictAcceptStream
			}
			return VerdictAccept
		}
		outcome = ent.tcpSess.Feed(ev.Reverse, chunk)
		if outcome.Decision == proto.DecisionContinue && ((ent.tcpC2S.Capped() && ent.tcpS2C.Capped()) || ent.pktCount >= 64) {
			outcome.Decision = proto.DecisionAllow
		}
	} else {
		outcome = ent.udpSess.Feed(ev.Reverse, pkt.Payload)
	}

	w.recordEvents(snap.raw, ent.meta, outcome.Events)

	switch outcome.Decision {
	case proto.DecisionAllow:
		w.finishEntry(ent, VerdictAcceptStream)
		return VerdictAcceptStream
	case proto.DecisionBlock:
		w.finishEntry(ent, VerdictDropStream)
		return VerdictDropStream
	default:
		return VerdictAccept
	}
}

func (w *worker) finishEntry(ent *streamEntry, v Verdict) {
	ent.finished = true
	ent.verdict = v
	if v == VerdictAcceptStream {
		w.engine.offloadedAccept.Add(1)
	} else if v == VerdictDropStream {
		w.engine.offloadedDrop.Add(1)
		if len(w.recentDrops) >= 2048 {
			clear(w.recentDrops)
		}
		w.recentDrops[ent.streamID] = time.Now()
	}
	// Release evaluator memory immediately; drop entry from pending LRU.
	w.removeEntry(ent)
}

func (w *worker) recordEvents(pol model.Policy, meta proto.FlowMeta, events []proto.MatchResult) {
	if len(events) == 0 {
		return
	}
	tenantStr := meta.TenantIP.String()
	peerStr := meta.PeerIP.String()
	var instID, hostname string
	if w.engine.discovery != nil {
		if inst, ok := w.engine.discovery.Snapshot().LookupByIP(tenantStr); ok {
			instID = inst.ID
			hostname = inst.Hostname
		}
	}

	now := time.Now()
	for _, ev := range events {
		if w.engine.audit != nil {
			auditEv := store.AuditEvent{
				Timestamp:  now,
				TenantIP:   tenantStr,
				InstanceID: instID,
				Hostname:   hostname,
				PeerIP:     peerStr,
				L4Proto:    meta.L4Proto,
				Direction:  string(meta.Direction),
				SrcPort:    meta.SrcPort,
				DstPort:    meta.DstPort,
				HostPort:   meta.HostPort,
				Protocol:   string(ev.Protocol),
				Action:     string(ev.Action),
				Detail:     ev.Detail,
			}
			key := logDedupeKey{tenant: tenantStr, protocol: string(ev.Protocol), action: string(ev.Action)}
			throttled := false
			if w.burstWindow > 0 {
				if prev, ok := w.logDedupe[key]; ok && now.Sub(prev) < w.burstWindow {
					throttled = true
				} else {
					if len(w.logDedupe) >= 256 {
						clear(w.logDedupe)
					}
					w.logDedupe[key] = now
				}
			}
			if throttled {
				w.engine.audit.RecordCountOnly(auditEv)
			} else {
				w.engine.audit.Record(auditEv)
			}
		}
		if ev.Action == model.ActionBlock && w.engine.quarantine != nil {
			w.engine.quarantine.RecordBlock(pol, tenantStr, instID, hostname, string(ev.Protocol)+" "+ev.Detail)
		}
	}
}

func buildFlowMeta(ev PacketEvent, pkt ParsedPacket, disc *runman.Discovery) proto.FlowMeta {
	l4 := "tcp"
	if pkt.L4Proto == 17 {
		l4 = "udp"
	}
	var tenantIP, peerIP net.IP
	var srcPort, dstPort uint16

	// Queue direction + reverse flag uniquely identify which IP belongs to the container.
	if (ev.Direction == proto.DirInbound && !ev.Reverse) || (ev.Direction == proto.DirOutbound && ev.Reverse) {
		tenantIP = cloneIP(pkt.DstIP)
		peerIP = cloneIP(pkt.SrcIP)
	} else {
		tenantIP = cloneIP(pkt.SrcIP)
		peerIP = cloneIP(pkt.DstIP)
	}
	if ev.Reverse {
		srcPort = pkt.DstPort
		dstPort = pkt.SrcPort
	} else {
		srcPort = pkt.SrcPort
		dstPort = pkt.DstPort
	}

	var hostPort uint16
	if ev.Direction == proto.DirInbound && disc != nil {
		hostPort = disc.Snapshot().LookupHostPort(tenantIP.String(), l4, dstPort)
	}

	return proto.FlowMeta{
		L4Proto:   l4,
		Direction: ev.Direction,
		TenantIP:  tenantIP,
		PeerIP:    peerIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		HostPort:  hostPort,
	}
}

func cloneIP(ip net.IP) net.IP {
	cp := make(net.IP, len(ip))
	copy(cp, ip)
	return cp
}
