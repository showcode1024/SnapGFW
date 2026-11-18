package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuditEvent captures one DPI detection or L4/quarantine enforcement event.
type AuditEvent struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"ts"`
	TenantIP   string    `json:"tenant_ip"`
	InstanceID string    `json:"instance_id,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	PeerIP     string    `json:"peer_ip"`
	L4Proto    string    `json:"l4"`       // tcp | udp
	Direction  string    `json:"dir"`      // in | out
	SrcPort    uint16    `json:"src_port"` // Client port
	DstPort    uint16    `json:"dst_port"` // Guest/target port
	HostPort   uint16    `json:"host_port,omitempty"`
	Protocol   string    `json:"protocol"` // ProtoID or "quarantine"
	Action     string    `json:"action"`   // block | log | quarantine
	Detail     string    `json:"detail,omitempty"`
}

// TenantStats summarizes violations for one tenant IP.
type TenantStats struct {
	TenantIP     string         `json:"tenant_ip"`
	InstanceID   string         `json:"instance_id,omitempty"`
	Hostname     string         `json:"hostname,omitempty"`
	BlockCount   int64          `json:"block_count"`
	LogCount     int64          `json:"log_count"`
	LastSeen     time.Time      `json:"last_seen"`
	LastProtocol string         `json:"last_protocol"`
	ByProtocol   map[string]int `json:"by_protocol"`
}

const (
	defaultRingCap    = 200
	defaultMaxFileSz  = 2 * 1024 * 1024 // 2 MiB active + 1 rotated backup = <= 4 MiB ROM
	maxDetailBytes    = 128
	maxTenantStatsCap = 512
)

// AuditStore maintains a tiny bounded in-memory ring buffer, size-capped JSONL file,
// per-tenant counters, and live SSE subscribers.
type AuditStore struct {
	logPath    string
	maxFileSz  int64
	ringCap    int
	mu         sync.RWMutex
	ring       []AuditEvent
	nextID     atomic.Int64
	byTenant   map[string]*TenantStats
	byProto    map[string]int64
	totalBlock atomic.Int64
	totalLog   atomic.Int64
	subsMu     sync.Mutex
	subs       map[chan AuditEvent]struct{}
	file       *os.File
	fileSize   int64
}

// NewAuditStore initializes an AuditStore with bounded ring buffer and size-capped JSONL persistence.
// Passing maxFileBytes == 0 disables disk logging completely; < 0 uses the 2 MiB default.
func NewAuditStore(logPath string, ringCap int, maxFileBytes int64) (*AuditStore, error) {
	if ringCap <= 0 {
		ringCap = defaultRingCap
	}
	if maxFileBytes < 0 {
		maxFileBytes = defaultMaxFileSz
	}
	as := &AuditStore{
		logPath:   logPath,
		maxFileSz: maxFileBytes,
		ringCap:   ringCap,
		ring:      make([]AuditEvent, 0, min(ringCap, 64)),
		byTenant:  make(map[string]*TenantStats),
		byProto:   make(map[string]int64),
		subs:      make(map[chan AuditEvent]struct{}),
	}
	if logPath != "" && maxFileBytes > 0 {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
			return nil, err
		}
		as.loadRecentFromDisk()
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		if st, err := f.Stat(); err == nil {
			as.fileSize = st.Size()
		}
		as.file = f
	}
	return as, nil
}

// RingCap returns the configured in-memory event buffer cap.
func (a *AuditStore) RingCap() int { return a.ringCap }

// MaxDiskBytes returns the maximum combined bytes used on disk (active + 1 backup).
func (a *AuditStore) MaxDiskBytes() int64 {
	if a.file == nil && a.logPath == "" {
		return 0
	}
	if a.maxFileSz <= 0 {
		return 0
	}
	return a.maxFileSz * 2
}

func truncateDetail(s string) string {
	if len(s) <= maxDetailBytes {
		return s
	}
	return s[:maxDetailBytes]
}

func (a *AuditStore) loadRecentFromDisk() {
	f, err := os.Open(a.logPath)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4*1024), 16*1024)
	for sc.Scan() {
		var ev AuditEvent
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			ev.Detail = truncateDetail(ev.Detail)
			a.appendLocked(ev, false, true)
			if ev.ID > a.nextID.Load() {
				a.nextID.Store(ev.ID)
			}
		}
	}
}

// Close closes the backing audit log file.
func (a *AuditStore) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		err := a.file.Close()
		a.file = nil
		return err
	}
	return nil
}

// Record stores an audit event, updates counters, persists to capped JSONL, and fans out to SSE listeners.
func (a *AuditStore) Record(ev AuditEvent) AuditEvent {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	ev.ID = a.nextID.Add(1)
	ev.Detail = truncateDetail(ev.Detail)

	a.mu.Lock()
	a.appendLocked(ev, true, true)
	a.mu.Unlock()

	a.subsMu.Lock()
	for ch := range a.subs {
		select {
		case ch <- ev:
		default: // Drop if subscriber is slow; never block packet workers
		}
	}
	a.subsMu.Unlock()
	return ev
}

// RecordCountOnly increments aggregate counters for burst-throttled duplicate events
// without allocating ring entries, writing to disk, or flooding SSE clients.
func (a *AuditStore) RecordCountOnly(ev AuditEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	a.mu.Lock()
	a.appendLocked(ev, false, false)
	a.mu.Unlock()
}

func (a *AuditStore) appendLocked(ev AuditEvent, writeDisk bool, storeRing bool) {
	if storeRing {
		if len(a.ring) >= a.ringCap {
			copy(a.ring, a.ring[1:])
			a.ring[len(a.ring)-1] = ev
		} else {
			a.ring = append(a.ring, ev)
		}
	}

	if ev.Action == "block" || ev.Action == "quarantine" {
		a.totalBlock.Add(1)
	} else {
		a.totalLog.Add(1)
	}
	a.byProto[ev.Protocol]++

	if ev.TenantIP != "" {
		ts := a.byTenant[ev.TenantIP]
		if ts == nil {
			if len(a.byTenant) >= maxTenantStatsCap {
				a.evictOldestTenantLocked()
			}
			ts = &TenantStats{
				TenantIP:   ev.TenantIP,
				ByProtocol: make(map[string]int),
			}
			a.byTenant[ev.TenantIP] = ts
		}
		if ev.InstanceID != "" {
			ts.InstanceID = ev.InstanceID
		}
		if ev.Hostname != "" {
			ts.Hostname = ev.Hostname
		}
		if ev.Action == "block" || ev.Action == "quarantine" {
			ts.BlockCount++
		} else {
			ts.LogCount++
		}
		ts.LastSeen = ev.Timestamp
		ts.LastProtocol = ev.Protocol
		ts.ByProtocol[ev.Protocol]++
	}

	if writeDisk && a.file != nil && a.maxFileSz > 0 {
		line, err := json.Marshal(ev)
		if err == nil {
			line = append(line, '\n')
			n, _ := a.file.Write(line)
			a.fileSize += int64(n)
			if a.fileSize >= a.maxFileSz {
				_ = a.file.Close()
				_ = os.Rename(a.logPath, a.logPath+".1")
				if nf, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
					a.file = nf
					a.fileSize = 0
				} else {
					a.file = nil
				}
			}
		}
	}
}

func (a *AuditStore) evictOldestTenantLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, v := range a.byTenant {
		if oldestKey == "" || v.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.LastSeen
		}
	}
	if oldestKey != "" {
		delete(a.byTenant, oldestKey)
	}
}

// Query filters recent audit events in reverse chronological order.
func (a *AuditStore) Query(tenantIP, protocol, action, q string, limit int) []AuditEvent {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q = strings.ToLower(strings.TrimSpace(q))
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]AuditEvent, 0, min(limit, len(a.ring)))
	for i := len(a.ring) - 1; i >= 0; i-- {
		ev := a.ring[i]
		if tenantIP != "" && ev.TenantIP != tenantIP {
			continue
		}
		if protocol != "" && ev.Protocol != protocol {
			continue
		}
		if action != "" && ev.Action != action {
			continue
		}
		if q != "" {
			hay := strings.ToLower(ev.TenantIP + " " + ev.PeerIP + " " + ev.Protocol + " " + ev.Detail + " " + ev.Hostname)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// TenantSnapshot returns a copy of per-tenant counters.
func (a *AuditStore) TenantSnapshot() map[string]TenantStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make(map[string]TenantStats, len(a.byTenant))
	for k, v := range a.byTenant {
		cp := *v
		cp.ByProtocol = make(map[string]int, len(v.ByProtocol))
		for pk, pv := range v.ByProtocol {
			cp.ByProtocol[pk] = pv
		}
		out[k] = cp
	}
	return out
}

// Totals returns total block/log counts and per-protocol counts.
func (a *AuditStore) Totals() (blocks, logs int64, byProto map[string]int64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	byProto = make(map[string]int64, len(a.byProto))
	for k, v := range a.byProto {
		byProto[k] = v
	}
	return a.totalBlock.Load(), a.totalLog.Load(), byProto
}

// Subscribe registers a non-blocking channel for live SSE audit events.
func (a *AuditStore) Subscribe() (<-chan AuditEvent, func()) {
	ch := make(chan AuditEvent, 16)
	a.subsMu.Lock()
	a.subs[ch] = struct{}{}
	a.subsMu.Unlock()
	cancel := func() {
		a.subsMu.Lock()
		if _, ok := a.subs[ch]; ok {
			delete(a.subs, ch)
			close(ch)
		}
		a.subsMu.Unlock()
	}
	return ch, cancel
}
