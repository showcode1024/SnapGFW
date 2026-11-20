package engine

import (
	"fmt"
	"sync"
	"time"

	"snapgfw/internal/model"
	"snapgfw/internal/netfilter"
	"snapgfw/internal/notify"
	"snapgfw/internal/store"
)

// QuarantinedTenant represents an active temporary kernel ban on a tenant IP.
type QuarantinedTenant struct {
	TenantIP   string    `json:"tenant_ip"`
	InstanceID string    `json:"instance_id,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Reason     string    `json:"reason"`
	BannedAt   time.Time `json:"banned_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// QuarantineManager tracks sliding-window L7 violations per tenant and enforces temporary bans.
type QuarantineManager struct {
	tableName  string
	audit      *store.AuditStore
	notifier   *notify.Notifier
	applyBan   func(tableName, tenantIP string, durationSec int) error
	applyUnban func(tableName, tenantIP string) error

	mu     sync.Mutex
	hits   map[string][]time.Time
	banned map[string]QuarantinedTenant
}

// NewQuarantineManager creates a QuarantineManager bound to an nftables table.
func NewQuarantineManager(tableName string, audit *store.AuditStore, notifier *notify.Notifier) *QuarantineManager {
	return &QuarantineManager{
		tableName:  tableName,
		audit:      audit,
		notifier:   notifier,
		applyBan:   netfilter.QuarantineIP,
		applyUnban: netfilter.UnquarantineIP,
		hits:       make(map[string][]time.Time),
		banned:     make(map[string]QuarantinedTenant),
	}
}

// RecordBlock records a blocked event for tenantIP and triggers auto-quarantine if threshold is reached.
func (q *QuarantineManager) RecordBlock(pol model.Policy, tenantIP, instanceID, hostname, reason string) {
	if tenantIP == "" {
		return
	}
	now := time.Now()
	if pol.Notify.AlertOnBlock && q.notifier != nil {
		q.notifier.Send(
			pol.Notify,
			"block:"+tenantIP,
			"SnapGFW 拦截告警",
			fmt.Sprintf("租户 IP: %s (%s)\n原因: %s", tenantIP, hostname, reason),
			map[string]string{"tenant_ip": tenantIP, "instance_id": instanceID, "reason": reason},
		)
	}

	if !pol.Abuse.AutoQuarantineEnabled {
		return
	}
	threshold := max(pol.Abuse.QuarantineThreshold, 1)
	window := time.Duration(max(pol.Abuse.QuarantineWindowSec, 10)) * time.Second
	durSec := max(pol.Abuse.QuarantineDurationSec, 30)

	q.mu.Lock()
	if cur, ok := q.banned[tenantIP]; ok && cur.ExpiresAt.After(now) {
		q.mu.Unlock()
		return
	}
	cutoff := now.Add(-window)
	arr := q.hits[tenantIP]
	kept := arr[:0]
	for _, ts := range arr {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	q.hits[tenantIP] = kept
	shouldBan := len(kept) >= threshold
	if shouldBan {
		delete(q.hits, tenantIP)
	}
	q.mu.Unlock()

	if shouldBan {
		_ = q.Ban(tenantIP, instanceID, hostname, fmt.Sprintf("%d次违规(%s)", threshold, reason), durSec, pol.Abuse.FlushConntrackOnBlock, pol.Notify)
	}
}

// Ban adds tenantIP to the kernel quarantine set and emits an audit event + alert.
func (q *QuarantineManager) Ban(tenantIP, instanceID, hostname, reason string, durationSec int, flushCt bool, notifyCfg model.NotifyConfig) error {
	if q.applyBan != nil {
		if err := q.applyBan(q.tableName, tenantIP, durationSec); err != nil {
			return err
		}
	}
	if flushCt {
		netfilter.FlushConntrackForIP(tenantIP)
	}
	now := time.Now()
	entry := QuarantinedTenant{
		TenantIP:   tenantIP,
		InstanceID: instanceID,
		Hostname:   hostname,
		Reason:     reason,
		BannedAt:   now,
		ExpiresAt:  now.Add(time.Duration(max(durationSec, 10)) * time.Second),
	}
	q.mu.Lock()
	q.banned[tenantIP] = entry
	q.mu.Unlock()

	if q.audit != nil {
		q.audit.Record(store.AuditEvent{
			Timestamp:  now,
			TenantIP:   tenantIP,
			InstanceID: instanceID,
			Hostname:   hostname,
			Protocol:   "quarantine",
			Action:     "quarantine",
			Detail:     fmt.Sprintf("%s (%ds)", reason, durationSec),
		})
	}
	if notifyCfg.AlertOnBan && q.notifier != nil {
		q.notifier.Send(
			notifyCfg,
			"ban:"+tenantIP,
			"SnapGFW 自动熔断隔离",
			fmt.Sprintf("租户 IP: %s (%s)\n原因: %s\n隔离时长: %d 秒", tenantIP, hostname, reason, durationSec),
			entry,
		)
	}
	return nil
}

// Unban removes tenantIP from kernel quarantine immediately.
func (q *QuarantineManager) Unban(tenantIP string) error {
	if q.applyUnban != nil {
		if err := q.applyUnban(q.tableName, tenantIP); err != nil {
			return err
		}
	}
	q.mu.Lock()
	delete(q.banned, tenantIP)
	delete(q.hits, tenantIP)
	q.mu.Unlock()
	return nil
}

// ListActive returns currently non-expired quarantined tenants.
func (q *QuarantineManager) ListActive() []QuarantinedTenant {
	now := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]QuarantinedTenant, 0, len(q.banned))
	for k, v := range q.banned {
		if !v.ExpiresAt.After(now) {
			delete(q.banned, k)
			continue
		}
		out = append(out, v)
	}
	return out
}

// ReapplyActive re-inserts all non-expired quarantined tenants into the kernel nftables set
// after a full table reload (e.g., policy update or bridge switch) so bans are never lost.
func (q *QuarantineManager) ReapplyActive() error {
	if q == nil || q.applyBan == nil {
		return nil
	}
	active := q.ListActive()
	var firstErr error
	now := time.Now()
	for _, item := range active {
		rem := int(item.ExpiresAt.Sub(now).Seconds())
		if rem < 1 {
			continue
		}
		if err := q.applyBan(q.tableName, item.TenantIP, rem); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
