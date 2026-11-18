package runman

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Instance describes a container discovered read-only from runman-agent state files.
type Instance struct {
	ID       string        `json:"id"`
	Index    uint32        `json:"idx"`
	Hostname string        `json:"hostname"`
	Desired  string        `json:"desired"`
	IPv4     string        `json:"ipv4"`
	IPv6     string        `json:"ipv6,omitempty"`
	CPU      uint32        `json:"cpu"`
	RAMMB    uint64        `json:"ram_mb"`
	Forwards []PortForward `json:"forwards,omitempty"`
}

// PortForward describes a host-to-guest port mapping from portforwards.json.
type PortForward struct {
	VMID        string `json:"vm_id"`
	Proto       string `json:"proto"`
	HostPort    uint16 `json:"host_port"`
	GuestPort   uint16 `json:"guest_port"`
	Description string `json:"description,omitempty"`
}

type rawRecord struct {
	ID       string `json:"id"`
	Idx      uint32 `json:"idx"`
	CPU      uint32 `json:"cpu"`
	RAMMB    uint64 `json:"ram_mb"`
	Hostname string `json:"hostname"`
	Desired  string `json:"desired"`
	Builder  bool   `json:"builder"`
	Addrs    struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	} `json:"addrs"`
}

type forwardKey struct {
	ip        string
	proto     string
	guestPort uint16
}

// Snapshot holds a point-in-time read-only view of runman-agent instances and forwards.
type Snapshot struct {
	Available bool
	UpdatedAt time.Time
	Instances []Instance
	byIP      map[string]Instance
	hostPorts map[forwardKey]uint16
}

// LookupByIP resolves a container IP (IPv4 or IPv6) to its Instance metadata.
func (s *Snapshot) LookupByIP(ip string) (Instance, bool) {
	if s == nil || s.byIP == nil {
		return Instance{}, false
	}
	inst, ok := s.byIP[normalizeIP(ip)]
	return inst, ok
}

// LookupHostPort resolves (tenantIP, proto, guestPort) to the mapped host public port if any.
func (s *Snapshot) LookupHostPort(ip, proto string, guestPort uint16) uint16 {
	if s == nil || s.hostPorts == nil {
		return 0
	}
	return s.hostPorts[forwardKey{
		ip:        normalizeIP(ip),
		proto:     strings.ToLower(proto),
		guestPort: guestPort,
	}]
}

// Discovery periodically reads runman-agent's data directory in read-only mode.
type Discovery struct {
	dataDir string
	mu      sync.RWMutex
	snap    *Snapshot
}

// NewDiscovery creates a Discovery reader for the given runman-agent data directory.
func NewDiscovery(dataDir string) *Discovery {
	d := &Discovery{dataDir: dataDir}
	_ = d.Refresh()
	return d
}

// Refresh reloads instances and portforwards from disk (read-only).
func (d *Discovery) Refresh() error {
	snap := &Snapshot{
		UpdatedAt: time.Now(),
		byIP:      make(map[string]Instance),
		hostPorts: make(map[forwardKey]uint16),
	}
	if d.dataDir == "" {
		d.setSnapshot(snap)
		return nil
	}

	instDir := filepath.Join(d.dataDir, "instances")
	entries, err := os.ReadDir(instDir)
	if err != nil {
		if os.IsNotExist(err) {
			d.setSnapshot(snap)
			return nil
		}
		return err
	}
	snap.Available = true

	forwardsByVM := make(map[string][]PortForward)
	if rawFw, err := os.ReadFile(filepath.Join(d.dataDir, "portforwards.json")); err == nil {
		var fws []PortForward
		if json.Unmarshal(rawFw, &fws) == nil {
			for _, fw := range fws {
				fw.Proto = strings.ToLower(fw.Proto)
				forwardsByVM[fw.VMID] = append(forwardsByVM[fw.VMID], fw)
			}
		}
	}

	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(instDir, ent.Name(), "instance.json"))
		if err != nil {
			continue
		}
		var rec rawRecord
		if json.Unmarshal(raw, &rec) != nil || rec.Builder || rec.ID == "" {
			continue
		}
		inst := Instance{
			ID:       rec.ID,
			Index:    rec.Idx,
			Hostname: rec.Hostname,
			Desired:  rec.Desired,
			IPv4:     normalizeIP(rec.Addrs.IPv4),
			IPv6:     normalizeIP(rec.Addrs.IPv6),
			CPU:      rec.CPU,
			RAMMB:    rec.RAMMB,
			Forwards: forwardsByVM[rec.ID],
		}
		sort.Slice(inst.Forwards, func(i, j int) bool {
			return inst.Forwards[i].HostPort < inst.Forwards[j].HostPort
		})
		snap.Instances = append(snap.Instances, inst)
		if inst.IPv4 != "" {
			snap.byIP[inst.IPv4] = inst
		}
		if inst.IPv6 != "" {
			snap.byIP[inst.IPv6] = inst
		}
		for _, fw := range inst.Forwards {
			if inst.IPv4 != "" {
				snap.hostPorts[forwardKey{ip: inst.IPv4, proto: fw.Proto, guestPort: fw.GuestPort}] = fw.HostPort
			}
			if inst.IPv6 != "" {
				snap.hostPorts[forwardKey{ip: inst.IPv6, proto: fw.Proto, guestPort: fw.GuestPort}] = fw.HostPort
			}
		}
	}

	sort.Slice(snap.Instances, func(i, j int) bool {
		return snap.Instances[i].Index < snap.Instances[j].Index
	})
	d.setSnapshot(snap)
	return nil
}

func (d *Discovery) setSnapshot(s *Snapshot) {
	d.mu.Lock()
	d.snap = s
	d.mu.Unlock()
}

// Snapshot returns the latest cached snapshot.
func (d *Discovery) Snapshot() *Snapshot {
	d.mu.RLock()
	s := d.snap
	d.mu.RUnlock()
	if s == nil {
		return &Snapshot{}
	}
	return s
}

func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}
