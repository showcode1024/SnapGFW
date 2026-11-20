package runman

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

// Snapshot holds a point-in-time read-only view of discovered container instances and forwards.
type Snapshot struct {
	Available bool
	Source    string // "runman" | "podman" | "docker"
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

// Discovery periodically reads runman-agent's data directory or local Podman/Docker sockets (read-only).
type Discovery struct {
	dataDir     string
	socketPaths []string
	mu          sync.RWMutex
	snap        *Snapshot
}

// NewDiscovery creates a Discovery reader for runman-agent with automatic Podman/Docker socket fallback.
func NewDiscovery(dataDir string) *Discovery {
	d := &Discovery{
		dataDir:     dataDir,
		socketPaths: []string{"/run/podman/podman.sock", "/var/run/docker.sock"},
	}
	_ = d.Refresh()
	return d
}

// Refresh reloads instances and portforwards from disk or local Podman/Docker socket (read-only).
func (d *Discovery) Refresh() error {
	snap := &Snapshot{
		UpdatedAt: time.Now(),
		byIP:      make(map[string]Instance),
		hostPorts: make(map[forwardKey]uint16),
	}
	if d.dataDir != "" {
		instDir := filepath.Join(d.dataDir, "instances")
		entries, err := os.ReadDir(instDir)
		if err == nil {
			snap.Available = true
			snap.Source = "runman"
			d.loadRunman(snap, instDir, entries)
			d.setSnapshot(snap)
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
	}

	// Fallback: query local Podman or Docker Unix socket (rate-limited to 5s to keep UI polls lightweight).
	if prev := d.Snapshot(); prev != nil && (prev.Source == "podman" || prev.Source == "docker") && time.Since(prev.UpdatedAt) < 5*time.Second {
		return nil
	}
	if runtime.GOOS == "linux" {
		for _, sock := range d.socketPaths {
			if st, err := os.Stat(sock); err != nil || st.IsDir() {
				continue
			}
			insts, err := queryContainerSocket(sock)
			if err != nil {
				continue
			}
			snap.Available = true
			if strings.Contains(sock, "podman") {
				snap.Source = "podman"
			} else {
				snap.Source = "docker"
			}
			for _, inst := range insts {
				snap.Instances = append(snap.Instances, inst)
				if inst.IPv4 != "" {
					snap.byIP[inst.IPv4] = inst
				}
				if inst.IPv6 != "" {
					snap.byIP[inst.IPv6] = inst
				}
			}
			d.setSnapshot(snap)
			return nil
		}
	}
	d.setSnapshot(snap)
	return nil
}

func (d *Discovery) loadRunman(snap *Snapshot, instDir string, entries []os.DirEntry) {
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
}

func queryContainerSocket(sockPath string) ([]Instance, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", sockPath)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get("http://unix/v1.40/containers/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, io.ErrUnexpectedEOF
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	return ParseContainerListJSON(body)
}

// ParseContainerListJSON decodes Docker/Podman compatible `/containers/json` responses into Instance records.
func ParseContainerListJSON(raw []byte) ([]Instance, error) {
	var items []struct {
		ID              string   `json:"Id"`
		Names           []string `json:"Names"`
		State           string   `json:"State"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress         string `json:"IPAddress"`
				GlobalIPv6Address string `json:"GlobalIPv6Address"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	out := make([]Instance, 0, len(items))
	for i, c := range items {
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		name := shortID
		if len(c.Names) > 0 {
			trimmed := strings.TrimPrefix(strings.TrimSpace(c.Names[0]), "/")
			if trimmed != "" {
				name = trimmed
			}
		}
		var ipv4, ipv6 string
		// Sort network names for deterministic IP extraction
		netNames := make([]string, 0, len(c.NetworkSettings.Networks))
		for k := range c.NetworkSettings.Networks {
			netNames = append(netNames, k)
		}
		sort.Strings(netNames)
		for _, nk := range netNames {
			nw := c.NetworkSettings.Networks[nk]
			if ipv4 == "" && nw.IPAddress != "" {
				ipv4 = normalizeIP(nw.IPAddress)
			}
			if ipv6 == "" && nw.GlobalIPv6Address != "" {
				ipv6 = normalizeIP(nw.GlobalIPv6Address)
			}
		}
		if ipv4 == "" && ipv6 == "" {
			continue
		}
		out = append(out, Instance{
			ID:       shortID,
			Index:    uint32(i + 1),
			Hostname: name,
			Desired:  c.State,
			IPv4:     ipv4,
			IPv6:     ipv6,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IPv4 < out[j].IPv4
	})
	return out, nil
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
