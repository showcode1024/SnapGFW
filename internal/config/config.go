package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config defines host daemon startup and runtime tuning settings.
// Policy rules (protocols, ports, domains, limits) live in policy.json and are hot-reloaded.
type Config struct {
	ListenAddr       string `json:"listen_addr"`
	AdminUser        string `json:"admin_user"`
	AdminPassHash    string `json:"admin_pass_hash"`
	DataDir          string `json:"data_dir"`
	RunmanDataDir    string `json:"runman_data_dir"`
	BridgeIface      string `json:"bridge_iface"`
	NftTable         string `json:"nft_table"`
	QueueBase        uint16 `json:"queue_base"`
	ConnMarkAccept   uint32 `json:"conn_mark_accept"`
	ConnMarkDrop     uint32 `json:"conn_mark_drop"`
	Workers          int    `json:"workers"`
	WorkerQueueSize  int    `json:"worker_queue_size"`
	NFQueueLen       uint32 `json:"nfqueue_len"`
	SocketRcvBuf     int    `json:"socket_rcv_buf"`
	MaxPendingPerWkr int    `json:"max_pending_per_worker"`
	TCPPrefixLimit   int    `json:"tcp_prefix_limit"`
	UDPMaxPackets    int    `json:"udp_max_packets"`
	StreamIdleSec    int    `json:"stream_idle_sec"`
	GeoSitePath      string `json:"geosite_path"`
	GeoIPPath        string `json:"geoip_path"`
	LowMemMode       bool   `json:"low_mem_mode"`
}

// Default returns production-safe defaults tailored for a KVM host running runman-agent.
func Default() Config {
	return Config{
		ListenAddr:       "0.0.0.0:9090",
		AdminUser:        "admin",
		DataDir:          "/var/lib/natgfw",
		RunmanDataDir:    "/var/lib/runman-agent",
		BridgeIface:      "rmbr0",
		NftTable:         "natgfw",
		QueueBase:        200,
		ConnMarkAccept:   2001,
		ConnMarkDrop:     2002,
		Workers:          0, // 0 = auto runtime.NumCPU()
		WorkerQueueSize:  256,
		NFQueueLen:       2048,
		SocketRcvBuf:     4 * 1024 * 1024,
		MaxPendingPerWkr: 2048,
		TCPPrefixLimit:   16 * 1024,
		UDPMaxPackets:    6,
		StreamIdleSec:    20,
		GeoSitePath:      "/var/lib/natgfw/geosite.dat",
		GeoIPPath:        "/var/lib/natgfw/geoip.dat",
		LowMemMode:       false,
	}
}

// Normalize fills zero values and enforces safe bounds (including low-memory mode).
func (c *Config) Normalize() {
	def := Default()
	if strings.TrimSpace(c.ListenAddr) == "" {
		c.ListenAddr = def.ListenAddr
	}
	if strings.TrimSpace(c.AdminUser) == "" {
		c.AdminUser = def.AdminUser
	}
	if strings.TrimSpace(c.DataDir) == "" {
		c.DataDir = def.DataDir
	}
	if strings.TrimSpace(c.RunmanDataDir) == "" {
		c.RunmanDataDir = def.RunmanDataDir
	}
	if strings.TrimSpace(c.BridgeIface) == "" {
		c.BridgeIface = def.BridgeIface
	}
	if strings.TrimSpace(c.NftTable) == "" {
		c.NftTable = def.NftTable
	}
	if c.QueueBase == 0 {
		c.QueueBase = def.QueueBase
	}
	if c.ConnMarkAccept == 0 {
		c.ConnMarkAccept = def.ConnMarkAccept
	}
	if c.ConnMarkDrop == 0 {
		c.ConnMarkDrop = def.ConnMarkDrop
	}
	if c.Workers <= 0 {
		c.Workers = max(1, runtime.NumCPU())
	}
	if c.WorkerQueueSize <= 0 {
		c.WorkerQueueSize = def.WorkerQueueSize
	}
	if c.NFQueueLen == 0 {
		c.NFQueueLen = def.NFQueueLen
	}
	if c.SocketRcvBuf <= 0 {
		c.SocketRcvBuf = def.SocketRcvBuf
	}
	if c.MaxPendingPerWkr <= 0 {
		c.MaxPendingPerWkr = def.MaxPendingPerWkr
	}
	if c.TCPPrefixLimit <= 0 {
		c.TCPPrefixLimit = def.TCPPrefixLimit
	}
	if c.UDPMaxPackets <= 0 {
		c.UDPMaxPackets = def.UDPMaxPackets
	}
	if c.StreamIdleSec <= 0 {
		c.StreamIdleSec = def.StreamIdleSec
	}
	if strings.TrimSpace(c.GeoSitePath) == "" {
		c.GeoSitePath = filepath.Join(c.DataDir, "geosite.dat")
	}
	if strings.TrimSpace(c.GeoIPPath) == "" {
		c.GeoIPPath = filepath.Join(c.DataDir, "geoip.dat")
	}
	if c.LowMemMode {
		c.Workers = min(c.Workers, 2)
		c.WorkerQueueSize = min(c.WorkerQueueSize, 128)
		c.NFQueueLen = min(c.NFQueueLen, 1024)
		c.SocketRcvBuf = min(c.SocketRcvBuf, 2*1024*1024)
		c.MaxPendingPerWkr = min(c.MaxPendingPerWkr, 512)
		c.TCPPrefixLimit = min(c.TCPPrefixLimit, 8192)
	}
}

// Validate checks critical invariants before daemon startup.
func (c Config) Validate() error {
	if c.ConnMarkAccept == c.ConnMarkDrop {
		return errors.New("conn_mark_accept and conn_mark_drop must differ")
	}
	if !isSafeIdent(c.BridgeIface) {
		return errors.New("invalid bridge_iface")
	}
	if !isSafeIdent(c.NftTable) {
		return errors.New("invalid nft_table")
	}
	return nil
}

func isSafeIdent(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// Load reads config from path, returning defaults if the file does not exist yet.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg.Normalize()
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Save atomically writes config JSON with 0600 permissions (protects admin_pass_hash).
func Save(path string, cfg Config) error {
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
