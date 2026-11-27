package web

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"snapgfw/internal/config"
	"snapgfw/internal/engine"
	"snapgfw/internal/geo"
	"snapgfw/internal/model"
	"snapgfw/internal/netfilter"
	"snapgfw/internal/notify"
	"snapgfw/internal/runman"
	"snapgfw/internal/store"
	"snapgfw/internal/updater"
)

//go:embed ui.html
var uiHTML []byte

//go:embed favicon.svg
var faviconSVG []byte

const (
	sessionCookieName = "snapgfw_session"
	sessionTTL        = 12 * time.Hour
	loginWindow       = 10 * time.Minute
	loginMaxFailures  = 5
)

// Server provides the embedded Web UI and management REST APIs.
type Server struct {
	cfgPath    string
	cfgMu      sync.RWMutex
	cfg        config.Config
	policy     *store.PolicyStore
	audit      *store.AuditStore
	engine     *engine.Engine
	discovery  *runman.Discovery
	quarantine *engine.QuarantineManager
	notifier      *notify.Notifier
	updater       *updater.Updater
	applyConfigFn func(config.Config, model.Policy) error

	authMu   sync.Mutex
	sessions map[string]time.Time
	failures map[string][]time.Time
}

// NewServer constructs the Web UI and API server.
func NewServer(
	cfgPath string,
	cfg config.Config,
	policy *store.PolicyStore,
	audit *store.AuditStore,
	eng *engine.Engine,
	disc *runman.Discovery,
	qm *engine.QuarantineManager,
	notif *notify.Notifier,
) *Server {
	return &Server{
		cfgPath:    cfgPath,
		cfg:        cfg,
		policy:     policy,
		audit:      audit,
		engine:     eng,
		discovery:  disc,
		quarantine: qm,
		notifier:   notif,
		updater:    updater.New("dev", nil),
		sessions:   make(map[string]time.Time),
		failures:   make(map[string][]time.Time),
	}
}

// SetUpdater attaches a custom release updater to the server.
func (s *Server) SetUpdater(u *updater.Updater) {
	if u != nil {
		s.updater = u
	}
}

// SetApplyConfigHook registers the runtime nftables/engine re-applier invoked on config changes.
func (s *Server) SetApplyConfigHook(fn func(config.Config, model.Policy) error) {
	s.applyConfigFn = fn
}

// Config returns a thread-safe snapshot of the current runtime configuration.
func (s *Server) Config() config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

func (s *Server) currentVersion() string {
	if s.updater != nil && s.updater.CurrentVersion() != "" {
		return s.updater.CurrentVersion()
	}
	return "dev"
}

// Handler builds the complete HTTP router with auth, CSRF, and security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleUI)
	mux.HandleFunc("GET /favicon.svg", s.handleFavicon)
	mux.HandleFunc("GET /favicon.ico", s.handleFavicon)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.requireAuth(false, s.handleLogout))

	mux.HandleFunc("GET /api/overview", s.requireAuth(false, s.handleOverview))
	mux.HandleFunc("GET /api/policy", s.requireAuth(false, s.handleGetPolicy))
	mux.HandleFunc("PUT /api/policy", s.requireAuth(true, s.handlePutPolicy))
	mux.HandleFunc("GET /api/presets", s.requireAuth(false, s.handleListPresets))
	mux.HandleFunc("POST /api/presets/{id}/apply", s.requireAuth(true, s.handleApplyPreset))
	mux.HandleFunc("GET /api/policy/export", s.requireAuth(false, s.handleExportPolicy))
	mux.HandleFunc("POST /api/policy/import", s.requireAuth(true, s.handleImportPolicy))
	mux.HandleFunc("POST /api/bypass", s.requireAuth(true, s.handleToggleBypass))

	mux.HandleFunc("GET /api/instances", s.requireAuth(false, s.handleInstances))
	mux.HandleFunc("GET /api/quarantine", s.requireAuth(false, s.handleListQuarantine))
	mux.HandleFunc("POST /api/quarantine/ban", s.requireAuth(true, s.handleBan))
	mux.HandleFunc("POST /api/quarantine/unban", s.requireAuth(true, s.handleUnban))

	mux.HandleFunc("GET /api/logs", s.requireAuth(false, s.handleLogs))
	mux.HandleFunc("GET /api/logs/stream", s.requireAuth(false, s.handleLogsStream))

	mux.HandleFunc("POST /api/geo/download", s.requireAuth(true, s.handleGeoDownload))
	mux.HandleFunc("POST /api/settings/network", s.requireAuth(true, s.handleUpdateNetwork))
	mux.HandleFunc("POST /api/settings/password", s.requireAuth(true, s.handleChangePassword))
	mux.HandleFunc("POST /api/notify/test", s.requireAuth(true, s.handleNotifyTest))
	mux.HandleFunc("GET /api/system/update", s.requireAuth(false, s.handleCheckUpdate))
	mux.HandleFunc("POST /api/system/update", s.requireAuth(true, s.handleApplyUpdate))

	return withSecurityHeaders(mux)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(csrfCheck bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if csrfCheck && r.Header.Get("X-Snapgfw") != "1" {
			writeErr(w, http.StatusForbidden, "missing X-Snapgfw header")
			return
		}
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !s.validSession(cookie.Value) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (s *Server) validSession(token string) bool {
	if token == "" {
		return false
	}
	now := time.Now()
	s.authMu.Lock()
	defer s.authMu.Unlock()
	for k, exp := range s.sessions {
		if !exp.After(now) {
			delete(s.sessions, k)
		}
	}
	exp, ok := s.sessions[token]
	if !ok || !exp.After(now) {
		return false
	}
	s.sessions[token] = now.Add(sessionTTL)
	return true
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconSVG)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ipKey := clientIPKey(r.RemoteAddr)
	now := time.Now()

	s.authMu.Lock()
	recent := s.failures[ipKey]
	kept := recent[:0]
	for _, ts := range recent {
		if now.Sub(ts) < loginWindow {
			kept = append(kept, ts)
		}
	}
	s.failures[ipKey] = kept
	if len(kept) >= loginMaxFailures {
		s.authMu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	s.authMu.Unlock()

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.cfgMu.RLock()
	wantUser := s.cfg.AdminUser
	passHash := s.cfg.AdminPassHash
	s.cfgMu.RUnlock()

	ok := req.Username == wantUser && passHash != "" && bcrypt.CompareHashAndPassword([]byte(passHash), []byte(req.Password)) == nil
	if !ok {
		s.authMu.Lock()
		if len(s.failures) > 4096 {
			for k, arr := range s.failures {
				if len(arr) == 0 || now.Sub(arr[len(arr)-1]) >= loginWindow {
					delete(s.failures, k)
				}
			}
			if len(s.failures) > 4096 {
				clear(s.failures)
			}
		}
		s.failures[ipKey] = append(s.failures[ipKey], now)
		s.authMu.Unlock()
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	var raw [32]byte
	_, _ = rand.Read(raw[:])
	token := hex.EncodeToString(raw[:])

	s.authMu.Lock()
	delete(s.failures, ipKey)
	if len(s.sessions) >= 128 {
		var oldestKey string
		var oldestExp time.Time
		for k, exp := range s.sessions {
			if !exp.After(now) {
				delete(s.sessions, k)
				continue
			}
			if oldestKey == "" || exp.Before(oldestExp) {
				oldestKey = k
				oldestExp = exp
			}
		}
		if len(s.sessions) >= 128 && oldestKey != "" {
			delete(s.sessions, oldestKey)
		}
	}
	s.sessions[token] = now.Add(sessionTTL)
	s.authMu.Unlock()

	isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": wantUser})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		s.authMu.Lock()
		delete(s.sessions, c.Value)
		s.authMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	pol := s.policy.Get()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	blocks, logs, byProto := s.audit.Totals()
	var engStats engine.Stats
	var geoFallback bool
	if s.engine != nil {
		engStats = s.engine.Stats()
		geoFallback = s.engine.GeoFallback()
	}

	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	_, gsErr := os.Stat(cfg.GeoSitePath)
	_, giErr := os.Stat(cfg.GeoIPPath)

	var runmanAvail bool
	var instCount int
	if s.discovery != nil {
		_ = s.discovery.Refresh()
		snap := s.discovery.Snapshot()
		runmanAvail = snap.Available
		instCount = len(snap.Instances)
	}
	var qCount int
	if s.quarantine != nil {
		qCount = len(s.quarantine.ListActive())
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":            s.currentVersion(),
		"active_preset":      pol.ActivePreset,
		"global_bypass":      pol.GlobalBypass,
		"bridge_iface":       cfg.BridgeIface,
		"bridge_present":     netfilter.BridgeExists(cfg.BridgeIface),
		"available_bridges":  netfilter.ListBridges(),
		"host_proxy_compat":  !cfg.DisableHostProxy,
		"nft_table":          cfg.NftTable,
		"engine":             engStats,
		"l4_stats":           netfilter.ReadL4Stats(cfg.NftTable, cfg.ConnMarkDrop),
		"audit_blocks":       blocks,
		"audit_logs":         logs,
		"by_protocol":        byProto,
		"quarantine_count":   qCount,
		"runman_available":   runmanAvail,
		"instance_count":     instCount,
		"geosite_present":    gsErr == nil,
		"geoip_present":      giErr == nil,
		"geo_fallback":       geoFallback,
		"heap_alloc_mb":      float64(mem.HeapAlloc) / (1024 * 1024),
		"sys_mem_mb":         float64(mem.Sys) / (1024 * 1024),
		"low_mem_mode":       cfg.LowMemMode,
		"audit_ring_cap":     s.audit.RingCap(),
		"audit_max_disk_mb":  float64(s.audit.MaxDiskBytes()) / (1024 * 1024),
	})
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.policy.Get())
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var next model.Policy
	if err := json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024)).Decode(&next); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid policy JSON: "+err.Error())
		return
	}
	if err := s.policy.Update(next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.policy.Get())
}

func (s *Server) handleListPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.ListPresets())
}

func (s *Server) handleApplyPreset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pol, err := s.policy.ApplyPreset(id, true)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) handleExportPolicy(w http.ResponseWriter, r *http.Request) {
	pol := s.policy.Get()
	raw, _ := json.MarshalIndent(pol, "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="snapgfw-policy.json"`)
	_, _ = w.Write(append(raw, '\n'))
}

func (s *Server) handleImportPolicy(w http.ResponseWriter, r *http.Request) {
	s.handlePutPolicy(w, r)
}

func (s *Server) handleToggleBypass(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GlobalBypass bool `json:"global_bypass"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cur := s.policy.Get()
	cur.GlobalBypass = req.GlobalBypass
	if err := s.policy.Update(cur); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	var instances []runman.Instance
	var avail bool
	if s.discovery != nil {
		_ = s.discovery.Refresh()
		snap := s.discovery.Snapshot()
		avail = snap.Available
		instances = snap.Instances
	}
	statsMap := s.audit.TenantSnapshot()
	qMap := make(map[string]engine.QuarantinedTenant)
	if s.quarantine != nil {
		for _, q := range s.quarantine.ListActive() {
			qMap[q.TenantIP] = q
		}
	}

	type instanceRow struct {
		runman.Instance
		Stats       *store.TenantStats        `json:"stats,omitempty"`
		Quarantined *engine.QuarantinedTenant `json:"quarantined,omitempty"`
	}

	seenIP := make(map[string]bool)
	rows := make([]instanceRow, 0, len(instances)+len(statsMap))
	for _, inst := range instances {
		row := instanceRow{Instance: inst}
		if st, ok := statsMap[inst.IPv4]; ok {
			stCopy := st
			row.Stats = &stCopy
		}
		if q, ok := qMap[inst.IPv4]; ok {
			qCopy := q
			row.Quarantined = &qCopy
		}
		if inst.IPv4 != "" {
			seenIP[inst.IPv4] = true
		}
		rows = append(rows, row)
	}
	// Also append any observed tenant IPs not found in runman-agent (e.g. IPv6 or custom subnets)
	for ip, st := range statsMap {
		if seenIP[ip] {
			continue
		}
		stCopy := st
		row := instanceRow{
			Instance: runman.Instance{
				ID:       st.InstanceID,
				Hostname: st.Hostname,
				IPv4:     ip,
			},
			Stats: &stCopy,
		}
		if q, ok := qMap[ip]; ok {
			qCopy := q
			row.Quarantined = &qCopy
		}
		rows = append(rows, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runman_available": avail,
		"instances":        rows,
	})
}

func (s *Server) handleListQuarantine(w http.ResponseWriter, r *http.Request) {
	var list []engine.QuarantinedTenant
	if s.quarantine != nil {
		list = s.quarantine.ListActive()
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantIP    string `json:"tenant_ip"`
		Reason      string `json:"reason"`
		DurationSec int    `json:"duration_sec"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if net.ParseIP(strings.TrimSpace(req.TenantIP)) == nil {
		writeErr(w, http.StatusBadRequest, "invalid tenant_ip")
		return
	}
	if req.DurationSec <= 0 {
		req.DurationSec = 600
	}
	if req.Reason == "" {
		req.Reason = "管理员手动隔离"
	}
	var instID, hostname string
	if s.discovery != nil {
		if inst, ok := s.discovery.Snapshot().LookupByIP(req.TenantIP); ok {
			instID = inst.ID
			hostname = inst.Hostname
		}
	}
	if s.quarantine == nil {
		writeErr(w, http.StatusServiceUnavailable, "quarantine manager unavailable")
		return
	}
	pol := s.policy.Get()
	if err := s.quarantine.Ban(req.TenantIP, instID, hostname, req.Reason, req.DurationSec, pol.Abuse.FlushConntrackOnBlock, pol.Notify); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantIP string `json:"tenant_ip"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if s.quarantine == nil {
		writeErr(w, http.StatusServiceUnavailable, "quarantine manager unavailable")
		return
	}
	if err := s.quarantine.Unban(req.TenantIP); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	events := s.audit.Query(q.Get("tenant_ip"), q.Get("protocol"), q.Get("action"), q.Get("q"), 200)
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := s.audit.Subscribe()
	defer cancel()

	// Send initial keepalive
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			b, err := json.Marshal(ev)
			if err == nil {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			}
		case <-heartbeat.C:
			_, _ = fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleGeoDownload(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	gsPath := s.cfg.GeoSitePath
	giPath := s.cfg.GeoIPPath
	s.cfgMu.RUnlock()

	client := &http.Client{Timeout: 60 * time.Second}
	dl := func(url, dst string, validate func(tmpPath string) error) error {
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("http %d downloading %s", resp.StatusCode, url)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		tmp := dst + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, io.LimitReader(resp.Body, 64*1024*1024))
		closeErr := f.Close()
		if copyErr != nil {
			_ = os.Remove(tmp)
			return copyErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		if validate != nil {
			if err := validate(tmp); err != nil {
				_ = os.Remove(tmp)
				return err
			}
		}
		return os.Rename(tmp, dst)
	}

	const gsURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	const giURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

	if err := dl(gsURL, gsPath, func(p string) error {
		m, err := geo.LoadGeoSiteCats(p, []string{"CN"})
		if err != nil || len(m["CN"]) == 0 {
			return fmt.Errorf("downloaded geosite.dat failed integrity check")
		}
		return nil
	}); err != nil {
		writeErr(w, http.StatusBadGateway, "geosite download failed: "+err.Error())
		return
	}
	if err := dl(giURL, giPath, func(p string) error {
		m, err := geo.LoadGeoIPCountries(p, []string{"CN"})
		if err != nil || len(m["CN"]) == 0 {
			return fmt.Errorf("downloaded geoip.dat failed integrity check")
		}
		return nil
	}); err != nil {
		writeErr(w, http.StatusBadGateway, "geoip download failed: "+err.Error())
		return
	}

	// Re-apply active policy so engine & nft reload newly downloaded Geo files
	if err := s.policy.Update(s.policy.Get()); err != nil {
		writeErr(w, http.StatusInternalServerError, "reloading geo data failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(req.Password) < 6 {
		writeErr(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.cfgMu.Lock()
	s.cfg.AdminPassHash = string(hash)
	cfgCopy := s.cfg
	s.cfgMu.Unlock()

	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, cfgCopy); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	// Invalidate all existing sessions except current cookie if present
	var keep string
	if c, err := r.Cookie(sessionCookieName); err == nil {
		keep = c.Value
	}
	s.authMu.Lock()
	for k := range s.sessions {
		if k != keep {
			delete(s.sessions, k)
		}
	}
	s.authMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BridgeIface     string `json:"bridge_iface"`
		HostProxyCompat *bool  `json:"host_proxy_compat"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	br := strings.TrimSpace(req.BridgeIface)
	if br == "" {
		writeErr(w, http.StatusBadRequest, "bridge_iface is required")
		return
	}

	s.cfgMu.RLock()
	nextCfg := s.cfg
	s.cfgMu.RUnlock()

	nextCfg.BridgeIface = br
	if req.HostProxyCompat != nil {
		nextCfg.DisableHostProxy = !*req.HostProxyCompat
	}
	if err := nextCfg.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.applyConfigFn != nil {
		if err := s.applyConfigFn(nextCfg, s.policy.Get()); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, nextCfg); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.cfgMu.Lock()
	s.cfg = nextCfg
	s.cfgMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"bridge_iface":      nextCfg.BridgeIface,
		"bridge_present":    netfilter.BridgeExists(nextCfg.BridgeIface),
		"available_bridges": netfilter.ListBridges(),
		"host_proxy_compat": !nextCfg.DisableHostProxy,
	})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		writeErr(w, http.StatusServiceUnavailable, "notifier unavailable")
		return
	}
	pol := s.policy.Get()
	if pol.Notify.WebhookURL == "" && (pol.Notify.TelegramToken == "" || pol.Notify.TelegramChatID == "") {
		writeErr(w, http.StatusBadRequest, "请先保存 Webhook URL 或 Telegram 配置")
		return
	}
	if err := s.notifier.SendSync(pol.Notify, "SnapGFW 测试告警", "这是一条来自 SnapGFW 防火墙面板的测试通知。", map[string]string{"status": "ok"}); err != nil {
		writeErr(w, http.StatusBadGateway, "测试通知发送失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updater == nil {
		writeErr(w, http.StatusServiceUnavailable, "updater unavailable")
		return
	}
	force := r.URL.Query().Get("refresh") == "1"
	writeJSON(w, http.StatusOK, s.updater.Check(r.Context(), force))
}

func (s *Server) handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updater == nil {
		writeErr(w, http.StatusServiceUnavailable, "updater unavailable")
		return
	}
	info, err := s.updater.ApplyUpdate(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"latest_version": info.LatestVersion,
		"restarting":     true,
	})
}

// ReapplyAll compiles and applies the given policy to both DPI engine and nftables.
func ApplyPolicyRuntime(cfg config.Config, pol model.Policy, eng *engine.Engine) error {
	script, err := netfilter.RenderNFT(cfg, pol)
	if err != nil {
		return err
	}
	if err := netfilter.ApplyNFT(script); err != nil {
		return err
	}
	if eng != nil {
		eng.UpdatePolicy(pol)
	}
	if pol.Abuse.FlushConntrackOnBlock {
		for _, r := range pol.PortRules {
			if r.Enabled && r.Action == model.ActionBlock && r.PortStart > 0 && (r.PortEnd == 0 || r.PortEnd == r.PortStart) {
				netfilter.FlushConntrackPort(r.L4Proto, r.PortStart)
			}
		}
	}
	return nil
}

func clientIPKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
