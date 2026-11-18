package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultRepo      = "showcode1024/SnapGFW"
	defaultAPIBase   = "https://api.github.com"
	maxChecksumBytes = 64 * 1024
	maxBinaryBytes   = 64 * 1024 * 1024
	cacheTTL         = 60 * time.Second
)

// Info describes the current binary version and latest GitHub Release check result.
type Info struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	HasUpdate      bool   `json:"has_update"`
	ReleaseURL     string `json:"release_url,omitempty"`
	PublishedAt    string `json:"published_at,omitempty"`
	AssetName      string `json:"asset_name,omitempty"`
	CanSelfUpdate  bool   `json:"can_self_update"`
	CheckError     string `json:"check_error,omitempty"`
	assetURL       string
	checksumsURL   string
}

type githubRelease struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// Updater checks GitHub Releases and performs SHA-256 verified binary upgrades.
type Updater struct {
	currentVersion string
	repo           string
	apiBase        string
	osName         string
	archName       string
	execPathFn     func() (string, error)
	smokeTestFn    func(ctx context.Context, binPath string) error
	onRestart      func()
	client         *http.Client

	mu       sync.Mutex
	cached   *Info
	cachedAt time.Time
}

// New creates an Updater for the active SnapGFW binary version.
func New(currentVersion string, onRestart func()) *Updater {
	return &Updater{
		currentVersion: currentVersion,
		repo:           defaultRepo,
		apiBase:        defaultAPIBase,
		osName:         runtime.GOOS,
		archName:       runtime.GOARCH,
		execPathFn:     os.Executable,
		smokeTestFn:    defaultSmokeTest,
		onRestart:      onRestart,
		client:         &http.Client{Timeout: 30 * time.Second},
	}
}

func defaultSmokeTest(ctx context.Context, binPath string) error {
	out, err := exec.CommandContext(ctx, binPath, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("new binary self-check failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(strings.ToLower(string(out)), "snapgfw") {
		return fmt.Errorf("unexpected version output %q", strings.TrimSpace(string(out)))
	}
	return nil
}

// Check queries GitHub Releases for a newer release (cached for 60s unless forceRefresh is true).
func (u *Updater) Check(ctx context.Context, forceRefresh bool) Info {
	u.mu.Lock()
	if !forceRefresh && u.cached != nil && time.Since(u.cachedAt) < cacheTTL {
		cp := *u.cached
		u.mu.Unlock()
		return cp
	}
	u.mu.Unlock()

	info := u.fetchLatest(ctx)

	u.mu.Lock()
	if info.CheckError == "" {
		cp := info
		u.cached = &cp
		u.cachedAt = time.Now()
	}
	u.mu.Unlock()
	return info
}

func (u *Updater) expectedAssetName() string {
	return fmt.Sprintf("snapgfw-linux-%s", u.archName)
}

func (u *Updater) fetchLatest(ctx context.Context) Info {
	assetName := u.expectedAssetName()
	info := Info{
		CurrentVersion: u.currentVersion,
		AssetName:      assetName,
		CanSelfUpdate:  u.osName == "linux",
	}

	reqURL := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(u.apiBase, "/"), u.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		info.CheckError = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SnapGFW-Updater/"+u.currentVersion)

	resp, err := u.client.Do(req)
	if err != nil {
		info.CheckError = err.Error()
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.CheckError = fmt.Sprintf("github api http %d", resp.StatusCode)
		return info
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&rel); err != nil {
		info.CheckError = err.Error()
		return info
	}

	info.LatestVersion = rel.TagName
	info.ReleaseURL = rel.HTMLURL
	info.PublishedAt = rel.PublishedAt
	info.HasUpdate = isNewerVersion(u.currentVersion, rel.TagName)

	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			info.assetURL = a.BrowserDownloadURL
		case "SHA256SUMS":
			info.checksumsURL = a.BrowserDownloadURL
		}
	}
	return info
}

// ApplyUpdate downloads the latest Linux release, verifies SHA256SUMS, smoke-tests
// the binary, swaps it atomically in place, and schedules service restart.
func (u *Updater) ApplyUpdate(ctx context.Context) (Info, error) {
	if u.osName != "linux" {
		return Info{CurrentVersion: u.currentVersion}, errors.New("panel self-update is only supported on Linux")
	}

	info := u.Check(ctx, true)
	if info.CheckError != "" {
		return info, errors.New(info.CheckError)
	}
	if !info.HasUpdate {
		return info, errors.New("already on the latest version")
	}
	if info.assetURL == "" || info.checksumsURL == "" {
		return info, fmt.Errorf("release %s missing asset %s or SHA256SUMS", info.LatestVersion, info.AssetName)
	}

	wantHash, err := u.fetchExpectedSHA256(ctx, info.checksumsURL, info.AssetName)
	if err != nil {
		return info, err
	}

	exePath, err := u.execPathFn()
	if err != nil {
		return info, fmt.Errorf("locate executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", exePath, time.Now().UnixNano())
	if err := u.downloadAndVerify(ctx, info.assetURL, tmpPath, wantHash); err != nil {
		_ = os.Remove(tmpPath)
		return info, err
	}

	if u.smokeTestFn != nil {
		if err := u.smokeTestFn(ctx, tmpPath); err != nil {
			_ = os.Remove(tmpPath)
			return info, err
		}
	}

	if err := os.Rename(tmpPath, exePath); err != nil {
		_ = os.Remove(tmpPath)
		return info, fmt.Errorf("replace binary: %w", err)
	}

	u.mu.Lock()
	u.cached = nil
	u.mu.Unlock()

	if u.onRestart != nil {
		time.AfterFunc(350*time.Millisecond, u.onRestart)
	}
	return info, nil
}

func (u *Updater) fetchExpectedSHA256(ctx context.Context, url, assetName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download SHA256SUMS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download SHA256SUMS: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumBytes))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := strings.TrimPrefix(fields[1], "*")
			if name == assetName && len(fields[0]) == 64 {
				return strings.ToLower(fields[0]), nil
			}
		}
	}
	return "", fmt.Errorf("checksum entry for %s not found in SHA256SUMS", assetName)
}

func (u *Updater) downloadAndVerify(ctx context.Context, url, dstPath, wantHash string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download binary: http %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create temp binary: %w", err)
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(resp.Body, maxBinaryBytes))
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("write binary: %w", copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	gotHash := hex.EncodeToString(hasher.Sum(nil))
	if gotHash != wantHash {
		return fmt.Errorf("sha256 mismatch: want %s got %s", wantHash, gotHash)
	}
	return nil
}

func isNewerVersion(cur, latest string) bool {
	cNums, cOK := parseSemver(cur)
	lNums, lOK := parseSemver(latest)
	if !lOK {
		return false
	}
	if !cOK {
		return strings.TrimSpace(cur) != strings.TrimSpace(latest)
	}
	for i := 0; i < 3; i++ {
		if lNums[i] != cNums[i] {
			return lNums[i] > cNums[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if dash := strings.IndexAny(s, "-+"); dash >= 0 {
		s = s[:dash]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
