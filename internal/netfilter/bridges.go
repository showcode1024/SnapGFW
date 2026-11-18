package netfilter

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// BridgeInfo describes a local Linux bridge interface discovered via /sys/class/net.
type BridgeInfo struct {
	Name  string `json:"name"`
	Up    bool   `json:"up"`
	Ports int    `json:"ports"`
}

// BridgeExists reports whether the named network interface currently exists on this Linux host.
func BridgeExists(name string) bool {
	if runtime.GOOS != "linux" || strings.TrimSpace(name) == "" {
		return false
	}
	_, err := os.Stat(filepath.Join("/sys/class/net", name))
	return err == nil
}

// ListBridges enumerates local Linux bridge interfaces sorted with active bridges first.
func ListBridges() []BridgeInfo {
	if runtime.GOOS != "linux" {
		return nil
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []BridgeInfo
	for _, ent := range entries {
		name := ent.Name()
		base := filepath.Join("/sys/class/net", name)
		if st, err := os.Stat(filepath.Join(base, "bridge")); err != nil || !st.IsDir() {
			continue
		}
		stateRaw, _ := os.ReadFile(filepath.Join(base, "operstate"))
		up := strings.EqualFold(strings.TrimSpace(string(stateRaw)), "up")
		ports := 0
		if brifs, err := os.ReadDir(filepath.Join(base, "brif")); err == nil {
			ports = len(brifs)
		}
		out = append(out, BridgeInfo{Name: name, Up: up, Ports: ports})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Up != out[j].Up {
			return out[i].Up
		}
		if out[i].Ports != out[j].Ports {
			return out[i].Ports > out[j].Ports
		}
		return out[i].Name < out[j].Name
	})
	return out
}
