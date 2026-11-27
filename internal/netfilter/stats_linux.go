//go:build linux

package netfilter

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

var (
	l4StatsMu   sync.Mutex
	l4StatsAt   time.Time
	l4StatsVal  L4Stats
	l4StatsTbl  string
	l4StatsTTL  = 5 * time.Second
)

// ReadL4Stats queries `nft -j list table inet <tableName>` with a short TTL cache
// so frequent Web UI polls never hammer the kernel netlink interface.
func ReadL4Stats(tableName string, dropMark uint32) L4Stats {
	if tableName == "" {
		return L4Stats{}
	}
	l4StatsMu.Lock()
	if l4StatsTbl == tableName && time.Since(l4StatsAt) < l4StatsTTL {
		cached := l4StatsVal
		l4StatsMu.Unlock()
		return cached
	}
	l4StatsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Use -t (--terse) to omit potentially huge GeoIP set elements while keeping all counters.
	out, err := exec.CommandContext(ctx, "nft", "-j", "-t", "list", "table", "inet", tableName).Output()
	if err != nil {
		out, err = exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", tableName).Output()
		if err != nil {
			return L4Stats{}
		}
	}
	parsed := ParseNFTJSONStats(out, dropMark)

	l4StatsMu.Lock()
	l4StatsTbl = tableName
	l4StatsVal = parsed
	l4StatsAt = time.Now()
	l4StatsMu.Unlock()
	return parsed
}
