//go:build !linux

package netfilter

// ReadL4Stats returns empty kernel L4 counters on non-Linux hosts.
func ReadL4Stats(tableName string, dropMark uint32) L4Stats {
	return L4Stats{}
}
