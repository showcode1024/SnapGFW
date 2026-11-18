//go:build !linux

package netfilter

// CheckHostPrereqs is a no-op outside Linux.
func CheckHostPrereqs() error { return nil }

// ApplyNFT is a no-op outside Linux.
func ApplyNFT(script string) error { return nil }

// DeleteTable is a no-op outside Linux.
func DeleteTable(tableName string) error { return nil }

// QuarantineIP is a no-op outside Linux.
func QuarantineIP(tableName, ipStr string, timeoutSec int) error { return nil }

// UnquarantineIP is a no-op outside Linux.
func UnquarantineIP(tableName, ipStr string) error { return nil }

// FlushConntrackForIP is a no-op outside Linux.
func FlushConntrackForIP(ipStr string) {}

// FlushConntrackPort is a no-op outside Linux.
func FlushConntrackPort(l4 string, port uint16) {}
