//go:build linux

package netfilter

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// CheckHostPrereqs verifies that nft and kernel netfilter queue/conntrack facilities are usable.
func CheckHostPrereqs() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found (install nftables): %w", err)
	}
	out, err := exec.Command("nft", "list", "tables").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables unusable (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ApplyNFT atomically loads the rendered nftables script via `nft -f -`.
func ApplyNFT(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// DeleteTable removes the natgfw nftables table cleanly on shutdown.
func DeleteTable(tableName string) error {
	cmd := exec.Command("nft", "delete", "table", "inet", tableName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "No such file") {
			return nil
		}
		return err
	}
	return nil
}

// QuarantineIP adds a tenant IP to the nft quarantine set with a kernel-enforced timeout.
func QuarantineIP(tableName, ipStr string, timeoutSec int) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return fmt.Errorf("invalid ip %q", ipStr)
	}
	setName := "quarantine4"
	if ip.To4() == nil {
		setName = "quarantine6"
	}
	elem := fmt.Sprintf("{ %s timeout %ds }", ip.String(), max(timeoutSec, 10))
	out, err := exec.Command("nft", "add", "element", "inet", tableName, setName, elem).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft quarantine add failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// UnquarantineIP removes a tenant IP from the nft quarantine set.
func UnquarantineIP(tableName, ipStr string) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return fmt.Errorf("invalid ip %q", ipStr)
	}
	setName := "quarantine4"
	if ip.To4() == nil {
		setName = "quarantine6"
	}
	elem := fmt.Sprintf("{ %s }", ip.String())
	out, err := exec.Command("nft", "delete", "element", "inet", tableName, setName, elem).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") && !strings.Contains(string(out), "Element does not exist") {
		return fmt.Errorf("nft quarantine delete failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// FlushConntrackForIP drops active conntrack entries involving ipStr (best-effort if conntrack CLI exists).
func FlushConntrackForIP(ipStr string) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return
	}
	if _, err := exec.LookPath("conntrack"); err != nil {
		return
	}
	fam := "ipv4"
	if ip.To4() == nil {
		fam = "ipv6"
	}
	_ = exec.Command("conntrack", "-D", "-f", fam, "-s", ip.String()).Run()
	_ = exec.Command("conntrack", "-D", "-f", fam, "-d", ip.String()).Run()
}

// FlushConntrackPort drops active conntrack entries for newly blocked L4 ports (best-effort).
func FlushConntrackPort(l4 string, port uint16) {
	if port == 0 {
		return
	}
	if _, err := exec.LookPath("conntrack"); err != nil {
		return
	}
	pStr := fmt.Sprintf("%d", port)
	if l4 == "tcp" || l4 == "both" {
		_ = exec.Command("conntrack", "-D", "-p", "tcp", "--dport", pStr).Run()
	}
	if l4 == "udp" || l4 == "both" {
		_ = exec.Command("conntrack", "-D", "-p", "udp", "--dport", pStr).Run()
	}
}
