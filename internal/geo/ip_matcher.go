package geo

import (
	"bytes"
	"net"
	"slices"
)

// IPMatcher performs fast binary-search lookup over sorted IPv4 and IPv6 CIDR lists.
type IPMatcher struct {
	n4 []*net.IPNet
	n6 []*net.IPNet
}

// NewIPMatcher creates a sorted IPMatcher from a slice of IPNets.
func NewIPMatcher(nets []*net.IPNet) *IPMatcher {
	var n4, n6 []*net.IPNet
	for _, n := range nets {
		if n == nil {
			continue
		}
		if ip4 := n.IP.To4(); ip4 != nil {
			n4 = append(n4, &net.IPNet{IP: ip4, Mask: n.Mask})
		} else if ip16 := n.IP.To16(); ip16 != nil {
			n6 = append(n6, &net.IPNet{IP: ip16, Mask: n.Mask})
		}
	}
	slices.SortFunc(n4, func(a, b *net.IPNet) int { return bytes.Compare(a.IP, b.IP) })
	slices.SortFunc(n6, func(a, b *net.IPNet) int { return bytes.Compare(a.IP, b.IP) })
	return &IPMatcher{n4: n4, n6: n6}
}

// Contains returns true if ip falls inside any CIDR in the matcher.
func (m *IPMatcher) Contains(ip net.IP) bool {
	if m == nil || ip == nil {
		return false
	}
	var list []*net.IPNet
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		list = m.n4
	} else {
		ip = ip.To16()
		list = m.n6
	}
	left, right := 0, len(list)-1
	for left <= right {
		mid := (left + right) / 2
		if list[mid].Contains(ip) {
			return true
		}
		if bytes.Compare(list[mid].IP, ip) < 0 {
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	return false
}
