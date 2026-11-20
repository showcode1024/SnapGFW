package netfilter

import (
	"encoding/json"
	"strings"
)

// L4Stats summarizes kernel-level nftables L4 drop counters (excluding L7 DPI ct-mark drops).
type L4Stats struct {
	PortDrops       uint64 `json:"port_drops"`
	RateDrops       uint64 `json:"rate_drops"`
	QuarantineDrops uint64 `json:"quarantine_drops"`
	TotalDrops      uint64 `json:"total_drops"`
}

// ParseNFTJSONStats parses the JSON output of `nft -j list table inet <table>` and aggregates
// L4 kernel drops by category while excluding L7 DPI conntrack mark drops (`dropMark`).
func ParseNFTJSONStats(raw []byte, dropMark uint32) L4Stats {
	var doc struct {
		NFTables []struct {
			Rule *struct {
				Chain string            `json:"chain"`
				Expr  []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return L4Stats{}
	}

	var stats L4Stats
	for _, item := range doc.NFTables {
		r := item.Rule
		if r == nil {
			continue
		}
		var (
			hasDrop      bool
			hasDPI       bool
			isQuarantine bool
			isRate       bool
			pkts         uint64
		)
		for _, rawExpr := range r.Expr {
			var obj map[string]json.RawMessage
			if json.Unmarshal(rawExpr, &obj) != nil {
				continue
			}
			if _, ok := obj["drop"]; ok {
				hasDrop = true
			}
			if cntRaw, ok := obj["counter"]; ok {
				var c struct {
					Packets uint64 `json:"packets"`
				}
				if json.Unmarshal(cntRaw, &c) == nil {
					pkts = c.Packets
				}
			}
			if addRaw, ok := obj["add"]; ok {
				s := string(addRaw)
				if strings.Contains(s, "@conn_limit") || strings.Contains(s, "@conn_rate") || strings.Contains(s, "@udp_pps") {
					isRate = true
				}
			}
			if matchRaw, ok := obj["match"]; ok {
				s := string(matchRaw)
				if strings.Contains(s, "@quarantine") {
					isQuarantine = true
				}
				if strings.Contains(s, `"ct"`) && strings.Contains(s, `"mark"`) {
					var m struct {
						Right uint32 `json:"right"`
					}
					if json.Unmarshal(matchRaw, &m) == nil && m.Right == dropMark {
						hasDPI = true
					}
				}
			}
		}
		if !hasDrop || hasDPI || pkts == 0 {
			continue
		}
		switch {
		case isQuarantine:
			stats.QuarantineDrops += pkts
		case isRate:
			stats.RateDrops += pkts
		default:
			stats.PortDrops += pkts
		}
	}
	stats.TotalDrops = stats.PortDrops + stats.RateDrops + stats.QuarantineDrops
	return stats
}
