package geo

import (
	"regexp"
	"slices"
	"strings"
)

// DomainSet provides fast O(domain length) exact/suffix matching plus optional plain & regex rules.
type DomainSet struct {
	rootTrie *trieNode
	full     map[string]struct{}
	plain    []string
	regex    []*regexp.Regexp
}

type trieNode struct {
	children map[string]*trieNode
	terminal bool
}

// NewDomainSet constructs an empty DomainSet.
func NewDomainSet() *DomainSet {
	return &DomainSet{
		rootTrie: &trieNode{},
		full:     make(map[string]struct{}),
	}
}

// NormalizeDomain strips trailing dots and lowercases a domain name.
func NormalizeDomain(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	return strings.TrimRight(s, ".")
}

// AddRoot inserts a root domain (matches exact domain and all subdomains).
func (ds *DomainSet) AddRoot(domain string) {
	d := NormalizeDomain(domain)
	if d == "" {
		return
	}
	parts := strings.Split(d, ".")
	cur := ds.rootTrie
	// Insert labels in reverse order (e.g., com -> baidu) so suffix lookup walks from TLD down.
	for i := len(parts) - 1; i >= 0; i-- {
		lbl := parts[i]
		if lbl == "" {
			continue
		}
		if cur.children == nil {
			cur.children = make(map[string]*trieNode, 2)
		}
		next := cur.children[lbl]
		if next == nil {
			next = &trieNode{}
			cur.children[lbl] = next
		}
		cur = next
	}
	cur.terminal = true
}

// AddFull inserts an exact-match domain.
func (ds *DomainSet) AddFull(domain string) {
	d := NormalizeDomain(domain)
	if d != "" {
		ds.full[d] = struct{}{}
	}
}

// AddPlain inserts a substring keyword match.
func (ds *DomainSet) AddPlain(kw string) {
	kw = strings.ToLower(strings.TrimSpace(kw))
	if kw != "" {
		ds.plain = append(ds.plain, kw)
	}
}

// AddRegex compiles and adds a regular expression match.
func (ds *DomainSet) AddRegex(expr string) error {
	re, err := regexp.Compile(expr)
	if err != nil {
		return err
	}
	ds.regex = append(ds.regex, re)
	return nil
}

// AddSpec parses user shorthand syntax:
//   - "full:example.com" -> exact match
//   - "regexp:..."       -> regex match
//   - "keyword:..."      -> plain substring
//   - ".cn" or "cn"      -> TLD root match
//   - "example.com"      -> root domain match (exact + *.example.com)
func (ds *DomainSet) AddSpec(spec string) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return
	}
	switch {
	case strings.HasPrefix(s, "full:"):
		ds.AddFull(strings.TrimPrefix(s, "full:"))
	case strings.HasPrefix(s, "keyword:") || strings.HasPrefix(s, "plain:"):
		_, v, _ := strings.Cut(s, ":")
		ds.AddPlain(v)
	case strings.HasPrefix(s, "regexp:"):
		_ = ds.AddRegex(strings.TrimPrefix(s, "regexp:"))
	case strings.HasPrefix(s, "domain:"):
		ds.AddRoot(strings.TrimPrefix(s, "domain:"))
	default:
		s = strings.TrimPrefix(s, ".")
		ds.AddRoot(s)
	}
}

// AddGeoSiteEntries appends DomainEntry records filtered by optional attribute tag (e.g. "cn@ads").
func (ds *DomainSet) AddGeoSiteEntries(entries []DomainEntry, requiredAttr string) {
	for _, e := range entries {
		if requiredAttr != "" && !slices.Contains(e.Attrs, requiredAttr) {
			continue
		}
		switch e.Type {
		case DomainRoot:
			ds.AddRoot(e.Value)
		case DomainFull:
			ds.AddFull(e.Value)
		case DomainPlain:
			ds.AddPlain(e.Value)
		case DomainRegex:
			_ = ds.AddRegex(e.Value)
		}
	}
}

// Match returns true if domain matches any rule in the DomainSet.
func (ds *DomainSet) Match(raw string) bool {
	if ds == nil {
		return false
	}
	d := NormalizeDomain(raw)
	if d == "" {
		return false
	}
	if _, ok := ds.full[d]; ok {
		return true
	}
	if ds.matchTrie(d) {
		return true
	}
	for _, kw := range ds.plain {
		if strings.Contains(d, kw) {
			return true
		}
	}
	for _, re := range ds.regex {
		if re.MatchString(d) {
			return true
		}
	}
	return false
}

func (ds *DomainSet) matchTrie(d string) bool {
	cur := ds.rootTrie
	if cur == nil || len(cur.children) == 0 {
		return false
	}
	// Walk labels from right to left without allocating a slice.
	end := len(d)
	for i := len(d) - 1; i >= -1; i-- {
		if i == -1 || d[i] == '.' {
			lbl := d[i+1 : end]
			if lbl != "" {
				next := cur.children[lbl]
				if next == nil {
					return false
				}
				if next.terminal {
					return true
				}
				cur = next
			}
			end = i
		}
	}
	return false
}

// DomainPolicyMatcher combines include (GeoSite + custom) and exclude override DomainSets.
type DomainPolicyMatcher struct {
	Include *DomainSet
	Exclude *DomainSet
}

// Match returns true if domain is included and NOT excluded.
func (m *DomainPolicyMatcher) Match(domain string) bool {
	if m == nil || m.Include == nil {
		return false
	}
	if m.Exclude != nil && m.Exclude.Match(domain) {
		return false
	}
	return m.Include.Match(domain)
}

// BuildDomainPolicyMatcher compiles GeoSite categories + custom specs into a fast runtime matcher.
// If geosite.dat is missing or fails to load, it gracefully falls back to embedded core CN domains when "cn" is requested.
func BuildDomainPolicyMatcher(geositePath string, cats, matchDomains, excludeDomains []string) (*DomainPolicyMatcher, bool) {
	inc := NewDomainSet()
	exc := NewDomainSet()
	for _, d := range matchDomains {
		inc.AddSpec(d)
	}
	for _, d := range excludeDomains {
		exc.AddSpec(d)
	}

	usedFallback := false
	if len(cats) > 0 {
		var loaded map[string][]DomainEntry
		if geositePath != "" {
			if m, err := LoadGeoSiteCats(geositePath, cats); err == nil {
				loaded = m
			}
		}
		for _, rawCat := range cats {
			base, attr, _ := strings.Cut(strings.TrimSpace(rawCat), "@")
			upper := strings.ToUpper(base)
			if entries := loaded[upper]; len(entries) > 0 {
				inc.AddGeoSiteEntries(entries, attr)
			} else if upper == "CN" {
				// Always enforce .cn + builtin core CN domains if geosite.dat is absent.
				usedFallback = true
				for _, d := range BuiltinCNDomains {
					inc.AddRoot(d)
				}
			}
		}
	}
	return &DomainPolicyMatcher{Include: inc, Exclude: exc}, usedFallback
}
