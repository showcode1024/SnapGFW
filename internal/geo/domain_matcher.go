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
// Priority order:
//  1. Exclude (user explicit exclude_domains whitelist) -> allow (false)
//  2. CustomInclude (user explicit match_domains blacklist) -> match (true)
//  3. AutoExclude (international/world domains stripped from geosite:cn direct-routing pollution) -> allow (false)
//  4. Include (GeoSite categories + core Chinese domestic domains) -> match (true)
type DomainPolicyMatcher struct {
	Include       *DomainSet
	CustomInclude *DomainSet
	AutoExclude   *DomainSet
	Exclude       *DomainSet
}

// Match returns true if domain is included and NOT excluded.
func (m *DomainPolicyMatcher) Match(domain string) bool {
	if m == nil {
		return false
	}
	if m.Exclude != nil && m.Exclude.Match(domain) {
		return false
	}
	if m.CustomInclude != nil && m.CustomInclude.Match(domain) {
		return true
	}
	if m.AutoExclude != nil && m.AutoExclude.Match(domain) {
		return false
	}
	return m.Include != nil && m.Include.Match(domain)
}

func isChineseTLDDomain(d string) bool {
	d = NormalizeDomain(d)
	return d == "cn" ||
		strings.HasSuffix(d, ".cn") ||
		strings.HasSuffix(d, ".xn--fiqs8s") ||
		strings.HasSuffix(d, ".xn--55qx5d") ||
		strings.HasSuffix(d, ".xn--io0a7i")
}

// BuildDomainPolicyMatcher compiles GeoSite categories + custom specs into a fast runtime matcher.
// When "cn" is requested, it blocks genuine Chinese domains (.cn TLDs + domestic platforms) while
// automatically excluding international/global domains (such as www.apple.com, microsoft.com,
// google.com, and geolocation-!cn) that upstream geosite.dat bundles into "cn" for direct-routing.
func BuildDomainPolicyMatcher(geositePath string, cats, matchDomains, excludeDomains []string) (*DomainPolicyMatcher, bool) {
	return BuildDomainPolicyMatcherWithCache(geositePath, cats, matchDomains, excludeDomains, nil)
}

// BuildDomainPolicyMatcherWithCache compiles a DomainPolicyMatcher reusing pre-loaded GeoSite
// categories from preloaded (when non-nil) to avoid reading geosite.dat repeatedly per rule.
func BuildDomainPolicyMatcherWithCache(geositePath string, cats, matchDomains, excludeDomains []string, preloaded map[string][]DomainEntry) (*DomainPolicyMatcher, bool) {
	inc := NewDomainSet()
	customInc := NewDomainSet()
	autoExc := NewDomainSet()
	exc := NewDomainSet()

	for _, d := range matchDomains {
		customInc.AddSpec(d)
	}
	for _, d := range excludeDomains {
		exc.AddSpec(d)
	}

	coreCN := NewDomainSet()
	for _, d := range BuiltinCNDomains {
		coreCN.AddRoot(d)
	}

	wantsPureCN := false
	loadCats := make([]string, 0, len(cats)+1)
	for _, rawCat := range cats {
		loadCats = append(loadCats, rawCat)
		base, attr, _ := strings.Cut(strings.TrimSpace(rawCat), "@")
		if strings.EqualFold(base, "CN") && attr == "" {
			wantsPureCN = true
		}
	}
	if wantsPureCN {
		loadCats = append(loadCats, "GEOLOCATION-!CN")
	}

	usedFallback := false
	if len(cats) > 0 {
		loaded := preloaded
		if loaded == nil && geositePath != "" {
			if m, err := LoadGeoSiteCats(geositePath, loadCats); err == nil {
				loaded = m
			}
		}
		for _, rawCat := range cats {
			base, attr, _ := strings.Cut(strings.TrimSpace(rawCat), "@")
			upper := strings.ToUpper(base)
			if entries := loaded[upper]; len(entries) > 0 {
				inc.AddGeoSiteEntries(entries, attr)
				if upper == "CN" && attr == "" {
					for _, d := range BuiltinCNDomains {
						inc.AddRoot(d)
					}
				}
			} else if upper == "CN" {
				// Always enforce .cn + builtin core CN domains if geosite.dat is absent.
				usedFallback = true
				for _, d := range BuiltinCNDomains {
					inc.AddRoot(d)
				}
			}
		}
		if wantsPureCN {
			for _, d := range BuiltinGlobalDomains {
				autoExc.AddRoot(d)
			}
			for _, e := range loaded["GEOLOCATION-!CN"] {
				val := NormalizeDomain(e.Value)
				if val == "" || isChineseTLDDomain(val) || coreCN.Match(val) {
					continue
				}
				switch e.Type {
				case DomainRoot:
					autoExc.AddRoot(val)
				case DomainFull:
					autoExc.AddFull(val)
				}
			}
		}
	}
	return &DomainPolicyMatcher{
		Include:       inc,
		CustomInclude: customInc,
		AutoExclude:   autoExc,
		Exclude:       exc,
	}, usedFallback
}
