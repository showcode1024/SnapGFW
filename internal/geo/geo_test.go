package geo

import (
	"encoding/binary"
	"net"
	"testing"
)

func encodeVarintField(fieldNum int, val uint64) []byte {
	var buf []byte
	buf = binary.AppendUvarint(buf, uint64(fieldNum<<3))
	buf = binary.AppendUvarint(buf, val)
	return buf
}

func encodeBytesField(fieldNum int, payload []byte) []byte {
	var buf []byte
	buf = binary.AppendUvarint(buf, uint64((fieldNum<<3)|2))
	buf = binary.AppendUvarint(buf, uint64(len(payload)))
	buf = append(buf, payload...)
	return buf
}

func TestDomainSet_RootExactNoSubstringFalsePositive(t *testing.T) {
	ds := NewDomainSet()
	ds.AddRoot("jd.com")
	ds.AddRoot("cn")
	ds.AddFull("exact.example.org")

	if !ds.Match("jd.com") || !ds.Match("item.jd.com") || !ds.Match("WWW.JD.COM.") {
		t.Fatal("expected jd.com and subdomains to match")
	}
	if ds.Match("myjd.com") || ds.Match("jd.com.evil.org") {
		t.Fatal("substring false positive on myjd.com / jd.com.evil.org")
	}
	if !ds.Match("foo.edu.cn") || !ds.Match("bar.cn.") {
		t.Fatal("expected .cn TLD to match")
	}
	if ds.Match("sub.exact.example.org") || !ds.Match("exact.example.org") {
		t.Fatal("full match failed")
	}
}

func TestDomainPolicyMatcher_FallbackAndExclude(t *testing.T) {
	m, fallback := BuildDomainPolicyMatcher("", []string{"cn"}, []string{"custom-spoof.org"}, []string{"allowed.baidu.com"})
	if !fallback {
		t.Fatal("expected fallback=true when no geosite file given")
	}
	if !m.Match("www.baidu.com") || !m.Match("sub.custom-spoof.org") || !m.Match("test.cn") {
		t.Fatal("expected cn and custom domain to match")
	}
	if m.Match("allowed.baidu.com") {
		t.Fatal("expected excluded domain to be bypassed")
	}
	if m.Match("www.google.com") {
		t.Fatal("unexpected match on google.com")
	}
}

func TestParseGeoSiteAndGeoIPBytes(t *testing.T) {
	// Build minimal protobuf GeoSiteList with US (skipped) and CN (loaded)
	var usDom []byte
	usDom = append(usDom, encodeVarintField(1, uint64(DomainRoot))...)
	usDom = append(usDom, encodeBytesField(2, []byte("google.com"))...)
	var usEntry []byte
	usEntry = append(usEntry, encodeBytesField(1, []byte("US"))...)
	usEntry = append(usEntry, encodeBytesField(2, usDom)...)

	var cnDom []byte
	cnDom = append(cnDom, encodeVarintField(1, uint64(DomainRoot))...)
	cnDom = append(cnDom, encodeBytesField(2, []byte("qq.com"))...)
	var cnEntry []byte
	cnEntry = append(cnEntry, encodeBytesField(1, []byte("CN"))...)
	cnEntry = append(cnEntry, encodeBytesField(2, cnDom)...)

	var siteList []byte
	siteList = append(siteList, encodeBytesField(1, usEntry)...)
	siteList = append(siteList, encodeBytesField(1, cnEntry)...)

	sites, err := ParseGeoSiteBytes(siteList, map[string]bool{"CN": true})
	if err != nil {
		t.Fatalf("ParseGeoSiteBytes failed: %v", err)
	}
	if len(sites["US"]) != 0 || len(sites["CN"]) != 1 || sites["CN"][0].Value != "qq.com" {
		t.Fatalf("unexpected parsed geosite result: %+v", sites)
	}

	// Build minimal protobuf GeoIPList
	var cidr []byte
	cidr = append(cidr, encodeBytesField(1, net.ParseIP("1.2.3.0").To4())...)
	cidr = append(cidr, encodeVarintField(2, 24)...)
	var ipEntry []byte
	ipEntry = append(ipEntry, encodeBytesField(1, []byte("CN"))...)
	ipEntry = append(ipEntry, encodeBytesField(2, cidr)...)
	var ipList []byte
	ipList = append(ipList, encodeBytesField(1, ipEntry)...)

	ips, err := ParseGeoIPBytes(ipList, map[string]bool{"CN": true})
	if err != nil {
		t.Fatalf("ParseGeoIPBytes failed: %v", err)
	}
	matcher := NewIPMatcher(ips["CN"])
	if !matcher.Contains(net.ParseIP("1.2.3.45")) || matcher.Contains(net.ParseIP("1.2.4.1")) {
		t.Fatal("IPMatcher lookup failed")
	}
}
