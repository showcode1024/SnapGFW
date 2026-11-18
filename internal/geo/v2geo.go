package geo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// DomainType mirrors V2Ray Domain_Type.
type DomainType int

const (
	DomainPlain DomainType = 0
	DomainRegex DomainType = 1
	DomainRoot  DomainType = 2
	DomainFull  DomainType = 3
)

// DomainEntry represents a parsed domain rule from geosite.dat.
type DomainEntry struct {
	Type  DomainType
	Value string
	Attrs []string
}

// LoadGeoSiteCats reads a V2Ray geosite.dat file and decodes ONLY the requested categories
// (case-insensitive, optionally supporting "cat@attr" syntax), keeping memory usage minimal.
func LoadGeoSiteCats(path string, wantedCats []string) (map[string][]DomainEntry, error) {
	if len(wantedCats) == 0 {
		return nil, nil
	}
	wantMap := make(map[string]bool, len(wantedCats))
	for _, c := range wantedCats {
		base, _, _ := strings.Cut(strings.TrimSpace(c), "@")
		if base != "" {
			wantMap[strings.ToUpper(base)] = true
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseGeoSiteBytes(data, wantMap)
}

// ParseGeoSiteBytes decodes only categories present in wantMap from raw protobuf bytes.
func ParseGeoSiteBytes(data []byte, wantMap map[string]bool) (map[string][]DomainEntry, error) {
	result := make(map[string][]DomainEntry, len(wantMap))
	i := 0
	for i < len(data) {
		fieldNum, wireType, n, err := readTag(data[i:])
		if err != nil {
			return nil, fmt.Errorf("geosite tag: %w", err)
		}
		i += n
		if fieldNum == 1 && wireType == 2 {
			entryBytes, m, err := readBytes(data[i:])
			if err != nil {
				return nil, fmt.Errorf("geosite entry: %w", err)
			}
			i += m
			code, err := peekCode(entryBytes, 1, 4)
			if err != nil {
				return nil, err
			}
			upper := strings.ToUpper(code)
			if wantMap[upper] {
				domains, err := decodeGeoSiteDomains(entryBytes)
				if err != nil {
					return nil, err
				}
				result[upper] = append(result[upper], domains...)
			}
		} else {
			m, err := skipField(data[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return result, nil
}

// LoadGeoIPCountries reads a V2Ray geoip.dat file and decodes ONLY the requested country codes.
func LoadGeoIPCountries(path string, countries []string) (map[string][]*net.IPNet, error) {
	if len(countries) == 0 {
		return nil, nil
	}
	wantMap := make(map[string]bool, len(countries))
	for _, c := range countries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			wantMap[c] = true
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseGeoIPBytes(data, wantMap)
}

// ParseGeoIPBytes decodes only countries present in wantMap from raw geoip.dat bytes.
func ParseGeoIPBytes(data []byte, wantMap map[string]bool) (map[string][]*net.IPNet, error) {
	result := make(map[string][]*net.IPNet, len(wantMap))
	i := 0
	for i < len(data) {
		fieldNum, wireType, n, err := readTag(data[i:])
		if err != nil {
			return nil, fmt.Errorf("geoip tag: %w", err)
		}
		i += n
		if fieldNum == 1 && wireType == 2 {
			entryBytes, m, err := readBytes(data[i:])
			if err != nil {
				return nil, fmt.Errorf("geoip entry: %w", err)
			}
			i += m
			code, err := peekCode(entryBytes, 1, 5)
			if err != nil {
				return nil, err
			}
			upper := strings.ToUpper(code)
			if wantMap[upper] {
				nets, err := decodeGeoIPCIDRs(entryBytes)
				if err != nil {
					return nil, err
				}
				result[upper] = append(result[upper], nets...)
			}
		} else {
			m, err := skipField(data[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return result, nil
}

func peekCode(b []byte, f1, fAlt int) (string, error) {
	i := 0
	var alt string
	for i < len(b) {
		fieldNum, wireType, n, err := readTag(b[i:])
		if err != nil {
			return "", err
		}
		i += n
		if (fieldNum == f1 || fieldNum == fAlt) && wireType == 2 {
			val, m, err := readBytes(b[i:])
			if err != nil {
				return "", err
			}
			i += m
			if fieldNum == f1 {
				return string(val), nil
			}
			alt = string(val)
		} else {
			m, err := skipField(b[i:], wireType)
			if err != nil {
				return "", err
			}
			i += m
		}
	}
	return alt, nil
}

func decodeGeoSiteDomains(b []byte) ([]DomainEntry, error) {
	var out []DomainEntry
	i := 0
	for i < len(b) {
		fieldNum, wireType, n, err := readTag(b[i:])
		if err != nil {
			return nil, err
		}
		i += n
		if fieldNum == 2 && wireType == 2 {
			domBytes, m, err := readBytes(b[i:])
			if err != nil {
				return nil, err
			}
			i += m
			d, err := decodeDomain(domBytes)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		} else {
			m, err := skipField(b[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return out, nil
}

func decodeDomain(b []byte) (DomainEntry, error) {
	var d DomainEntry
	i := 0
	for i < len(b) {
		fieldNum, wireType, n, err := readTag(b[i:])
		if err != nil {
			return d, err
		}
		i += n
		switch {
		case fieldNum == 1 && wireType == 0:
			v, m := binary.Uvarint(b[i:])
			if m <= 0 {
				return d, io.ErrUnexpectedEOF
			}
			i += m
			d.Type = DomainType(v)
		case fieldNum == 2 && wireType == 2:
			val, m, err := readBytes(b[i:])
			if err != nil {
				return d, err
			}
			i += m
			d.Value = string(val)
		case fieldNum == 3 && wireType == 2:
			attrBytes, m, err := readBytes(b[i:])
			if err != nil {
				return d, err
			}
			i += m
			if key, err := peekCode(attrBytes, 1, -1); err == nil && key != "" {
				d.Attrs = append(d.Attrs, key)
			}
		default:
			m, err := skipField(b[i:], wireType)
			if err != nil {
				return d, err
			}
			i += m
		}
	}
	return d, nil
}

func decodeGeoIPCIDRs(b []byte) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	i := 0
	for i < len(b) {
		fieldNum, wireType, n, err := readTag(b[i:])
		if err != nil {
			return nil, err
		}
		i += n
		if fieldNum == 2 && wireType == 2 {
			cidrBytes, m, err := readBytes(b[i:])
			if err != nil {
				return nil, err
			}
			i += m
			ipNet, err := decodeCIDR(cidrBytes)
			if err != nil {
				return nil, err
			}
			if ipNet != nil {
				nets = append(nets, ipNet)
			}
		} else {
			m, err := skipField(b[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	return nets, nil
}

func decodeCIDR(b []byte) (*net.IPNet, error) {
	var ipBytes []byte
	var prefix uint32
	i := 0
	for i < len(b) {
		fieldNum, wireType, n, err := readTag(b[i:])
		if err != nil {
			return nil, err
		}
		i += n
		switch {
		case fieldNum == 1 && wireType == 2:
			val, m, err := readBytes(b[i:])
			if err != nil {
				return nil, err
			}
			i += m
			ipBytes = append([]byte(nil), val...)
		case fieldNum == 2 && wireType == 0:
			v, m := binary.Uvarint(b[i:])
			if m <= 0 {
				return nil, io.ErrUnexpectedEOF
			}
			i += m
			prefix = uint32(v)
		default:
			m, err := skipField(b[i:], wireType)
			if err != nil {
				return nil, err
			}
			i += m
		}
	}
	switch len(ipBytes) {
	case 4:
		if prefix > 32 {
			return nil, errors.New("invalid IPv4 prefix")
		}
		return &net.IPNet{IP: net.IP(ipBytes), Mask: net.CIDRMask(int(prefix), 32)}, nil
	case 16:
		if prefix > 128 {
			return nil, errors.New("invalid IPv6 prefix")
		}
		return &net.IPNet{IP: net.IP(ipBytes), Mask: net.CIDRMask(int(prefix), 128)}, nil
	default:
		return nil, nil
	}
}

func readTag(b []byte) (fieldNum int, wireType int, n int, err error) {
	v, m := binary.Uvarint(b)
	if m <= 0 {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}
	return int(v >> 3), int(v & 0x7), m, nil
}

func readBytes(b []byte) ([]byte, int, error) {
	l, m := binary.Uvarint(b)
	if m <= 0 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	end := m + int(l)
	if end < m || end > len(b) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return b[m:end], end, nil
}

func skipField(b []byte, wireType int) (int, error) {
	switch wireType {
	case 0: // varint
		_, m := binary.Uvarint(b)
		if m <= 0 {
			return 0, io.ErrUnexpectedEOF
		}
		return m, nil
	case 1: // 64-bit
		if len(b) < 8 {
			return 0, io.ErrUnexpectedEOF
		}
		return 8, nil
	case 2: // length-delimited
		_, end, err := readBytes(b)
		return end, err
	case 5: // 32-bit
		if len(b) < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported protobuf wire type %d", wireType)
	}
}
