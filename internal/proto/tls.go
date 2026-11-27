package proto

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// TLSParseStatus indicates ClientHello parsing progress.
type TLSParseStatus int

const (
	TLSNeedMore TLSParseStatus = iota
	TLSNotTLS                  // Not a TLS handshake record
	TLSMalformed               // Looked like TLS record header but invalid ClientHello (possible fake TLS obfs)
	TLSValid
)

// TLSClientHello holds extracted ClientHello metadata.
type TLSClientHello struct {
	SNI        string
	ALPN       []string
	HasECH     bool
	HasESNI    bool
	RecordCount int
}

// ParseTLSClientHello parses a TLS ClientHello across ONE OR MORE TLS handshake records.
// Reassembling fragmented TLS records prevents record-splitting evasion that breaks single-record parsers.
func ParseTLSClientHello(b []byte) (TLSClientHello, TLSParseStatus) {
	if len(b) == 0 {
		return TLSClientHello{}, TLSNeedMore
	}
	// Record ContentType: 0x16 (Handshake). Note: fake TLS obfs sometimes starts with 0x17 0x03 ...
	if b[0] == 0x17 {
		if len(b) >= 3 && b[1] == 0x03 && b[2] <= 0x09 {
			return TLSClientHello{}, TLSMalformed
		}
		return TLSClientHello{}, TLSNotTLS
	}
	if b[0] != 0x16 {
		return TLSClientHello{}, TLSNotTLS
	}
	if len(b) < 3 {
		return TLSClientHello{}, TLSNeedMore
	}
	if b[1] != 0x03 || b[2] > 0x09 {
		return TLSClientHello{}, TLSNotTLS
	}
	if len(b) < 5 {
		return TLSClientHello{}, TLSNeedMore
	}

	// Collect handshake bytes across consecutive TLS 0x16 records.
	var hs []byte
	pos := 0
	records := 0
	var needLen int
	for pos < len(b) {
		if pos+5 > len(b) {
			return TLSClientHello{}, TLSNeedMore
		}
		if b[pos] != 0x16 || b[pos+1] != 0x03 || b[pos+2] > 0x09 {
			if records == 0 {
				return TLSClientHello{}, TLSMalformed
			}
			break
		}
		recLen := int(binary.BigEndian.Uint16(b[pos+3 : pos+5]))
		if recLen == 0 || recLen > 16384 {
			return TLSClientHello{}, TLSMalformed
		}
		if pos+5+recLen > len(b) {
			return TLSClientHello{}, TLSNeedMore
		}
		hs = append(hs, b[pos+5:pos+5+recLen]...)
		pos += 5 + recLen
		records++

		if len(hs) >= 4 {
			if hs[0] != 0x01 { // HandshakeType ClientHello
				return TLSClientHello{}, TLSMalformed
			}
			needLen = int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if needLen < 41 || needLen > 32768 {
				return TLSClientHello{}, TLSMalformed
			}
			if len(hs) >= 4+needLen {
				break
			}
		}
		if records > 32 {
			return TLSClientHello{}, TLSMalformed
		}
	}

	if len(hs) < 4 || len(hs) < 4+needLen {
		return TLSClientHello{}, TLSNeedMore
	}

	info, ok := ParseClientHelloBody(hs[4 : 4+needLen])
	if !ok {
		return TLSClientHello{}, TLSMalformed
	}
	info.RecordCount = records
	return info, TLSValid
}

// ParseClientHelloBody decodes the raw TLS ClientHello body (without 4-byte handshake header).
// Shared by both TLS and QUIC analyzers.
func ParseClientHelloBody(body []byte) (TLSClientHello, bool) {
	var out TLSClientHello
	// 2 bytes version + 32 bytes random + 1 byte session_id_len = 35
	if len(body) < 35 {
		return out, false
	}
	off := 34
	sidLen := int(body[off])
	off++
	if off+sidLen+2 > len(body) {
		return out, false
	}
	off += sidLen

	cipherLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if cipherLen%2 != 0 || off+cipherLen+1 > len(body) {
		return out, false
	}
	off += cipherLen

	compLen := int(body[off])
	off++
	if off+compLen > len(body) {
		return out, false
	}
	off += compLen

	if off == len(body) {
		return out, true // No extensions
	}
	if off+2 > len(body) {
		return out, false
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extTotalLen > len(body) {
		return out, false
	}
	extEnd := off + extTotalLen
	for off < extEnd {
		if off+4 > extEnd {
			return out, false
		}
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			return out, false
		}
		extData := body[off : off+extLen]
		off += extLen

		switch extType {
		case 0x0000: // server_name
			if len(extData) < 5 {
				return out, false
			}
			// list len (2) + name_type (1) + name_len (2)
			if extData[2] != 0x00 {
				return out, false
			}
			sniLen := int(binary.BigEndian.Uint16(extData[3:5]))
			if 5+sniLen > len(extData) {
				return out, false
			}
			out.SNI = strings.ToLower(string(extData[5 : 5+sniLen]))
		case 0x0010: // ALPN
			if len(extData) < 2 {
				return out, false
			}
			p := 2
			for p < len(extData) {
				l := int(extData[p])
				p++
				if p+l > len(extData) {
					return out, false
				}
				out.ALPN = append(out.ALPN, string(extData[p:p+l]))
				p += l
			}
		case 0xffce: // ESNI
			out.HasESNI = true
		case 0xfe0d: // ECH
			out.HasECH = true
		}
	}
	return out, true
}

// ParseTLSServerCerts passively parses server-to-client TLS Handshake records to detect
// whether TLS 1.3 was negotiated (in which case certificates are encrypted and isTLS13=true)
// or extracts the plaintext X.509 certificate chain from a TLS 1.2 (or older) handshake.
func ParseTLSServerCerts(b []byte) (certs []*x509.Certificate, isTLS13 bool, status TLSParseStatus) {
	if len(b) == 0 {
		return nil, false, TLSNeedMore
	}
	if b[0] != 0x16 {
		return nil, false, TLSNotTLS
	}
	if len(b) < 5 {
		return nil, false, TLSNeedMore
	}
	if b[1] != 0x03 || b[2] > 0x09 {
		return nil, false, TLSNotTLS
	}

	var hs []byte
	pos := 0
	records := 0
	for pos < len(b) {
		if pos+5 > len(b) {
			break
		}
		recType := b[pos]
		if recType != 0x16 {
			// Reached ChangeCipherSpec (0x14), ApplicationData (0x17), or Alert (0x15).
			break
		}
		if b[pos+1] != 0x03 || b[pos+2] > 0x09 {
			return nil, false, TLSMalformed
		}
		recLen := int(binary.BigEndian.Uint16(b[pos+3 : pos+5]))
		if recLen == 0 || recLen > 16384 {
			return nil, false, TLSMalformed
		}
		if pos+5+recLen > len(b) {
			// Partial handshake record; parse what we have so far (e.g. ServerHello might already be complete).
			hs = append(hs, b[pos+5:]...)
			break
		}
		hs = append(hs, b[pos+5:pos+5+recLen]...)
		pos += 5 + recLen
		records++
		if records > 32 {
			return nil, false, TLSMalformed
		}
	}

	// Walk TLS handshake messages inside reassembled stream.
	off := 0
	sawServerHello := false
	for off+4 <= len(hs) {
		msgType := hs[off]
		msgLen := int(hs[off+1])<<16 | int(hs[off+2])<<8 | int(hs[off+3])
		if msgLen > 32768 {
			return nil, false, TLSMalformed
		}
		if off+4+msgLen > len(hs) {
			return nil, false, TLSNeedMore
		}
		body := hs[off+4 : off+4+msgLen]
		off += 4 + msgLen

		switch msgType {
		case 0x02: // ServerHello
			sawServerHello = true
			if isServerHelloTLS13(body) {
				return nil, true, TLSValid
			}
		case 0x0b: // Certificate (TLS 1.2 plaintext)
			parsed, ok := parseTLSCertificateList(body)
			if !ok {
				return nil, false, TLSMalformed
			}
			return parsed, false, TLSValid
		case 0x0e: // ServerHelloDone (no cert presented, e.g. PSK/resumed session)
			return nil, false, TLSValid
		}
	}

	if !sawServerHello && len(hs) >= 4 && hs[0] != 0x02 {
		return nil, false, TLSMalformed
	}
	return nil, false, TLSNeedMore
}

func isServerHelloTLS13(body []byte) bool {
	// 2B version + 32B random + 1B session_id_len
	if len(body) < 35 {
		return false
	}
	off := 34
	sidLen := int(body[off])
	off++
	if off+sidLen+3 > len(body) {
		return false
	}
	off += sidLen
	off += 2 // cipher suite
	off += 1 // compression method
	if off+2 > len(body) {
		return false
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extTotalLen > len(body) {
		return false
	}
	extEnd := off + extTotalLen
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			return false
		}
		if extType == 0x002b && extLen == 2 { // supported_versions
			ver := binary.BigEndian.Uint16(body[off : off+2])
			return ver >= 0x0304
		}
		off += extLen
	}
	return false
}

func parseTLSCertificateList(body []byte) ([]*x509.Certificate, bool) {
	if len(body) < 3 {
		return nil, false
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if 3+listLen > len(body) {
		return nil, false
	}
	off := 3
	end := 3 + listLen
	var certs []*x509.Certificate
	for off < end {
		if off+3 > end {
			return nil, false
		}
		certLen := int(body[off])<<16 | int(body[off+1])<<8 | int(body[off+2])
		off += 3
		if certLen == 0 || off+certLen > end {
			return nil, false
		}
		cert, err := x509.ParseCertificate(body[off : off+certLen])
		if err != nil {
			return nil, false
		}
		certs = append(certs, cert)
		off += certLen
		if len(certs) >= 10 {
			break
		}
	}
	return certs, len(certs) > 0
}

var (
	sysRootsOnce  sync.Once
	sysRootsReady bool
)

// SystemRootsAvailable returns true when platform root CAs are present so certificate
// verification will not falsely reject legitimate CA-signed sites (e.g. REALITY targets).
func SystemRootsAvailable() bool {
	sysRootsOnce.Do(func() {
		if runtime.GOOS != "linux" {
			sysRootsReady = true
			return
		}
		if p := os.Getenv("SSL_CERT_FILE"); p != "" {
			if st, err := os.Stat(p); err == nil && st.Size() > 0 {
				sysRootsReady = true
				return
			}
		}
		for _, p := range []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/ca-bundle.pem",
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/ssl/cert.pem",
		} {
			if st, err := os.Stat(p); err == nil && st.Size() > 0 {
				sysRootsReady = true
				return
			}
		}
	})
	return sysRootsReady
}

// VerifyCertChain checks a presented server certificate chain against trusted roots (or platform
// system roots when roots == nil) and the observed SNI. Returns (true, "") when trusted or when
// verification cannot safely run (fail-open).
func VerifyCertChain(certs []*x509.Certificate, sni string, roots *x509.CertPool, now time.Time) (bool, string) {
	if len(certs) == 0 {
		return true, ""
	}
	if roots == nil && !SystemRootsAvailable() {
		return true, ""
	}
	if now.IsZero() {
		now = time.Now()
	}
	leaf := certs[0]
	var inter *x509.CertPool
	if len(certs) > 1 {
		inter = x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       sni,
		Intermediates: inter,
		Roots:         roots,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := leaf.Verify(opts); err == nil {
		return true, ""
	} else {
		return false, describeCertError(err, leaf, sni)
	}
}

func describeCertError(err error, leaf *x509.Certificate, sni string) string {
	cn := leaf.Subject.CommonName
	if cn == "" && len(leaf.DNSNames) > 0 {
		cn = leaf.DNSNames[0]
	}
	sniTag := sni
	if sniTag == "" {
		sniTag = "-"
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return fmt.Sprintf("cert mismatch sni=%s cn=%s", sniTag, cn)
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
			return fmt.Sprintf("self-signed cert sni=%s cn=%s", sniTag, cn)
		}
		issuer := leaf.Issuer.CommonName
		if issuer == "" && len(leaf.Issuer.Organization) > 0 {
			issuer = leaf.Issuer.Organization[0]
		}
		return fmt.Sprintf("untrusted ca sni=%s issuer=%s", sniTag, issuer)
	}
	var invErr x509.CertificateInvalidError
	if errors.As(err, &invErr) {
		if invErr.Reason == x509.Expired {
			return fmt.Sprintf("expired cert sni=%s cn=%s", sniTag, cn)
		}
		return fmt.Sprintf("invalid cert sni=%s cn=%s", sniTag, cn)
	}
	return fmt.Sprintf("untrusted cert sni=%s cn=%s", sniTag, cn)
}
