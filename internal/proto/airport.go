package proto

import (
	"bytes"
	"strings"
)

type airportPathSig struct {
	prefix string
	label  string
}

// Strict commercial airport panel & backend sync paths (V2Board / Xboard / SSPanel / PPanel).
// Intentionally excludes personal node-management panels such as 3x-ui, x-ui, and s-ui.
var airportPathSigs = []airportPathSig{
	{prefix: "/api/v1/server/uniproxy/", label: "v2board/xboard uniproxy"},
	{prefix: "/api/v1/server/deepbwork/", label: "v2board deepbwork"},
	{prefix: "/api/v1/server/trojantornado/", label: "v2board trojantornado"},
	{prefix: "/api/v1/server/shadowsockst/", label: "v2board shadowsockst"},
	{prefix: "/api/v1/passport/auth/", label: "v2board/xboard passport"},
	{prefix: "/api/v1/client/subscribe", label: "v2board/xboard subscribe"},
	{prefix: "/api/v1/guest/comm/config", label: "v2board/xboard config"},
	{prefix: "/api/v1/user/getsubscribe", label: "v2board/xboard user-sub"},
	{prefix: "/mod_mu/nodes", label: "sspanel mod_mu nodes"},
	{prefix: "/mod_mu/users", label: "sspanel mod_mu users"},
	{prefix: "/mod_mu/func/ping", label: "sspanel mod_mu ping"},
	{prefix: "/mod_mu/func/detect_rules", label: "sspanel mod_mu detect"},
}

// DetectAirportHTTPRequest checks whether an HTTP/1.x request targets a known commercial
// airport panel endpoint (frontend auth/subscribe or V2bX/XrayR/Soga backend sync API).
func DetectAirportHTTPRequest(info HTTPInfo) (bool, string) {
	path := normalizeHTTPTargetPath(info.Target)
	if path == "" {
		return false, ""
	}
	for _, sig := range airportPathSigs {
		if strings.HasPrefix(path, sig.prefix) {
			return true, sig.label
		}
	}
	return false, ""
}

// IsAirportHomepageCandidate returns true for root/login GET paths where inspecting the
// first plaintext HTTP response chunk can identify a hosted commercial airport homepage.
func IsAirportHomepageCandidate(info HTTPInfo) bool {
	if info.Method != "GET" {
		return false
	}
	path := normalizeHTTPTargetPath(info.Target)
	return path == "/" || path == "/index.html" || path == "/auth/login"
}

func normalizeHTTPTargetPath(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return ""
	}
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		if idx := strings.Index(t, "://"); idx >= 0 {
			rest := t[idx+3:]
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				t = rest[slash:]
			} else {
				return "/"
			}
		}
	}
	if q := strings.IndexByte(t, '?'); q >= 0 {
		t = t[:q]
	}
	return t
}

// DetectAirportHTTPResponse inspects an HTTP/1.x response (headers + initial HTML body)
// for unmistakable commercial airport panel markers (V2Board / Xboard / SSPanel / PPanel).
// Personal single-node panels (3x-ui / x-ui / s-ui), normal websites, and REALITY targets
// never match these signatures.
func DetectAirportHTTPResponse(raw []byte) (bool, string) {
	if len(raw) < 12 || !bytes.HasPrefix(raw, []byte("HTTP/1.")) {
		return false, ""
	}
	lower := strings.ToLower(string(raw))
	hdrPart, bodyPart, hasBody := strings.Cut(lower, "\r\n\r\n")
	if !hasBody {
		hdrPart = lower
	}

	// 1. Session cookie / header signatures
	if strings.Contains(hdrPart, "v2board_session=") {
		return true, "v2board panel"
	}
	if strings.Contains(hdrPart, "xboard_session=") {
		return true, "xboard panel"
	}
	if strings.Contains(hdrPart, "set-cookie:") && strings.Contains(hdrPart, "expire_in=") &&
		(strings.Contains(hdrPart, "uid=") || strings.Contains(hdrPart, "key=")) {
		return true, "sspanel cookie"
	}

	if !hasBody || len(bodyPart) == 0 {
		return false, ""
	}

	// 2. HTML / asset signatures
	if strings.Contains(bodyPart, "/theme/v2board/") || strings.Contains(bodyPart, "assets/v2board") || strings.Contains(bodyPart, "v2board.min.js") {
		return true, "v2board html"
	}
	if strings.Contains(bodyPart, "/theme/xboard/") || strings.Contains(bodyPart, "assets/xboard") || strings.Contains(bodyPart, "xboard.min.js") {
		return true, "xboard html"
	}
	if strings.Contains(bodyPart, "window.settings") &&
		(strings.Contains(bodyPart, "is_email_verify") || strings.Contains(bodyPart, "is_invite_force") ||
			strings.Contains(bodyPart, "v2board") || strings.Contains(bodyPart, "xboard")) {
		return true, "v2board/xboard settings"
	}
	if strings.Contains(bodyPart, "sspanel-uim") || strings.Contains(bodyPart, "sspanel_uim") ||
		strings.Contains(bodyPart, "powered by sspanel") ||
		(strings.Contains(bodyPart, "/theme/malio/") && strings.Contains(bodyPart, "sspanel")) ||
		(strings.Contains(bodyPart, "metron.css") && (strings.Contains(bodyPart, "sspanel") || strings.Contains(bodyPart, "metron"))) {
		return true, "sspanel html"
	}
	if strings.Contains(bodyPart, "next_public_ppanel") || strings.Contains(bodyPart, "ppanel-user") || strings.Contains(bodyPart, "ppanel.dev") {
		return true, "ppanel html"
	}

	return false, ""
}
