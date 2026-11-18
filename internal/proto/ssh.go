package proto

import (
	"bytes"
	"strings"
)

// SSHResult classifies an SSH protocol exchange line.
type SSHResult int

const (
	SSHNone SSHResult = iota
	SSHNeedMore
	SSHMatched
	SSHNotSSH
)

// DetectSSH parses RFC 4253 SSH version banner ("SSH-2.0-...").
func DetectSSH(client []byte) (SSHResult, string) {
	if len(client) == 0 {
		return SSHNeedMore, ""
	}
	prefix := []byte("SSH-")
	if len(client) < len(prefix) {
		if bytes.HasPrefix(prefix, client) {
			return SSHNeedMore, ""
		}
		return SSHNotSSH, ""
	}
	if !bytes.HasPrefix(client, prefix) {
		return SSHNotSSH, ""
	}
	nl := bytes.IndexByte(client, '\n')
	if nl < 0 {
		if len(client) > 256 {
			return SSHNotSSH, ""
		}
		return SSHNeedMore, ""
	}
	banner := strings.TrimRight(string(client[:nl]), "\r\n")
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 || parts[1] == "" {
		return SSHNotSSH, ""
	}
	return SSHMatched, banner
}
