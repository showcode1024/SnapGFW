package proto

import "bytes"

var btHandshakePrefix = []byte("\x13BitTorrent protocol")

// DetectBitTorrentTCP checks for BitTorrent peer wire handshake.
func DetectBitTorrentTCP(client []byte) (matched bool, needMore bool) {
	if len(client) == 0 {
		return false, true
	}
	if len(client) < len(btHandshakePrefix) {
		if bytes.HasPrefix(btHandshakePrefix, client) {
			return false, true
		}
		return false, false
	}
	return bytes.HasPrefix(client, btHandshakePrefix), false
}

// DetectBitTorrentUDP checks for BitTorrent DHT (KRPC bencode) or uTP-over-DHT queries.
func DetectBitTorrentUDP(data []byte) (bool, string) {
	if len(data) < 16 {
		return false, ""
	}
	// KRPC messages are bencoded dictionaries starting with 'd' and ending with 'e'
	if data[0] == 'd' && data[len(data)-1] == 'e' {
		if bytes.Contains(data, []byte("2:id20:")) &&
			(bytes.Contains(data, []byte("1:q4:ping")) ||
				bytes.Contains(data, []byte("1:q9:find_node")) ||
				bytes.Contains(data, []byte("1:q9:get_peers")) ||
				bytes.Contains(data, []byte("1:q13:announce_peer")) ||
				bytes.Contains(data, []byte("1:y1:q")) ||
				bytes.Contains(data, []byte("1:y1:r"))) {
			return true, "bt-dht"
		}
	}
	return false, ""
}
