package proto

import "bytes"

// BuiltinMiningPoolDomains provides common public cryptocurrency mining pool root domains
// matched via TLS/QUIC SNI and DNS when the mining protocol detector is enabled.
var BuiltinMiningPoolDomains = []string{
	"supportxmr.com",
	"nanopool.org",
	"f2pool.com",
	"poolin.com",
	"poolin.me",
	"hashvault.pro",
	"herominers.com",
	"2miners.com",
	"moneroocean.stream",
	"nicehash.com",
	"viabtc.io",
	"viabtc.com",
	"antpool.com",
	"ethermine.org",
	"flexpool.io",
	"kryptex.network",
	"unmineable.com",
	"c3pool.com",
	"minexmr.com",
	"hiveon.net",
	"woolypooly.com",
	"dxpool.com",
	"cruxpool.com",
	"emcd.io",
	"braiins.com",
	"slushpool.com",
	"luxor.tech",
	"spiderpool.com",
}

// MiningStatus indicates plaintext Stratum JSON-RPC mining handshake progress.
type MiningStatus int

const (
	MiningNotMining MiningStatus = iota
	MiningNeedMore
	MiningMatched
)

var stratumMethods = [][]byte{
	[]byte(`"mining.subscribe"`),
	[]byte(`"mining.authorize"`),
	[]byte(`"mining.submit"`),
	[]byte(`"mining.extranonce.subscribe"`),
	[]byte(`"eth_submitlogin"`),
	[]byte(`"eth_getwork"`),
}

var minerAgentMarkers = [][]byte{
	[]byte("xmrig"),
	[]byte("xmr-stak"),
	[]byte("srbminer"),
	[]byte("gminer"),
	[]byte("nbminer"),
	[]byte("lolminer"),
	[]byte("t-rex"),
	[]byte("nanominer"),
	[]byte("teamredminer"),
	[]byte("bzminer"),
}

// DetectStratumTCP detects raw newline-delimited JSON-RPC Stratum mining handshakes
// without false positives on standard HTTP requests.
func DetectStratumTCP(c []byte) (MiningStatus, string) {
	trimmed := bytes.TrimLeft(c, " \t")
	if len(trimmed) == 0 {
		return MiningNeedMore, ""
	}
	if trimmed[0] != '{' {
		return MiningNotMining, ""
	}

	limit := min(len(trimmed), 768)
	nl := bytes.IndexByte(trimmed[:limit], '\n')
	var line []byte
	if nl >= 0 {
		line = trimmed[:nl]
	} else {
		if len(trimmed) < 512 {
			// Verify printable JSON bytes before waiting for newline
			for _, b := range trimmed {
				if (b < 0x20 && b != '\t' && b != '\r') || b == 0x7f {
					return MiningNotMining, ""
				}
			}
			return MiningNeedMore, ""
		}
		line = trimmed[:limit]
	}

	if !bytes.Contains(line, []byte(":")) {
		return MiningNotMining, ""
	}
	lower := bytes.ToLower(line)

	if bytes.Contains(lower, []byte(`"method"`)) {
		for _, m := range stratumMethods {
			if bytes.Contains(lower, m) {
				return MiningMatched, "stratum " + string(bytes.Trim(m, `"`))
			}
		}
		// CryptoNote Stratum login (e.g. XMRig: {"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"...","agent":"XMRig/..."}})
		if bytes.Contains(lower, []byte(`"login"`)) && bytes.Contains(lower, []byte(`"params"`)) {
			for _, ag := range minerAgentMarkers {
				if bytes.Contains(lower, ag) {
					return MiningMatched, "stratum cryptonote (" + string(ag) + ")"
				}
			}
			if bytes.Contains(lower, []byte(`"pass"`)) && (bytes.Contains(lower, []byte(`"rigid"`)) || bytes.Contains(lower, []byte(`"algo"`))) {
				return MiningMatched, "stratum cryptonote login"
			}
		}
	}
	return MiningNotMining, ""
}
