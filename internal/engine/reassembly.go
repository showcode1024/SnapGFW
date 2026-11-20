package engine

import "sort"

const maxBufferedOOOChunks = 16

type oooChunk struct {
	seq  uint32
	data []byte
}

// tcpHalfReassembler performs bounded in-order TCP prefix reassembly for one direction.
// It handles SYN initialization, retransmission overlap trimming, and out-of-order segments
// up to maxBytes without retaining large packet pools.
type tcpHalfReassembler struct {
	initialized bool
	nextSeq     uint32
	emitted     int
	maxBytes    int
	ooo         []oooChunk
}

func newTCPHalfReassembler(maxBytes int) tcpHalfReassembler {
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	return tcpHalfReassembler{maxBytes: maxBytes}
}

// Capped reports whether this half-stream has emitted its configured inspection prefix budget.
func (r *tcpHalfReassembler) Capped() bool {
	return r.emitted >= r.maxBytes
}

// Push processes one TCP segment and returns newly contiguous bytes (up to maxBytes total)
// plus midStream=true if a non-SYN packet arrives before initialization.
func (r *tcpHalfReassembler) Push(seq uint32, flags uint8, payload []byte) (contiguous []byte, midStream bool) {
	if flags&TCPFlagSYN != 0 {
		r.initialized = true
		r.nextSeq = seq + 1
		if len(payload) == 0 {
			return nil, false
		}
		seq = r.nextSeq
	} else if !r.initialized {
		return nil, true
	}

	if r.emitted >= r.maxBytes || len(payload) == 0 {
		return nil, false
	}

	diff := seqDiff(seq, r.nextSeq)
	if diff <= 0 {
		// Starts at or before nextSeq (in-order or partial overlap/retransmission)
		overlap := int(-diff)
		if overlap >= len(payload) {
			return nil, false
		}
		fresh := payload[overlap:]
		rem := r.maxBytes - r.emitted
		if len(fresh) > rem {
			fresh = fresh[:rem]
		}
		contiguous = append(contiguous, fresh...)
		r.nextSeq += uint32(len(fresh))
		r.emitted += len(fresh)
		// Drain buffered out-of-order chunks that are now contiguous
		contiguous = append(contiguous, r.drainOOO()...)
		return contiguous, false
	}

	// Out-of-order segment ahead of nextSeq: buffer within bounded limit
	if int(diff) > r.maxBytes || len(r.ooo) >= maxBufferedOOOChunks {
		return nil, false
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	r.ooo = append(r.ooo, oooChunk{seq: seq, data: cp})
	sort.Slice(r.ooo, func(i, j int) bool {
		return seqDiff(r.ooo[i].seq, r.ooo[j].seq) < 0
	})
	return nil, false
}

func (r *tcpHalfReassembler) drainOOO() []byte {
	var out []byte
	for len(r.ooo) > 0 && r.emitted < r.maxBytes {
		c := r.ooo[0]
		diff := seqDiff(c.seq, r.nextSeq)
		if diff > 0 {
			break
		}
		r.ooo = r.ooo[1:]
		overlap := int(-diff)
		if overlap >= len(c.data) {
			continue
		}
		fresh := c.data[overlap:]
		rem := r.maxBytes - r.emitted
		if len(fresh) > rem {
			fresh = fresh[:rem]
		}
		out = append(out, fresh...)
		r.nextSeq += uint32(len(fresh))
		r.emitted += len(fresh)
	}
	if r.emitted >= r.maxBytes {
		r.ooo = nil
	}
	return out
}

// seqDiff computes signed modular 32-bit TCP sequence difference (a - b).
func seqDiff(a, b uint32) int32 {
	return int32(a - b)
}
