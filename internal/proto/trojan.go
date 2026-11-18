package proto

import "bytes"

var trojanCCSPattern = []byte{20, 3, 3, 0, 1, 1}

// TrojanTracker detects TLS-in-TLS length-sequence heuristics after client ChangeCipherSpec.
// Note: Unlike OpenGFW's buggy initialization (`first == false`), firstChecked is properly initialized.
type TrojanTracker struct {
	checkedFirst bool
	counting     bool
	lastRev      bool
	seq          [4]int
	seqIdx       int
}

// Feed processes one reassembled TCP chunk for Trojan length-sequence analysis.
// Returns (matched, done).
func (t *TrojanTracker) Feed(rev bool, data []byte) (matched bool, done bool) {
	if len(data) == 0 {
		return false, false
	}
	if !t.checkedFirst {
		t.checkedFirst = true
		if rev || len(data) < 3 || data[0] != 0x16 || data[1] != 0x03 || data[2] > 0x09 {
			return false, true
		}
	}
	if !rev && !t.counting && len(data) >= 6 {
		if idx := bytes.Index(data, trojanCCSPattern); idx >= 0 && idx+6 <= len(data) {
			t.counting = true
			// Count remaining bytes in this flight after CCS (or from CCS if segmented).
			data = data[idx:]
		}
	}
	if t.counting {
		if rev == t.lastRev {
			t.seq[t.seqIdx] += len(data)
		} else {
			t.seqIdx++
			if t.seqIdx == 4 {
				return isTrojanSeq(t.seq), true
			}
			t.seq[t.seqIdx] += len(data)
			t.lastRev = rev
		}
	}
	return false, false
}

// isTrojanSeq implements the 4-flight encrypted length heuristic from OpenGFW.
func isTrojanSeq(seq [4]int) bool {
	l1, l2, l3, l4 := seq[0], seq[1], seq[2], seq[3]
	if l2 <= 2431 {
		if l2 <= 157 {
			if l1 <= 156 {
				return false
			}
			if l1 <= 892 {
				if l3 <= 40 {
					return false
				}
				if l3 <= 788 {
					if l4 <= 185 {
						return l1 <= 411
					}
					return l2 > 112
				}
				return l3 <= 1346 && l1 > 418
			}
			return false
		}
		if l1 <= 206 {
			if l1 <= 185 {
				return false
			}
			return l2 <= 251
		}
		if l2 <= 286 {
			if l1 <= 1123 {
				if l3 <= 70 {
					return false
				}
				if l1 <= 659 {
					return l3 <= 370
				}
				return l4 > 272
			}
			if l4 <= 537 {
				return false
			}
			return l1 <= 1466 && l1 > 1435
		}
		if l1 <= 284 {
			if l1 <= 277 {
				return l2 > 726 && l2 <= 768
			}
			return l2 <= 782 && l4 <= 783
		}
		if l2 <= 492 && l2 > 396 && l4 > 971 {
			return true
		}
		return false
	}
	if l2 <= 6232 {
		if l3 <= 85 {
			return false
		}
		if l3 <= 220 {
			if l4 <= 1173 {
				if l1 <= 874 {
					return true
				}
				if l3 <= 108 {
					return true
				}
				return l2 > 5383
			}
			return false
		}
		if l1 <= 664 {
			if l3 <= 411 {
				if l3 <= 383 {
					return l4 <= 346
				}
				return l1 <= 445
			}
			return l2 <= 3708 && l4 <= 307
		}
		if l1 <= 1055 {
			if l3 <= 580 {
				return l1 <= 724
			}
			return l1 > 678
		}
		return l2 > 5352 && l4 <= 2173
	}
	if l2 <= 9408 {
		if l1 <= 670 {
			if l4 <= 76 {
				return true
			}
			return l2 > 9072
		}
		if l1 <= 795 {
			if l2 <= 6334 {
				return l2 <= 6288
			}
			if l4 <= 6404 {
				return true
			}
			return l2 > 8924
		}
		return l3 > 732 && l1 <= 2840 && l1 > 2591
	}
	return l4 > 30 && l2 <= 13314 && l4 <= 1786 && l2 > 13018
}
