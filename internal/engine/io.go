package engine

import (
	"context"

	"natgfw/internal/proto"
)

// Verdict represents the NFQUEUE decision for a packet/stream.
type Verdict int

const (
	VerdictAccept       Verdict = iota // Accept this packet, keep evaluating future packets
	VerdictAcceptStream                // Accept packet and offload stream in kernel (ct mark ACCEPT)
	VerdictDrop                        // Drop this packet only
	VerdictDropStream                  // Drop packet and block stream in kernel (ct mark DROP)
)

// PacketEvent represents one packet delivered from kernel NFQUEUE (or unit test).
type PacketEvent struct {
	PacketID   uint32
	QueueNum   uint16
	StreamID   uint32
	Direction  proto.Direction // Inferred unambiguously from queue number (in / out)
	Reverse    bool            // True if packet is in reply direction (server -> client)
	Data       []byte
	SetVerdict func(Verdict) error
}

// PacketSource abstracts Linux NFQUEUE registration for testability across OSes.
type PacketSource interface {
	Start(ctx context.Context, onPacket func(PacketEvent)) error
	Close() error
}
