//go:build linux

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"natgfw/internal/proto"
)

// NFQueueSource opens 4 Linux NFQUEUE queues (QueueBase..QueueBase+3) matching
// the 4 unambiguous (flow_direction, packet_direction) combinations in inet natgfw.
type NFQueueSource struct {
	queueBase      uint16
	queueLen       uint32
	rcvBuf         int
	connMarkAccept uint32
	connMarkDrop   uint32

	mu     sync.Mutex
	queues []*nfqueue.Nfqueue
}

// NewNFQueueSource configures Linux NFQUEUE binding parameters.
func NewNFQueueSource(queueBase uint16, queueLen uint32, rcvBuf int, markAccept, markDrop uint32) *NFQueueSource {
	return &NFQueueSource{
		queueBase:      queueBase,
		queueLen:       queueLen,
		rcvBuf:         rcvBuf,
		connMarkAccept: markAccept,
		connMarkDrop:   markDrop,
	}
}

// Start opens and registers all 4 NFQUEUE handles until ctx is cancelled.
func (s *NFQueueSource) Start(ctx context.Context, onPacket func(PacketEvent)) error {
	type qMeta struct {
		offset uint16
		dir    proto.Direction
		rev    bool
	}
	defs := []qMeta{
		{0, proto.DirInbound, false},  // QueueBase+0: inbound original (external -> tenant)
		{1, proto.DirOutbound, false}, // QueueBase+1: outbound original (tenant -> external)
		{2, proto.DirOutbound, true},  // QueueBase+2: outbound reply (external -> tenant)
		{3, proto.DirInbound, true},   // QueueBase+3: inbound reply (tenant -> external)
	}

	s.mu.Lock()
	for _, d := range defs {
		qNum := s.queueBase + d.offset
		nfq, err := nfqueue.Open(&nfqueue.Config{
			NfQueue:      qNum,
			MaxPacketLen: 0xFFFF,
			MaxQueueLen:  s.queueLen,
			Copymode:     nfqueue.NfQnlCopyPacket,
			Flags:        nfqueue.NfQaCfgFlagConntrack,
		})
		if err != nil {
			s.mu.Unlock()
			_ = s.Close()
			return fmt.Errorf("open nfqueue %d: %w", qNum, err)
		}
		if s.rcvBuf > 0 {
			// go-nfqueue wraps mdlayher/netlink -> mdlayher/socket which attempts SO_RCVBUFFORCE first.
			_ = nfq.Con.SetReadBuffer(s.rcvBuf)
		}
		s.queues = append(s.queues, nfq)

		qMetaCopy := d
		qPtr := nfq
		err = qPtr.RegisterWithErrorFunc(ctx,
			func(a nfqueue.Attribute) int {
				if a.PacketID == nil {
					return 0
				}
				pktID := *a.PacketID
				if a.Payload == nil || len(*a.Payload) < 20 {
					_ = qPtr.SetVerdict(pktID, nfqueue.NfDrop)
					return 0
				}
				if a.Ct == nil {
					_ = qPtr.SetVerdict(pktID, nfqueue.NfAccept)
					return 0
				}
				streamID := extractCtID(*a.Ct)
				ev := PacketEvent{
					PacketID:  pktID,
					QueueNum:  qNum,
					StreamID:  streamID,
					Direction: qMetaCopy.dir,
					Reverse:   qMetaCopy.rev,
					Data:      *a.Payload,
					SetVerdict: func(v Verdict) error {
						switch v {
						case VerdictAccept:
							return qPtr.SetVerdict(pktID, nfqueue.NfAccept)
						case VerdictAcceptStream:
							return qPtr.SetVerdictWithConnMark(pktID, nfqueue.NfAccept, int(s.connMarkAccept))
						case VerdictDrop:
							return qPtr.SetVerdict(pktID, nfqueue.NfDrop)
						case VerdictDropStream:
							return qPtr.SetVerdictWithConnMark(pktID, nfqueue.NfDrop, int(s.connMarkDrop))
						default:
							return qPtr.SetVerdict(pktID, nfqueue.NfAccept)
						}
					},
				}
				onPacket(ev)
				return 0
			},
			func(e error) int {
				var opErr *netlink.OpError
				if errors.As(e, &opErr) && errors.Is(opErr.Err, unix.ENOBUFS) {
					return 0
				}
				return 0
			},
		)
		if err != nil {
			s.mu.Unlock()
			_ = s.Close()
			return fmt.Errorf("register nfqueue %d: %w", qNum, err)
		}
	}
	s.mu.Unlock()

	<-ctx.Done()
	return s.Close()
}

// Close closes all NFQUEUE netlink sockets.
func (s *NFQueueSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range s.queues {
		_ = q.Close()
	}
	s.queues = nil
	return nil
}

func extractCtID(ct []byte) uint32 {
	attrs, err := netlink.UnmarshalAttributes(ct)
	if err != nil {
		return 0
	}
	for _, a := range attrs {
		if a.Type == 12 && len(a.Data) >= 4 { // CTA_ID
			return binary.BigEndian.Uint32(a.Data)
		}
	}
	return 0
}
