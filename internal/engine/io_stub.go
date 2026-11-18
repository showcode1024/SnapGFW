//go:build !linux

package engine

import (
	"context"
	"errors"
)

// NewNFQueueSource returns an error outside Linux because NFQUEUE is Linux-only.
func NewNFQueueSource(queueBase uint16, queueLen uint32, rcvBuf int, markAccept, markDrop uint32) PacketSource {
	return &unsupportedSource{}
}

type unsupportedSource struct{}

func (u *unsupportedSource) Start(ctx context.Context, onPacket func(PacketEvent)) error {
	return errors.New("nfqueue packet engine requires Linux")
}

func (u *unsupportedSource) Close() error { return nil }
