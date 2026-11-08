//go:build desktop

package desktop

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/sahrdp/internal/playback"
	"github.com/ebitengine/oto/v3"
)

// Oto permits one process-wide device context; players belong to individual
// sessions so closing a connection cannot leak its audio into the next session.
var audioDevice struct {
	once  sync.Once
	ctx   *oto.Context
	ready chan struct{}
	err   error
}

func startAudio(ctx context.Context, b *playback.Buffer) (*oto.Player, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	audioDevice.once.Do(func() {
		audioDevice.ctx, audioDevice.ready, audioDevice.err = oto.NewContext(&oto.NewContextOptions{
			SampleRate: 48000, ChannelCount: 2, Format: oto.FormatSignedInt16LE, BufferSize: 20 * time.Millisecond,
		})
	})
	if audioDevice.err != nil {
		return nil, audioDevice.err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-audioDevice.ready:
	}
	if err := audioDevice.ctx.Err(); err != nil {
		return nil, err
	}
	p := audioDevice.ctx.NewPlayer(b)
	p.SetBufferSize(48000 * 4 / 50)
	p.Play()
	return p, nil
}
