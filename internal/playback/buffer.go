// Package playback provides bounded, nonblocking local audio delivery.
package playback

import (
	"io"
	"sync"

	"github.com/afterdarksys/sahrdp/internal/frame"
)

// Buffer converts authorized PCM to 48 kHz stereo s16le. The simple sample-hold
// conversion preserves timing across packets. It is not a high fidelity resampler.
// At most 200 ms is retained; overflow discards oldest local playback samples.
// Host recording is unaffected. Underflow produces silence rather than blocking video.
type Buffer struct {
	mu            sync.Mutex
	data          []byte
	phase         uint32
	rate          uint32
	muted, closed bool
}

const Capacity = 48000 * 4 / 5

func NewBuffer() *Buffer { return &Buffer{muted: true} }
func (b *Buffer) Mute(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.muted = v
	b.data = nil
	b.phase = 0
}
func (b *Buffer) Push(a frame.PCM) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.muted {
		return
	}
	if a.Format != 1 || (a.Channels != 1 && a.Channels != 2) {
		return
	}
	switch a.Rate {
	case 8000, 16000, 44100, 48000:
	default:
		return
	}
	unit := int(a.Channels) * 2
	if len(a.PCM)%unit != 0 || len(a.PCM) > frame.MaxAudio-8 {
		return
	}
	if b.rate != a.Rate {
		b.phase = 0
		b.rate = a.Rate
	}
	for i := 0; i < len(a.PCM); i += unit {
		left := a.PCM[i : i+2]
		right := left
		if unit == 4 {
			right = a.PCM[i+2 : i+4]
		}
		b.phase += 48000
		for b.phase >= a.Rate {
			b.data = append(b.data, left...)
			b.data = append(b.data, right...)
			b.phase -= a.Rate
		}
	}
	if len(b.data) > Capacity {
		copy(b.data, b.data[len(b.data)-Capacity:])
		b.data = b.data[:Capacity]
	}
}
func (b *Buffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	copy(b.data, b.data[n:])
	b.data = b.data[:len(b.data)-n]
	clear(p[n:])
	return len(p), nil
}
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.data = nil
	return nil
}
