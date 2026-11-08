package playback

import (
	"bytes"
	"github.com/afterdarksys/sahrdp/internal/frame"
	"io"
	"testing"
)

func TestMuteAndCloseDiscardAudio(t *testing.T) {
	b := NewBuffer()
	a := frame.PCM{Rate: 48000, Channels: 1, Format: 1, PCM: []byte{1, 2}}
	b.Push(a)
	p := make([]byte, 4)
	b.Read(p)
	if !bytes.Equal(p, make([]byte, 4)) {
		t.Fatal("default mute failed")
	}
	b.Mute(false)
	b.Push(a)
	b.Read(p)
	if !bytes.Equal(p, []byte{1, 2, 1, 2}) {
		t.Fatal(p)
	}
	b.Push(a)
	b.Mute(true)
	b.Mute(false)
	b.Read(p)
	if !bytes.Equal(p, make([]byte, 4)) {
		t.Fatal("stale audio after unmute")
	}
	b.Close()
	b.Push(a)
	if _, err := b.Read(p); err != io.EOF {
		t.Fatal(err)
	}
}
func TestRateConversionAcrossPacketsAndBound(t *testing.T) {
	for _, rate := range []uint32{8000, 16000, 44100, 48000} {
		b := NewBuffer()
		b.Mute(false)
		// 10 ms in single-sample packets must produce exactly 480 stereo samples.
		for i := uint32(0); i < rate/100; i++ {
			b.Push(frame.PCM{Rate: rate, Channels: 1, Format: 1, PCM: []byte{1, 2}})
		}
		if len(b.data) != 480*4 {
			t.Fatalf("rate %d: %d", rate, len(b.data))
		}
		for i := 0; i < 100; i++ {
			b.Push(frame.PCM{Rate: 8000, Channels: 1, Format: 1, PCM: make([]byte, 16000)})
		}
		if len(b.data) != Capacity {
			t.Fatal(len(b.data))
		}
	}
}
