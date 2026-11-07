package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type guardReader struct {
	b   []byte
	n   int
	big bool
}

func (g *guardReader) Read(p []byte) (int, error) {
	if len(p) > 64 {
		g.big = true
		return 0, errors.New("big")
	}
	if len(g.b) == 0 {
		return 0, io.EOF
	}
	k := copy(p, g.b)
	g.b = g.b[k:]
	g.n += k
	return k, nil
}

func TestReadRejectsDeclaredLength(t *testing.T) {
	for _, n := range []uint32{0, 65538, 0x7fffffff} {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], n)
		r := &guardReader{b: append([]byte(nil), hdr[:]...)}
		_, _, err := Read(r)
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("%d: %v", n, err)
		}
		if r.n != 4 || r.big {
			t.Fatalf("%d consumed %d big %v", n, r.n, r.big)
		}
	}
}

func TestWriteRejectsOversize(t *testing.T) {
	var b bytes.Buffer
	err := Write(&b, Video, bytes.Repeat([]byte{1}, MaxPayload+1))
	if !errors.Is(err, ErrProtocol) || b.Len() != 0 {
		t.Fatalf("%v %d", err, b.Len())
	}
}

func TestVideoRoundTrip(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0x11, 0xff, 0xd9}
	p, err := AppendVideo(Tile{X: 1, Y: 2, W: 3, H: 4, JPEG: jpeg})
	if err != nil {
		t.Fatal(err)
	}
	jpeg[2] = 0
	v, err := ParseVideo(p)
	if err != nil {
		t.Fatal(err)
	}
	if v.X != 1 || v.Y != 2 || v.W != 3 || v.H != 4 || !bytes.Equal(v.JPEG, []byte{0xff, 0xd8, 0x11, 0xff, 0xd9}) {
		t.Fatalf("%+v", v)
	}
	v.JPEG[2] = 9
	if p[10] != 0x11 {
		t.Fatal("payload aliases caller")
	}
	if _, err := ParseVideo(p[:11]); err == nil {
		t.Fatal("short marker")
	}
	bad := append([]byte(nil), p...)
	bad[8] = 0
	if _, err := ParseVideo(bad); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if _, err := AppendVideo(Tile{W: 0, H: 1, JPEG: jpeg}); !errors.Is(err, ErrProtocol) {
		t.Fatal("zero width")
	}
}

func TestAudioRoundTrip(t *testing.T) {
	pcm := []byte{0x01, 0x02, 0x03, 0x04}
	p, err := AppendAudio(PCM{Rate: 48000, Channels: 2, Format: 1, PCM: pcm})
	if err != nil {
		t.Fatal(err)
	}
	pcm[0] = 0
	a, err := ParseAudio(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Rate != 48000 || a.Channels != 2 || a.Format != 1 || !bytes.Equal(a.PCM, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("%+v", a)
	}
	if _, err := ParseAudio(p[:len(p)-1]); !errors.Is(err, ErrProtocol) {
		t.Fatal("misaligned")
	}
	mono := append([]byte(nil), p...)
	binary.BigEndian.PutUint16(mono[4:6], 3)
	if _, err := ParseAudio(mono); !errors.Is(err, ErrProtocol) {
		t.Fatal("channels")
	}
	rate := append([]byte(nil), p...)
	binary.BigEndian.PutUint32(rate[0:4], 8001)
	if _, err := ParseAudio(rate); !errors.Is(err, ErrProtocol) {
		t.Fatal("rate")
	}
	if _, err := AppendAudio(PCM{Rate: 8000, Channels: 1, Format: 1, PCM: nil}); !errors.Is(err, ErrProtocol) {
		t.Fatal("empty")
	}
}

func TestDecodeJSON(t *testing.T) {
	var g Size
	if err := DecodeJSON([]byte(`{"width":8,"height":4}`), &g); err != nil || g.Width != 8 || g.Height != 4 {
		t.Fatal(err, g)
	}
	if err := DecodeJSON([]byte(`{"width":8,"height":4,"alg":1}`), &g); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if err := DecodeJSON([]byte(`{"width":8,"height":4}{}`), &g); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if err := DecodeJSON(nil, &g); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, Hello, []byte(HelloMagic)); err != nil {
		t.Fatal(err)
	}
	typ, p, err := Read(&b)
	if err != nil || typ != Hello || string(p) != HelloMagic {
		t.Fatal(typ, p, err)
	}
}
