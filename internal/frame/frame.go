// Threats: a peer that declares a huge length, a video tile that is not a
// JPEG, and an audio payload that is not aligned PCM. The reader rejects an
// oversize length before it allocates the body. Does NOT authenticate the
// peer; the session layer does that with the lease.
package frame

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const (
	Hello    byte = 1
	Status   byte = 2
	Video    byte = 3
	Audio    byte = 4
	Close    byte = 5
	Lease    byte = 6
	Renew    byte = 7
	Input    byte = 8
	Reject   byte = 9
	Geometry byte = 10

	HelloMagic = "SAHRDP1"
	MaxPayload = 65536
	MaxAudio   = 16384
)

// ErrProtocol is a frame the peer must treat as fatal.
var ErrProtocol = errors.New("protocol_error")

const maxFrame = 1 + MaxPayload

// Write sends one frame. payload may be nil.
func Write(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrProtocol
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(1+len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{typ}); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// Read returns the type and payload. An illegal length is refused before the
// body is allocated.
func Read(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > maxFrame {
		return 0, nil, ErrProtocol
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

// Tile is one JPEG tile. The frame type byte is the Video constant.
type Tile struct {
	X, Y, W, H uint16
	JPEG       []byte
}

// ParseVideo checks the tile header and the JPEG markers.
func ParseVideo(p []byte) (Tile, error) {
	if len(p) < 12 || len(p) > MaxPayload {
		return Tile{}, ErrProtocol
	}
	v := Tile{
		X: binary.BigEndian.Uint16(p[0:2]),
		Y: binary.BigEndian.Uint16(p[2:4]),
		W: binary.BigEndian.Uint16(p[4:6]),
		H: binary.BigEndian.Uint16(p[6:8]),
	}
	if v.W == 0 || v.H == 0 {
		return Tile{}, ErrProtocol
	}
	v.JPEG = append([]byte(nil), p[8:]...)
	if v.JPEG[0] != 0xff || v.JPEG[1] != 0xd8 || v.JPEG[len(v.JPEG)-2] != 0xff || v.JPEG[len(v.JPEG)-1] != 0xd9 {
		return Tile{}, ErrProtocol
	}
	return v, nil
}

// AppendVideo encodes a tile into a payload.
func AppendVideo(v Tile) ([]byte, error) {
	if v.W == 0 || v.H == 0 || len(v.JPEG) < 4 || 8+len(v.JPEG) > MaxPayload {
		return nil, ErrProtocol
	}
	p := make([]byte, 8+len(v.JPEG))
	binary.BigEndian.PutUint16(p[0:2], v.X)
	binary.BigEndian.PutUint16(p[2:4], v.Y)
	binary.BigEndian.PutUint16(p[4:6], v.W)
	binary.BigEndian.PutUint16(p[6:8], v.H)
	copy(p[8:], v.JPEG)
	if _, err := ParseVideo(p); err != nil {
		return nil, err
	}
	return p, nil
}

// PCM is one audio chunk. Format 1 is signed 16-bit little-endian.
// The frame type byte is the Audio constant.
type PCM struct {
	Rate     uint32
	Channels uint16
	Format   uint16
	PCM      []byte
}

// ParseAudio checks rate, channel count, format, and alignment.
func ParseAudio(p []byte) (PCM, error) {
	if len(p) < 10 || len(p) > MaxAudio {
		return PCM{}, ErrProtocol
	}
	a := PCM{
		Rate:     binary.BigEndian.Uint32(p[0:4]),
		Channels: binary.BigEndian.Uint16(p[4:6]),
		Format:   binary.BigEndian.Uint16(p[6:8]),
		PCM:      append([]byte(nil), p[8:]...),
	}
	if !allowedRate(a.Rate) || (a.Channels != 1 && a.Channels != 2) || a.Format != 1 {
		return PCM{}, ErrProtocol
	}
	unit := int(a.Channels) * 2
	if len(a.PCM) == 0 || len(a.PCM)%unit != 0 {
		return PCM{}, ErrProtocol
	}
	return a, nil
}

// AppendAudio encodes one PCM chunk.
func AppendAudio(a PCM) ([]byte, error) {
	if _, err := ParseAudio(encodeAudioUnchecked(a)); err != nil {
		return nil, err
	}
	return encodeAudioUnchecked(a), nil
}

func encodeAudioUnchecked(a PCM) []byte {
	p := make([]byte, 8+len(a.PCM))
	binary.BigEndian.PutUint32(p[0:4], a.Rate)
	binary.BigEndian.PutUint16(p[4:6], a.Channels)
	binary.BigEndian.PutUint16(p[6:8], a.Format)
	copy(p[8:], a.PCM)
	return p
}

func allowedRate(r uint32) bool {
	switch r {
	case 8000, 16000, 44100, 48000:
		return true
	default:
		return false
	}
}

// Size is the captured picture size. The frame type byte is the Geometry constant.
type Size struct {
	Width  uint16 `json:"width"`
	Height uint16 `json:"height"`
}

// DecodeJSON decodes one object and refuses unknown fields and trailing data.
func DecodeJSON(p []byte, dest any) error {
	if len(p) == 0 || len(p) > MaxPayload {
		return ErrProtocol
	}
	dec := json.NewDecoder(bytesReader(p))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return ErrProtocol
	}
	if dec.More() || dec.InputOffset() != int64(len(p)) {
		return ErrProtocol
	}
	return nil
}

type byteReader struct {
	b []byte
	i int
}

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
