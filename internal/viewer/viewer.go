// Package viewer turns validated sahrdp/1 events into a desktop framebuffer.
package viewer

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/draw"
	"image/jpeg"
	"io"
	"os/exec"
	"sync"

	"github.com/afterdarksys/sahrdp/internal/frame"
	"github.com/afterdarksys/sahrdp/internal/session"
)

// Update owns its image; later frames never mutate images already delivered.
type Update struct {
	Status *session.Status
	Image  image.Image
	Close  *session.Close
	Audio  *frame.PCM
}

// Read consumes a live stream and emits only validated media.
// The caller owns r and must close it to interrupt a blocked read.
func Read(ctx context.Context, r io.Reader, emit func(Update)) error {
	c := session.NewClient(r)
	var screen *image.RGBA
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ev, err := c.Next()
		if err != nil {
			return err
		}
		switch ev.Type {
		case frame.Status:
			screen = image.NewRGBA(image.Rect(0, 0, int(ev.Status.Width), int(ev.Status.Height)))
			draw.Draw(screen, screen.Bounds(), image.Black, image.Point{}, draw.Src)
			emit(Update{Status: ev.Status, Image: screen})
		case frame.Video:
			v := ev.Video
			// Check decoded dimensions before allocating the JPEG's pixels.
			cfg, err := jpeg.DecodeConfig(bytes.NewReader(v.JPEG))
			if err != nil || cfg.Width != int(v.W) || cfg.Height != int(v.H) {
				return frame.ErrProtocol
			}
			tile, err := jpeg.Decode(bytes.NewReader(v.JPEG))
			if err != nil {
				return frame.ErrProtocol
			}
			next := image.NewRGBA(screen.Bounds())
			copy(next.Pix, screen.Pix)
			rect := image.Rect(int(v.X), int(v.Y), int(v.X)+int(v.W), int(v.Y)+int(v.H))
			draw.Draw(next, rect, tile, tile.Bounds().Min, draw.Src)
			screen = next
			emit(Update{Image: next})
		case frame.Audio:
			emit(Update{Audio: ev.Audio})
		case frame.Close:
			emit(Update{Close: ev.Close})
			return nil
		}
	}
}

// StartTransport executes an explicit argv, never a shell command. Authentication,
// host resolution, tickets and lease renewal belong to this transport adapter.
func StartTransport(ctx context.Context, argv []string, stderr io.Writer) (io.ReadCloser, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("transport_required")
	}
	childCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(childCtx, argv[0], argv[1:]...)
	cmd.Stderr = stderr
	r, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		cancel()
		_ = r.Close()
		return nil, err
	}
	return &transport{ReadCloser: r, cancel: cancel, cmd: cmd}, nil
}

type transport struct {
	io.ReadCloser
	cancel context.CancelFunc
	cmd    *exec.Cmd
	once   sync.Once
}

func (t *transport) Close() error {
	t.once.Do(func() {
		t.cancel()
		_ = t.ReadCloser.Close()
		_ = t.cmd.Wait()
	})
	return nil
}
