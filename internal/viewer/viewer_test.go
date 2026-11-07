package viewer

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahrdp/internal/frame"
	"github.com/afterdarksys/sahrdp/internal/session"
)

func stream(t *testing.T, tile frame.Tile) []byte {
	t.Helper()
	var b bytes.Buffer
	write := func(typ byte, p []byte) {
		t.Helper()
		if err := frame.Write(&b, typ, p); err != nil {
			t.Fatal(err)
		}
	}
	write(frame.Hello, []byte(frame.HelloMagic))
	st, _ := json.Marshal(session.Status{State: "connected", SessionID: "dsp_0123456789abcdef", Width: 4, Height: 4, Actor: "operator", MaxFPS: 5, MaxWidth: 1280})
	write(frame.Status, st)
	p, err := frame.AppendVideo(tile)
	if err != nil {
		t.Fatal(err)
	}
	write(frame.Video, p)
	cl, _ := json.Marshal(session.Close{Reason: "closed", Bytes: int64(len(p)), Digest: strings.Repeat("0", 64)})
	write(frame.Close, cl)
	return b.Bytes()
}

func jpegTile(t *testing.T) frame.Tile {
	t.Helper()
	pic := image.NewRGBA(image.Rect(0, 0, 2, 2))
	for y := 0; y < 2; y++ {
		for x := 0; x < 2; x++ {
			pic.Set(x, y, color.RGBA{255, 0, 0, 255})
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, pic, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatal(err)
	}
	return frame.Tile{X: 1, Y: 1, W: 2, H: 2, JPEG: b.Bytes()}
}

func TestReadComposesTilesWithoutMutatingPublishedImages(t *testing.T) {
	var updates []Update
	err := Read(context.Background(), bytes.NewReader(stream(t, jpegTile(t))), func(u Update) { updates = append(updates, u) })
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 3 || updates[0].Status == nil || updates[2].Close == nil {
		t.Fatalf("events: %#v", updates)
	}
	r, _, _, _ := updates[1].Image.At(1, 1).RGBA()
	if r < 60000 {
		t.Fatal("tile was not drawn at its offset")
	}
	r, _, _, _ = updates[1].Image.At(0, 0).RGBA()
	if r != 0 {
		t.Fatal("tile overwrote surrounding pixels")
	}
	r, _, _, _ = updates[0].Image.At(1, 1).RGBA()
	if r != 0 {
		t.Fatal("published image was mutated")
	}
}

func TestReadRejectsInvalidJPEGAndGeometry(t *testing.T) {
	for _, name := range []string{"dimensions", "invalid", "outside"} {
		t.Run(name, func(t *testing.T) {
			v := jpegTile(t)
			switch name {
			case "dimensions":
				v.W = 1
			case "invalid":
				v.JPEG = []byte{255, 216, 0, 0, 255, 217}
			case "outside":
				v.X = 4
			}
			err := Read(context.Background(), bytes.NewReader(stream(t, v)), func(Update) {})
			if err == nil || err.Error() != "protocol_error" {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestReadRejectAndTruncatedStream(t *testing.T) {
	var b bytes.Buffer
	_ = frame.Write(&b, frame.Hello, []byte(frame.HelloMagic))
	_ = frame.Write(&b, frame.Reject, []byte(`{"code":"scope_denied"}`))
	if err := Read(context.Background(), &b, func(Update) {}); err == nil || err.Error() != "scope_denied" {
		t.Fatalf("got %v", err)
	}
	data := stream(t, jpegTile(t))
	if err := Read(context.Background(), bytes.NewReader(data[:len(data)-1]), func(Update) {}); err == nil {
		t.Fatal("accepted truncated close")
	}
}

func TestTransportHelper(t *testing.T) {
	if os.Getenv("SAHRDP_TRANSPORT_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			_ = json.NewEncoder(os.Stdout).Encode(os.Args[i+1:])
			time.Sleep(time.Minute)
			os.Exit(0)
		}
	}
	os.Exit(1)
}

func TestTransportLiteralArgumentsAndCancellation(t *testing.T) {
	t.Setenv("SAHRDP_TRANSPORT_TEST", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	args := []string{"space value", "$(touch should-not-exist)", "; exit 1"}
	argv := append([]string{os.Args[0], "-test.run=^TestTransportHelper$", "--"}, args...)
	r, err := StartTransport(ctx, argv, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var got []string
	if err = json.NewDecoder(r).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, args) {
		t.Fatalf("argv changed: %q", got)
	}
	done := make(chan struct{})
	go func() { _ = r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("transport did not stop")
	}
}

func TestTransportStartFailure(t *testing.T) {
	for _, argv := range [][]string{nil, {"/does/not/exist/sahrdp-transport"}} {
		if r, err := StartTransport(context.Background(), argv, io.Discard); err == nil {
			r.Close()
			t.Fatal("expected start error")
		}
	}
}
