//go:build unix

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahrdp/internal/frame"
	"github.com/afterdarksys/sahrdp/internal/lease"
	"github.com/afterdarksys/sahrdp/internal/record"
	"github.com/afterdarksys/sahrdp/internal/session"
)

const (
	testHost = "11111111-1111-4111-8111-111111111111"
	testSID  = "dsp_0123456789abcdef"
)

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("stdin read")
}

func TestEmptyAllowBeforeKeyOrHello(t *testing.T) {
	dir := t.TempDir()
	var out, errw bytes.Buffer
	code := run([]string{
		"daemon",
		"--host-id", testHost,
		"--control-pub", filepath.Join(dir, "missing-pub"),
		"--allow", "",
		"--record-dir", filepath.Join(dir, "rec"),
		"--record-key", filepath.Join(dir, "missing-key"),
		"--capture", filepath.Join(dir, "missing-cap"),
	}, panicReader{}, &out, &errw)
	if code != 2 || errw.String() != "target_denied_agent\n" || out.Len() != 0 {
		t.Fatalf("code %d stderr %q stdout %q", code, errw.String(), out.String())
	}
	if strings.Contains(errw.String(), dir) {
		t.Fatal(errw.String())
	}
}

func TestAllowFlags(t *testing.T) {
	dir := t.TempDir()
	base := func(allow []string) []string {
		args := []string{
			"daemon",
			"--host-id", testHost,
			"--control-pub", filepath.Join(dir, "pub"),
			"--record-dir", filepath.Join(dir, "rec"),
			"--record-key", filepath.Join(dir, "key"),
			"--capture", filepath.Join(dir, "cap"),
		}
		return append(args, allow...)
	}
	cases := []struct {
		allow []string
		code  int
		err   string
	}{
		{nil, 2, "usage\n"},
		{[]string{"--allow", "virtual,virtual"}, 2, "bad_allow\n"},
		{[]string{"--allow", "virtual,printer"}, 2, "bad_allow\n"},
		{[]string{"--allow", "audio"}, 2, "target_denied_agent\n"},
	}
	for _, tc := range cases {
		var out, errw bytes.Buffer
		code := run(base(tc.allow), panicReader{}, &out, &errw)
		if code != tc.code || errw.String() != tc.err || out.Len() != 0 {
			t.Fatalf("%v code %d stderr %q stdout %q", tc.allow, code, errw.String(), out.String())
		}
	}
}

func TestSymlinkKeyBeforeCapture(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, bytes.Repeat([]byte{0x11}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	keyLink := filepath.Join(dir, "key")
	capLink := filepath.Join(dir, "cap")
	if err := os.Symlink(target, keyLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, capLink); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	code := run([]string{
		"daemon",
		"--host-id", testHost,
		"--control-pub", filepath.Join(dir, "missing-pub"),
		"--allow", "virtual,audio",
		"--record-dir", filepath.Join(dir, "rec"),
		"--record-key", keyLink,
		"--capture", capLink,
	}, panicReader{}, &out, &errw)
	if code != 1 || errw.String() != "bad_key\n" || out.Len() != 0 {
		t.Fatalf("code %d stderr %q stdout %q", code, errw.String(), out.String())
	}
	if strings.Contains(errw.String(), dir) {
		t.Fatal(errw.String())
	}
}

func TestSymlinkCaptureAfterKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	pubPath := filepath.Join(dir, "pub")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x11}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, bytes.Repeat([]byte{0x22}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "realcap")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	capLink := filepath.Join(dir, "cap")
	if err := os.Symlink(target, capLink); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	code := run([]string{
		"daemon",
		"--host-id", testHost,
		"--control-pub", pubPath,
		"--allow", "virtual",
		"--record-dir", filepath.Join(dir, "rec"),
		"--record-key", keyPath,
		"--capture", capLink,
	}, panicReader{}, &out, &errw)
	if code != 1 || errw.String() != "display_unavailable\n" || out.Len() != 0 {
		t.Fatalf("code %d stderr %q stdout %q", code, errw.String(), out.String())
	}
	if strings.Contains(errw.String(), dir) {
		t.Fatal(errw.String())
	}
}

func TestClientWritesMediaAndVerify(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	recDir := filepath.Join(dir, "rec")
	if err := os.MkdirAll(recDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(recDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x07}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x11}, 32)
	t0 := time.Unix(1_800_000_000, 0)
	d, err := session.New(session.Config{
		HostID: testHost, Pub: pub, Allow: session.Allow{Virtual: true, Audio: true},
		RecordDir: recDir, RecordKey: append([]byte(nil), key...),
		MinFree: 1, Free: func(string) (uint64, error) { return 1 << 40, nil },
		Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	g := lease.Grant{
		HostID: testHost, ExpiresUnix: t0.Unix() + 120, NonceHex: "00000000000000000000000000000001",
		SessionID: testSID, DeadlineUnix: t0.Unix() + 2000, Phase: "start",
		Seat: "virtual", Output: "0", Audio: 1, MaxFPS: 5, MaxWidth: 320, MaxBytes: 1 << 20, Actor: "ada",
	}
	signed, err := g.Sign(priv, t0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	if err := d.Hello(&stream); err != nil {
		t.Fatal(err)
	}
	if err := d.AcceptLease(raw); err != nil {
		t.Fatal(err)
	}
	geo, err := json.Marshal(frame.Size{Width: 64, Height: 48})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AcceptGeometry(geo); err != nil {
		t.Fatal(err)
	}
	jpeg := []byte{0xff, 0xd8, 0x11, 0x22, 0xff, 0xd9}
	video, err := frame.AppendVideo(frame.Tile{X: 1, Y: 2, W: 8, H: 8, JPEG: jpeg})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Capture(frame.Video, video); err != nil {
		t.Fatal(err)
	}
	pcm := []byte{0x01, 0x02, 0x03, 0x04}
	audio, err := frame.AppendAudio(frame.PCM{Rate: 8000, Channels: 1, Format: 1, PCM: pcm})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Capture(frame.Audio, audio); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish("closed"); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "client-out")
	var stdout, stderr bytes.Buffer
	code := run([]string{"client", "--out", outDir}, bytes.NewReader(stream.Bytes()), &stdout, &stderr)
	if code != 0 || stderr.String() != "closed\n" || stdout.Len() != 0 {
		t.Fatalf("code %d stderr %q stdout %q", code, stderr.String(), stdout.String())
	}
	gotJPEG, err := os.ReadFile(filepath.Join(outDir, "000001.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotJPEG, jpeg) {
		t.Fatalf("jpeg %x", gotJPEG)
	}
	gotPCM, err := os.ReadFile(filepath.Join(outDir, "audio.s16le"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPCM, pcm) {
		t.Fatalf("pcm %x", gotPCM)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		t.Fatal("session.json newline")
	}
	var meta sessionFile
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.SessionID != testSID || meta.Width != 64 || meta.Height != 48 || meta.Audio != 1 ||
		meta.Actor != "ada" || meta.MaxFPS != 5 || meta.MaxWidth != 320 || meta.Reason != "closed" ||
		meta.Bytes != int64(len(video)+len(audio)) || len(meta.Digest) != 64 {
		t.Fatalf("%+v", meta)
	}
	for _, name := range []string{"session.json", "000001.jpg", "audio.s16le"} {
		st, err := os.Lstat(filepath.Join(outDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", name, st.Mode().Perm())
		}
	}

	keyPath := filepath.Join(dir, "verify-key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(recDir, testSID+".rec")
	var vout, verr bytes.Buffer
	code = run([]string{"verify", "--file", recPath, "--key", keyPath, "--session", testSID}, panicReader{}, &vout, &verr)
	if code != 0 || verr.Len() != 0 || strings.TrimSpace(vout.String()) != meta.Digest {
		t.Fatalf("code %d stderr %q stdout %q", code, verr.String(), vout.String())
	}
	if _, err := record.Verify(recPath, key, testSID); err != nil {
		t.Fatal(err)
	}

	var missingOut, missingErr bytes.Buffer
	code = run([]string{"verify", "--file", filepath.Join(dir, "no-such.rec"), "--key", keyPath, "--session", testSID}, panicReader{}, &missingOut, &missingErr)
	if code != 1 || missingErr.String() != "recording_unavailable\n" || missingOut.Len() != 0 {
		t.Fatalf("code %d stderr %q stdout %q", code, missingErr.String(), missingOut.String())
	}
	if strings.Contains(missingErr.String(), dir) {
		t.Fatal(missingErr.String())
	}
}
