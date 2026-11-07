package record

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func testKey() []byte { return bytes.Repeat([]byte{0x11}, 32) }

func freeOK(string) (uint64, error) { return 1 << 40, nil }

func fixedNow() func() time.Time {
	n := time.Unix(1729999800, 0)
	return func() time.Time { return n }
}

func openRec(t *testing.T, dir, sid string, key, hdr []byte, max int64) *Recorder {
	t.Helper()
	if _, err := os.Lstat(dir); err == nil {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	r, err := Open(dir, sid, key, hdr, max, 1, fixedNow(), freeOK)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRecordRoundTripAndCopy(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	key := testKey()
	passed := append([]byte(nil), key...)
	hdr := []byte(`{"session_id":"dsp_0123456789abcdef","actor":"ada"}`)
	r := openRec(t, dir, sid, passed, hdr, 1<<20)
	passed[0] ^= 0xff
	jpeg := []byte{0xff, 0xd8, 0xff, 0xd9}
	if err := r.Append("video", jpeg); err != nil {
		t.Fatal(err)
	}
	if err := r.Append("clip", jpeg); err == nil || err.Error() != "recording_unavailable" {
		t.Fatal(err)
	}
	digest, err := r.Finish([]byte(`{"reason":"closed"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(r.Path(), key, sid)
	if err != nil || got != digest {
		t.Fatal(err, got, digest)
	}
	st, err := os.Stat(r.Path())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, err)
	}
	dst, err := os.Stat(dir)
	if err != nil || dst.Mode().Perm()&0o077 != 0 {
		t.Fatal(dst.Mode())
	}
	if _, err := Verify(r.Path(), bytes.Repeat([]byte{0x22}, 32), sid); err == nil || err.Error() != "recording_mac_mismatch" {
		t.Fatal(err)
	}
}

func TestDisplaySeedNotPTY(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	key := testKey()
	hdr := []byte(`{"session_id":"dsp_0123456789abcdef"}`)
	r := openRec(t, dir, sid, key, hdr, 1<<20)
	if _, err := r.Finish([]byte(`{"reason":"closed"}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))[0]
	var rec recLine
	if json.Unmarshal(line, &rec) != nil || rec.Kind != "start" {
		t.Fatal("start")
	}
	display := recordingSeed(key, sid)
	if rec.MAC != recordingMAC(key, display, rec.Seq, rec.T, rec.Kind, rec.B64) {
		t.Fatal("display mac")
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("systemapi-recording-v1\n" + sid))
	pty := hex.EncodeToString(m.Sum(nil))
	if pty == display {
		t.Fatal("seeds match")
	}
	if recordingMAC(key, pty, rec.Seq, rec.T, rec.Kind, rec.B64) == rec.MAC {
		t.Fatal("pty seed matched the file")
	}
	if _, err := Verify(r.Path(), key, sid); err != nil {
		t.Fatal(err)
	}
}

func TestFreeAndDir(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	key := testKey()
	hdr := []byte(`{"session_id":"dsp_0123456789abcdef"}`)
	if _, err := Open(dir, sid, key, hdr, 1<<20, 1<<30, fixedNow(), func(string) (uint64, error) {
		return 10, nil
	}); err == nil || err.Error() != "recording_unavailable" {
		t.Fatal(err)
	}
	if _, err := Open(dir, sid, key, hdr, 1<<20, 1, fixedNow(), func(string) (uint64, error) {
		return 0, errors.New("disk /secret")
	}); err == nil || err.Error() != "recording_unavailable" {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, sid, key, hdr, 1<<20, 1, fixedNow(), freeOK); err == nil || err.Error() != "recording_unavailable" {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(loose, sid, key, hdr, 1<<20, 1, fixedNow(), freeOK); err == nil || err.Error() != "recording_unavailable" {
		t.Fatal(err)
	}
	n, err := FreeBytes(t.TempDir())
	if err != nil || n == 0 {
		t.Fatal(err, n)
	}
}

func TestExclusiveAndStartCap(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	key := testKey()
	hdr := []byte(`{"session_id":"dsp_0123456789abcdef"}`)
	r := openRec(t, dir, sid, key, hdr, 1<<20)
	if _, err := Open(dir, sid, key, hdr, 1<<20, 1, fixedNow(), freeOK); err == nil || err.Error() != "recording_unavailable" {
		t.Fatal(err)
	}
	if _, err := r.Finish([]byte(`{"reason":"closed"}`)); err != nil {
		t.Fatal(err)
	}
	tiny := filepath.Join(dir, "tiny")
	if err := os.Mkdir(tiny, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(tiny, sid, key, hdr, 1, 1, fixedNow(), freeOK); err == nil || err.Error() != "recording_unavailable" {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tiny, sid+".rec")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestVerifyFailures(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	other := "dsp_ffffffffffffffff"
	key := testKey()
	match := []byte(`{"session_id":"dsp_0123456789abcdef"}`)
	started := openRec(t, dir, sid, key, match, 1<<20)
	raw, err := os.ReadFile(started.Path())
	if err != nil {
		t.Fatal(err)
	}
	trunc := filepath.Join(dir, "trunc.rec")
	if err := os.WriteFile(trunc, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(trunc, key, sid); err == nil || err.Error() != "recording_truncated" {
		t.Fatal(err)
	}
	if _, err := started.Finish([]byte(`{"reason":"closed"}`)); err != nil {
		t.Fatal(err)
	}

	hdr := []byte(`{"session_id":"dsp_ffffffffffffffff"}`)
	r := openRec(t, filepath.Join(dir, "mismatch"), sid, key, hdr, 1<<20)
	path := r.Path()
	digest, err := r.Finish([]byte(`{"reason":"closed"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, key, sid); err == nil || err.Error() != "recording_session_mismatch" {
		t.Fatal(err)
	}
	if _, err := Verify(path, key, other); err == nil || err.Error() != "recording_mac_mismatch" {
		t.Fatal(err)
	}
	_ = digest

	empty := filepath.Join(dir, "empty.rec")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(empty, key, sid); err == nil || err.Error() != "recording_empty" {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.rec")
	_, err = Verify(missing, key, sid)
	var pe *os.PathError
	if !errors.As(err, &pe) {
		t.Fatal(err)
	}

	huge := filepath.Join(dir, "huge.rec")
	if err := os.WriteFile(huge, bytes.Repeat([]byte{'a'}, 300000), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(huge, key, sid); err == nil || err.Error() != "recording_malformed" {
		t.Fatal(err)
	}
}

func TestDataAfterEnd(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	key := testKey()
	r := openRec(t, dir, sid, key, []byte(`{"session_id":"dsp_0123456789abcdef"}`), 1<<20)
	digest, err := r.Finish([]byte(`{"reason":"closed"}`))
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte{0xff, 0xd8, 0xff, 0xd9})
	mac := recordingMAC(key, digest, 3, 5, "video", b64)
	extra, err := json.Marshal(recLine{Seq: 3, T: 5, Kind: "video", B64: b64, MAC: mac})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(r.Path(), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(extra, '\n')); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Verify(r.Path(), key, sid); err == nil || err.Error() != "recording_data_after_end" {
		t.Fatal(err)
	}
}

func TestManualChain(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	key := testKey()
	path := filepath.Join(dir, "hand.rec")
	writeChain(t, path, key, []item{
		{"video", []byte("x")},
		{"end", []byte(`{"reason":"closed"}`)},
	})
	if _, err := Verify(path, key, sid); err == nil || err.Error() != "recording_no_start" {
		t.Fatal(err)
	}
	writeChain(t, path, key, []item{
		{"start", []byte(`{"session_id":"dsp_0123456789abcdef"}`)},
		{"clip", []byte("x")},
		{"end", []byte(`{"reason":"closed"}`)},
	})
	if _, err := Verify(path, key, sid); err == nil || err.Error() != "recording_malformed" {
		t.Fatal(err)
	}
	writeChain(t, path, key, []item{
		{"start", []byte(`{"session_id":"dsp_0123456789abcdef"}`)},
	})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"seq":1`), []byte(`"seq":2`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, key, sid); err == nil || err.Error() != "recording_sequence_broken" {
		t.Fatal(err)
	}
}

func TestLineCap(t *testing.T) {
	dir := t.TempDir()
	sid := "dsp_0123456789abcdef"
	key := testKey()
	hdr := []byte(`{"session_id":"dsp_0123456789abcdef"}`)
	r := openRec(t, dir, sid, key, hdr, 1<<20)
	r.written = r.max - 20
	seq := r.seq
	if err := r.Append("video", bytes.Repeat([]byte{0xff}, 80)); err == nil || err.Error() != "byte_cap" {
		t.Fatal(err)
	}
	if r.seq != seq {
		t.Fatal("seq moved")
	}
	r.max = HardMax
	r.written = HardMax - 20
	if err := r.Append("video", bytes.Repeat([]byte{0xff}, 80)); err == nil || err.Error() != "recording_size_limit" {
		t.Fatal(err)
	}
	if _, err := r.Finish([]byte(`{"reason":"closed"}`)); err != nil {
		t.Fatal(err)
	}
	kinds := kindsOf(t, r.Path())
	if len(kinds) != 2 || kinds[0] != "start" || kinds[1] != "end" {
		t.Fatal(kinds)
	}
}

func TestUmask(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	sid := "dsp_0123456789abcdef"
	r := openRec(t, sub, sid, testKey(), []byte(`{"session_id":"dsp_0123456789abcdef"}`), 1<<20)
	st, err := os.Stat(r.Path())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal(st, err)
	}
	dst, err := os.Stat(sub)
	if err != nil || dst.Mode().Perm()&0o077 != 0 {
		t.Fatal(dst.Mode())
	}
	r.Finish([]byte(`{"reason":"closed"}`))
}

type item struct {
	kind string
	data []byte
}

func writeChain(t *testing.T, path string, key []byte, items []item) {
	t.Helper()
	sid := "dsp_0123456789abcdef"
	prev := recordingSeed(key, sid)
	var buf bytes.Buffer
	for i, it := range items {
		seq := uint64(i + 1)
		b64 := base64.StdEncoding.EncodeToString(it.data)
		mac := recordingMAC(key, prev, seq, 1, it.kind, b64)
		line, err := json.Marshal(recLine{Seq: seq, T: 1, Kind: it.kind, B64: b64, MAC: mac})
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
		prev = mac
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func kindsOf(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec recLine
		if json.Unmarshal(line, &rec) != nil {
			t.Fatal("line")
		}
		out = append(out, rec.Kind)
	}
	return out
}
