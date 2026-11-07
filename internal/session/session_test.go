package session

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/sahrdp/internal/frame"
	"github.com/afterdarksys/sahrdp/internal/lease"
	"github.com/afterdarksys/sahrdp/internal/record"
)

const (
	hostID = "11111111-1111-4111-8111-111111111111"
	sid    = "dsp_0123456789abcdef"
)

func TestNewOrder(t *testing.T) {
	_, err := New(Config{})
	mustCode(t, err, "target_denied_agent")
	_, err = New(Config{Allow: Allow{Virtual: true}})
	mustCode(t, err, "bad_host")
	_, err = New(Config{Allow: Allow{Virtual: true}, HostID: hostID})
	mustCode(t, err, "malformed")
	pub := bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize)
	_, err = New(Config{Allow: Allow{Virtual: true}, HostID: hostID, Pub: pub})
	mustCode(t, err, "recording_unavailable")
	_, err = New(Config{Allow: Allow{Audio: true}, HostID: hostID, Pub: pub, RecordKey: bytes.Repeat([]byte{1}, 32), RecordDir: t.TempDir()})
	mustCode(t, err, "target_denied_agent")
}

func TestCopiesKeyAndPub(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv := keypair(t)
	key := bytes.Repeat([]byte{0x11}, 32)
	passedKey := append([]byte(nil), key...)
	passedPub := append(ed25519.PublicKey(nil), pub...)
	t0 := time.Unix(1_800_000_000, 0)
	d, err := New(Config{
		HostID: hostID, Pub: passedPub, Allow: Allow{Virtual: true, Audio: true},
		RecordDir: dir, RecordKey: passedKey, MinFree: 1, Free: freeLots,
		Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	passedKey[0] ^= 0xff
	passedPub[0] ^= 0xff
	var buf bytes.Buffer
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(1)})
	bringUp(t, d, raw, &buf)
	if err := d.Capture(frame.Video, jpegPayload(t, 0, 0, 8, 8, 4)); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish("closed"); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Verify(filepath.Join(dir, sid+".rec"), key, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Verify(filepath.Join(dir, sid+".rec"), passedKey, sid); err == nil || err.Error() != "recording_mac_mismatch" {
		t.Fatal(err)
	}
}

func TestHelloFailures(t *testing.T) {
	d, _, _, _ := newDaemon(t, true, nil)
	err := d.Hello(pathWriter{})
	if err == nil || err.Error() != "write /var/secret/display: broken" {
		t.Fatal(err)
	}
	d, _, _, _ = newDaemon(t, true, nil)
	mustCode(t, d.Hello(nil), "agent_disconnected")
	d, _, _, _ = newDaemon(t, true, nil)
	var buf bytes.Buffer
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	mustCode(t, d.Hello(&buf), "protocol_error")
}

func TestLeaseRejectsDoNotConsumeNonce(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	d, priv, _, _ := newDaemon(t, false, func() time.Time { return t0 })
	var buf bytes.Buffer
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	n := nonce(2)
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: n})
	mustCode(t, d.AcceptLease(raw), "target_denied_agent")
	if err := d.nonces.Remember(n, t0); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("hello missing")
	}

	d, priv, _, _ = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	n = nonce(3)
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: n, phase: "renew"})
	mustCode(t, d.AcceptLease(raw), "bad_phase")
	if err := d.nonces.Remember(n, t0); err != nil {
		t.Fatal(err)
	}
}

func TestRenewAfterStatus(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	now := func() time.Time { return t0 }
	exp := t0.Unix() + 120
	deadline := t0.Unix() + 2000
	n := nonce(4)

	d, priv, _, _ := newDaemon(t, true, now)
	var buf bytes.Buffer
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: n, exp: exp, deadline: deadline})
	bringUp(t, d, raw, &buf)
	_, renew := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: n, phase: "renew", exp: exp, deadline: deadline})
	mustCode(t, d.Control(frame.Renew, renew), "replay")
	if got := frameCode(t, buf.Bytes()); got != "replay" {
		t.Fatal(got)
	}

	d, priv, _, _ = newDaemon(t, true, now)
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(5), exp: exp, deadline: deadline})
	bringUp(t, d, raw, &buf)
	_, renew = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(6), phase: "renew", exp: exp, deadline: deadline, actor: "eve"})
	mustCode(t, d.Control(frame.Renew, renew), "lease_binding")
	if got := frameCode(t, buf.Bytes()); got != "lease_binding" {
		t.Fatal(got)
	}

	d, priv, _, _ = newDaemon(t, true, now)
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(7), exp: exp, deadline: deadline})
	bringUp(t, d, raw, &buf)
	signed, _ := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(8), phase: "renew", exp: exp, deadline: deadline})
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	swapped := bytes.Replace(body, []byte(`"actor":"ada"`), []byte(`"actor":"eve"`), 1)
	if bytes.Equal(swapped, body) {
		t.Fatal("actor not swapped")
	}
	mustCode(t, d.Control(frame.Renew, swapped), "payload_mismatch")

	d, priv, _, _ = newDaemon(t, true, now)
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(9), exp: exp, deadline: deadline})
	bringUp(t, d, raw, &buf)
	signed, _ = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(10), phase: "renew", exp: exp, deadline: deadline})
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatal(err)
	}
	sig[len(sig)-1] ^= 0xff
	signed.Signature = base64.StdEncoding.EncodeToString(sig)
	body, err = json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	mustCode(t, d.Control(frame.Renew, body), "bad_signature")
	if got := frameCode(t, buf.Bytes()); got != "bad_signature" {
		t.Fatal(got)
	}

	box := &clk{t: t0}
	d, priv, _, _ = newDaemon(t, true, box.now)
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(11), exp: exp, deadline: deadline})
	bringUp(t, d, raw, &buf)
	box.t = time.Unix(exp+int64(lease.Skew)+1, 0)
	mustCode(t, d.Control(frame.Renew, []byte("not-json")), "stopped")
}

func TestMediaGuards(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	d, priv, key, dir := newDaemon(t, true, func() time.Time { return t0 })
	var buf bytes.Buffer
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(12)})
	bringUp(t, d, raw, &buf)
	for i := 0; i < 5; i++ {
		if err := d.Capture(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)); err != nil {
			t.Fatal(err)
		}
	}
	before := buf.Len()
	mustCode(t, d.Capture(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)), "protocol_error")
	if buf.Len() == before {
		t.Fatal("close not written")
	}
	ks := kindsAt(t, dir)
	if countEq(ks, "video") != 5 || ks[len(ks)-1] != "end" {
		t.Fatal(ks)
	}
	if countEq(frameTypes(t, buf.Bytes()), string(frame.Video)) != 5 {
		t.Fatal(frameTypes(t, buf.Bytes()))
	}
	if _, err := record.Verify(filepath.Join(dir, sid+".rec"), key, sid); err != nil {
		t.Fatal(err)
	}

	box := &clk{t: t0}
	d, priv, _, dir = newDaemon(t, true, box.now)
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(13)})
	bringUp(t, d, raw, &buf)
	for i := 0; i < 5; i++ {
		if err := d.Capture(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)); err != nil {
			t.Fatal(err)
		}
	}
	box.t = t0.Add(time.Second)
	if err := d.Capture(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)); err != nil {
		t.Fatal(err)
	}

	d, priv, _, dir = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 0, nonce: nonce(14)})
	bringUp(t, d, raw, &buf)
	mustCode(t, d.Capture(frame.Audio, pcmPayload(t, 8000, 2)), "protocol_error")
	ks = kindsAt(t, dir)
	if countEq(ks, "audio") != 0 || countEq(ks, "video") != 0 {
		t.Fatal(ks)
	}

	d, priv, _, dir = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(15)})
	bringUp(t, d, raw, &buf)
	before = buf.Len()
	mustCode(t, d.Control(frame.Input, []byte{1}), "protocol_error")
	mustCode(t, d.Capture(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)), "protocol_error")
	ks = kindsAt(t, dir)
	if countEq(ks, "video") != 0 || ks[0] != "start" || ks[len(ks)-1] != "end" {
		t.Fatal(ks)
	}
	types := frameTypes(t, buf.Bytes())
	if countEq(types, string(frame.Video)) != 0 {
		t.Fatal(types)
	}
	_ = before

	d, priv, _, dir = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(16)})
	bringUp(t, d, raw, &buf)
	mustCode(t, d.Capture(frame.Video, jpegPayload(t, 65535, 0, 2, 2, 4)), "protocol_error")
	if countEq(kindsAt(t, dir), "video") != 0 {
		t.Fatal(kindsAt(t, dir))
	}

	d, priv, _, dir = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(17)})
	bringUp(t, d, raw, &buf)
	ok := pcmPayload(t, 8000, 8000)
	if err := d.Capture(frame.Audio, ok); err != nil {
		t.Fatal(err)
	}
	mustCode(t, d.Capture(frame.Audio, pcmPayload(t, 8000, 8001)), "protocol_error")
	if countEq(kindsAt(t, dir), "audio") != 1 {
		t.Fatal(kindsAt(t, dir))
	}

	d, priv, key, dir = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(18), maxBytes: 4096})
	bringUp(t, d, raw, &buf)
	before = buf.Len()
	mustCode(t, d.Capture(frame.Video, jpegPayload(t, 0, 0, 8, 8, 3000)), "byte_cap")
	if bytes.Contains(buf.Bytes()[before:], []byte{0xff, 0xd8}) {
		t.Fatal("tile forwarded")
	}
	ks = kindsAt(t, dir)
	if countEq(ks, "video") != 0 || ks[len(ks)-1] != "end" {
		t.Fatal(ks)
	}
	if _, err := record.Verify(filepath.Join(dir, sid+".rec"), key, sid); err != nil {
		t.Fatal(err)
	}
}

func TestStartLineRemovesFile(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	d, priv, _, dir := newDaemon(t, true, func() time.Time { return t0 })
	var buf bytes.Buffer
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(19), maxBytes: 1})
	if err := d.AcceptLease(raw); err != nil {
		t.Fatal(err)
	}
	geo, _ := json.Marshal(frame.Size{Width: 64, Height: 48})
	mustCode(t, d.AcceptGeometry(geo), "recording_unavailable")
	if _, err := os.Stat(filepath.Join(dir, sid+".rec")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestGeometryAndPipes(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	d, priv, _, dir := newDaemon(t, true, func() time.Time { return t0 })
	var buf bytes.Buffer
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(20)})
	if err := d.AcceptLease(raw); err != nil {
		t.Fatal(err)
	}
	mustCode(t, d.Capture(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)), "protocol_error")
	if _, err := os.Stat(filepath.Join(dir, sid+".rec")); !os.IsNotExist(err) {
		t.Fatal("recording opened")
	}

	d, priv, _, _ = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(21)})
	if err := d.AcceptLease(raw); err != nil {
		t.Fatal(err)
	}
	mustCode(t, d.AcceptGeometry([]byte(`{"width":0,"height":48}`)), "protocol_error")
	mustCode(t, d.AcceptGeometry([]byte(`{"width":64,"height":48,"alg":1}`)), "protocol_error")

	d, priv, _, _ = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(22)})
	bringUp(t, d, raw, &buf)
	mustCode(t, d.Control(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)), "protocol_error")

	d, _, _, _ = newDaemon(t, true, func() time.Time { return t0 })
	buf.Reset()
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	mustCode(t, d.Capture(frame.Lease, []byte("{}")), "protocol_error")
	mustCode(t, d.Finish("closed"), "protocol_error")
	d2, priv2, _, _ := newDaemon(t, true, func() time.Time { return t0 })
	var up bytes.Buffer
	_, raw = signRaw(t, priv2, t0, grantOpt{audio: 1, nonce: nonce(23)})
	bringUp(t, d2, raw, &up)
	mustCode(t, d2.Finish("lease_binding"), "protocol_error")
}

func TestPollLimits(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	exp := t0.Unix() + 200
	deadline := t0.Unix() + 100
	box := &clk{t: t0}
	d, priv, _, _ := newDaemon(t, true, box.now)
	var buf bytes.Buffer
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(24), exp: exp, deadline: deadline})
	bringUp(t, d, raw, &buf)
	box.t = time.Unix(deadline, 0)
	if err := d.Poll(); err != nil {
		t.Fatal(err)
	}
	box.t = time.Unix(deadline+1, 0)
	mustCode(t, d.Poll(), "max_duration")

	box = &clk{t: t0}
	d, priv, _, _ = newDaemon(t, true, box.now)
	buf.Reset()
	exp = t0.Unix() + 100
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(25), exp: exp, deadline: t0.Unix() + 2000})
	if err := d.Hello(&buf); err != nil {
		t.Fatal(err)
	}
	if err := d.AcceptLease(raw); err != nil {
		t.Fatal(err)
	}
	box.t = time.Unix(exp+int64(lease.Skew), 0)
	if err := d.Poll(); err != nil {
		t.Fatal(err)
	}
	box.t = time.Unix(exp+int64(lease.Skew)+1, 0)
	mustCode(t, d.Poll(), "stopped")

	box = &clk{t: t0}
	d, priv, _, _ = newDaemon(t, false, box.now)
	buf.Reset()
	deadline = t0.Unix() + 2000
	_, raw = signRaw(t, priv, t0, grantOpt{audio: 0, nonce: nonce(26), exp: t0.Unix() + int64(lease.MaxTTL), deadline: deadline})
	bringUp(t, d, raw, &buf)
	for i, at := range []int64{250, 500, 750} {
		box.t = t0.Add(time.Duration(at) * time.Second)
		_, renew := signRaw(t, priv, box.t, grantOpt{
			audio: 0, nonce: nonce(27 + i), phase: "renew",
			exp: box.t.Unix() + 290, deadline: deadline,
		})
		if err := d.Control(frame.Renew, renew); err != nil {
			t.Fatal(at, err)
		}
	}
	box.t = t0.Add(901 * time.Second)
	mustCode(t, d.Poll(), "idle_timeout")
	if got := frameCode(t, buf.Bytes()); got != "idle_timeout" {
		t.Fatal(got)
	}
}

func TestForwardFailsAfterAppend(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	d, priv, key, dir := newDaemon(t, true, func() time.Time { return t0 })
	w := &nWriter{left: 6}
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(28)})
	bringUp(t, d, raw, w)
	mustCode(t, d.Capture(frame.Video, jpegPayload(t, 0, 0, 4, 4, 4)), "agent_disconnected")
	ks := kindsAt(t, dir)
	if countEq(ks, "video") != 1 {
		t.Fatal(ks)
	}
	if _, err := record.Verify(filepath.Join(dir, sid+".rec"), key, sid); err != nil {
		t.Fatal(err)
	}
	if countEq(frameTypes(t, w.buf.Bytes()), string(frame.Video)) != 0 {
		t.Fatal("video forwarded")
	}
}

func TestLibraryRoundTrip(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	d, priv, key, dir := newDaemon(t, true, func() time.Time { return t0 })
	var buf bytes.Buffer
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(29)})
	bringUp(t, d, raw, &buf)
	vid := jpegPayload(t, 1, 2, 8, 8, 4)
	aud := pcmPayload(t, 16000, 4)
	if err := d.Capture(frame.Video, vid); err != nil {
		t.Fatal(err)
	}
	if err := d.Capture(frame.Audio, aud); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish("closed"); err != nil {
		t.Fatal(err)
	}
	digest, err := record.Verify(filepath.Join(dir, sid+".rec"), key, sid)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(bytes.NewReader(buf.Bytes()))
	ev, err := c.Next()
	if err != nil || ev.Type != frame.Hello {
		t.Fatal(err, ev.Type)
	}
	ev, err = c.Next()
	if err != nil || ev.Status == nil || ev.Status.Actor != "ada" || ev.Status.Audio != 1 {
		t.Fatal(err, ev.Status)
	}
	ev.Status.Actor = "swapped"
	ev, err = c.Next()
	if err != nil || ev.Video == nil || !bytes.Equal(ev.Video.JPEG, []byte{0xff, 0xd8, 0xff, 0xd9}) {
		t.Fatal(err)
	}
	ev, err = c.Next()
	if err != nil || ev.Audio == nil || len(ev.Audio.PCM) != 8 {
		t.Fatal(err, ev.Audio)
	}
	ev, err = c.Next()
	if err != nil || ev.Close == nil || ev.Close.Reason != "closed" || ev.Close.Digest != digest {
		t.Fatal(err, ev.Close)
	}
	if ev.Close.Bytes != int64(len(vid)+len(aud)) {
		t.Fatal(ev.Close.Bytes)
	}
	if _, err := c.Next(); err != io.EOF {
		t.Fatal(err)
	}
}

func TestServeRoundTrip(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	d, priv, key, dir := newDaemon(t, true, func() time.Time { return t0 })
	cr, cw := io.Pipe()
	vr, vw := io.Pipe()
	clientR, clientW := io.Pipe()
	control := pipeRC{r: cr, w: cw}
	capture := pipeRC{r: vr, w: vw}
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Serve(control, clientW, capture)
	}()
	typ, p := readFrame(t, clientR)
	if typ != frame.Hello || string(p) != frame.HelloMagic {
		t.Fatalf("hello %d %q", typ, p)
	}
	_, raw := signRaw(t, priv, t0, grantOpt{audio: 1, nonce: nonce(30)})
	if err := frame.Write(cw, frame.Lease, raw); err != nil {
		t.Fatal(err)
	}
	geo, _ := json.Marshal(frame.Size{Width: 64, Height: 48})
	if err := frame.Write(vw, frame.Geometry, geo); err != nil {
		t.Fatal(err)
	}
	typ, p = readFrame(t, clientR)
	if typ != frame.Status {
		t.Fatalf("status %d", typ)
	}
	vid := jpegPayload(t, 0, 0, 8, 8, 4)
	if err := frame.Write(vw, frame.Video, vid); err != nil {
		t.Fatal(err)
	}
	typ, got := readFrame(t, clientR)
	if typ != frame.Video || !bytes.Equal(got, vid) {
		t.Fatalf("video %d", typ)
	}
	if err := vw.Close(); err != nil {
		t.Fatal(err)
	}
	typ, p = readFrame(t, clientR)
	if typ != frame.Close {
		t.Fatalf("close %d", typ)
	}
	var cl Close
	if json.Unmarshal(p, &cl) != nil || cl.Reason != "closed" {
		t.Fatal(cl)
	}
	select {
	case err := <-errCh:
		mustCode(t, err, "closed")
	case <-time.After(5 * time.Second):
		t.Fatal("serve stalled")
	}
	digest, err := record.Verify(filepath.Join(dir, sid+".rec"), key, sid)
	if err != nil || digest != cl.Digest {
		t.Fatal(err, digest, cl.Digest)
	}
}

func TestClientRejects(t *testing.T) {
	if _, err := NewClient(nil).Next(); err == nil || err.Error() != "protocol_error" {
		t.Fatal(err)
	}
	st := statusBytes(t, 1)
	vid := jpegPayload(t, 0, 0, 8, 8, 4)
	digest := bytes.Repeat([]byte("ab"), 32)

	_, err := drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Reject, []byte(`{"code":"expired"}`)},
	})
	if err == nil || err.Error() != "expired" {
		t.Fatal(err)
	}
	c := clientOf(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Reject, []byte(`{"code":"expired"}`)},
	})
	ev, err := c.Next()
	if err != nil || ev.Type != frame.Hello {
		t.Fatal(err, ev.Type)
	}
	ev, err = c.Next()
	if err == nil || err.Error() != "expired" || ev.Reject != "expired" {
		t.Fatal(err, ev.Reject)
	}
	if _, err := c.Next(); err != io.EOF {
		t.Fatal(err)
	}

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Reject, []byte(`{"code":"BAD"}`)},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, append(append([]byte{}, st[:len(st)-1]...), []byte(`,"alg":"ed25519"}`)...)},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{frame.Input, []byte{1}},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{11, []byte{1}},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{frame.Video, vid},
		{frame.Close, closeBytes(t, "closed", int64(len(vid)+1), string(digest))},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{frame.Close, closeBytes(t, "closed", 0, "abcd")},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{frame.Close, closeBytes(t, "closed", 0, "AB"+string(bytes.Repeat([]byte("ab"), 31)))},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{frame.Close, closeBytes(t, "nope", 0, string(digest))},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{frame.Video, jpegPayload(t, 60, 0, 8, 8, 4)},
	})
	mustCode(t, err, "protocol_error")

	_, err = drive(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, statusBytes(t, 0)},
		{frame.Audio, pcmPayload(t, 8000, 2)},
	})
	mustCode(t, err, "protocol_error")

	parts := frames{{frame.Hello, []byte(frame.HelloMagic)}, {frame.Status, st}}
	for i := 0; i < 5; i++ {
		parts = append(parts, framePart{frame.Video, vid})
	}
	c = clientOf(t, parts)
	c.SetClock(func() time.Time { return time.Unix(1_800_000_000, 0) })
	if _, err := c.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Next(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.Next(); err != nil {
			t.Fatal(i, err)
		}
	}
	c2 := clientOf(t, append(parts, framePart{frame.Video, vid}))
	var now time.Time = time.Unix(1_800_000_000, 0)
	c2.SetClock(func() time.Time { return now })
	for i := 0; i < 7; i++ {
		_, err = c2.Next()
		if err != nil {
			t.Fatal(i, err)
		}
	}
	now = now.Add(time.Second)
	if _, err := c2.Next(); err != nil {
		t.Fatal(err)
	}

	c = clientOf(t, frames{
		{frame.Hello, []byte(frame.HelloMagic)},
		{frame.Status, st},
		{frame.Video, vid},
	})
	if _, err := c.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Next(); err != nil {
		t.Fatal(err)
	}
	c.media = lease.MaxByte - 1
	mustCode(t, errNext(c), "protocol_error")
}

type clk struct{ t time.Time }

func (c *clk) now() time.Time { return c.t }

type grantOpt struct {
	phase    string
	audio    int
	nonce    string
	exp      int64
	deadline int64
	actor    string
	maxBytes int64
	fps      int
}

func nonce(n int) string {
	var b [16]byte
	b[15] = byte(n)
	b[14] = byte(n >> 8)
	const hexd = "0123456789abcdef"
	out := make([]byte, 32)
	for i, v := range b {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0x0f]
	}
	return string(out)
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x07}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func freeLots(string) (uint64, error) { return 1 << 40, nil }

func newDaemon(t *testing.T, audio bool, now func() time.Time) (*Daemon, ed25519.PrivateKey, []byte, string) {
	t.Helper()
	if now == nil {
		t0 := time.Unix(1_800_000_000, 0)
		now = func() time.Time { return t0 }
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv := keypair(t)
	key := bytes.Repeat([]byte{0x11}, 32)
	d, err := New(Config{
		HostID: hostID, Pub: append(ed25519.PublicKey(nil), pub...),
		Allow:     Allow{Virtual: true, Audio: audio},
		RecordDir: dir, RecordKey: append([]byte(nil), key...),
		MinFree: 1, Free: freeLots, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, priv, key, dir
}

func signRaw(t *testing.T, priv ed25519.PrivateKey, now time.Time, o grantOpt) (lease.Grant, []byte) {
	t.Helper()
	if o.phase == "" {
		o.phase = "start"
	}
	if o.nonce == "" {
		o.nonce = nonce(1)
	}
	if o.exp == 0 {
		o.exp = now.Unix() + 120
	}
	if o.deadline == 0 {
		o.deadline = now.Unix() + 2000
	}
	if o.actor == "" {
		o.actor = "ada"
	}
	if o.maxBytes == 0 {
		o.maxBytes = 1 << 20
	}
	if o.fps == 0 {
		o.fps = 5
	}
	g := lease.Grant{
		HostID: hostID, ExpiresUnix: o.exp, NonceHex: o.nonce, SessionID: sid,
		DeadlineUnix: o.deadline, Phase: o.phase, Seat: "virtual", Output: "0",
		Audio: o.audio, MaxFPS: o.fps, MaxWidth: 320, MaxBytes: o.maxBytes, Actor: o.actor,
	}
	signed, err := g.Sign(priv, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return signed, raw
}

func bringUp(t *testing.T, d *Daemon, raw []byte, w io.Writer) {
	t.Helper()
	if err := d.Hello(w); err != nil {
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
}

func jpegPayload(t *testing.T, x, y, w, h uint16, n int) []byte {
	t.Helper()
	if n < 4 {
		n = 4
	}
	jpeg := bytes.Repeat([]byte{0x11}, n)
	jpeg[0], jpeg[1] = 0xff, 0xd8
	jpeg[n-2], jpeg[n-1] = 0xff, 0xd9
	p, err := frame.AppendVideo(frame.Tile{X: x, Y: y, W: w, H: h, JPEG: jpeg})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pcmPayload(t *testing.T, rate uint32, samples int) []byte {
	t.Helper()
	pcm := bytes.Repeat([]byte{0x01, 0x02}, samples)
	p, err := frame.AppendAudio(frame.PCM{Rate: rate, Channels: 1, Format: 1, PCM: pcm})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != code {
		t.Fatalf("got %v want %s", err, code)
	}
}

func kindsAt(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, sid+".rec"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			K string `json:"k"`
		}
		if json.Unmarshal(line, &row) != nil {
			t.Fatal(string(line))
		}
		out = append(out, row.K)
	}
	return out
}

func frameTypes(t *testing.T, b []byte) []string {
	t.Helper()
	r := bytes.NewReader(b)
	var out []string
	for {
		typ, _, err := frame.Read(r)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string([]byte{typ}))
	}
}

func countEq(xs []string, want string) int {
	n := 0
	for _, s := range xs {
		if s == want {
			n++
		}
	}
	return n
}

func frameCode(t *testing.T, b []byte) string {
	t.Helper()
	r := bytes.NewReader(b)
	var last string
	for {
		typ, p, err := frame.Read(r)
		if err == io.EOF {
			return last
		}
		if err != nil {
			t.Fatal(err)
		}
		switch typ {
		case frame.Close:
			var c Close
			if json.Unmarshal(p, &c) != nil {
				t.Fatal("close")
			}
			last = c.Reason
		case frame.Reject:
			var body struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(p, &body) != nil {
				t.Fatal("reject")
			}
			last = body.Code
		}
	}
}

type pathWriter struct{}

func (pathWriter) Write([]byte) (int, error) {
	return 0, errors.New("write /var/secret/display: broken")
}

type nWriter struct {
	left int
	buf  bytes.Buffer
}

func (w *nWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		return 0, errors.New("broken pipe")
	}
	w.left--
	return w.buf.Write(p)
}

type pipeRC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p pipeRC) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p pipeRC) Close() error {
	werr := p.w.Close()
	rerr := p.r.Close()
	if werr != nil && !errors.Is(werr, io.ErrClosedPipe) {
		return werr
	}
	if rerr != nil && !errors.Is(rerr, io.ErrClosedPipe) {
		return rerr
	}
	return nil
}

func readFrame(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()
	type res struct {
		typ byte
		p   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		typ, p, err := frame.Read(r)
		ch <- res{typ, p, err}
	}()
	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.typ, got.p
	case <-time.After(5 * time.Second):
		t.Fatal("read stalled")
	}
	return 0, nil
}

type framePart struct {
	typ byte
	p   []byte
}

type frames []framePart

func clientOf(t *testing.T, parts frames) *Client {
	t.Helper()
	var buf bytes.Buffer
	for _, part := range parts {
		if err := frame.Write(&buf, part.typ, part.p); err != nil {
			t.Fatal(err)
		}
	}
	return NewClient(bytes.NewReader(buf.Bytes()))
}

func drive(t *testing.T, parts frames) (Event, error) {
	t.Helper()
	c := clientOf(t, parts)
	var last Event
	var err error
	for {
		last, err = c.Next()
		if err != nil {
			return last, err
		}
		if last.Close != nil {
			return last, nil
		}
	}
}

func errNext(c *Client) error {
	_, err := c.Next()
	return err
}

func statusBytes(t *testing.T, audio int) []byte {
	t.Helper()
	b, err := json.Marshal(Status{
		State: "connected", SessionID: sid, Width: 64, Height: 48,
		Audio: audio, Actor: "ada", MaxFPS: 5, MaxWidth: 320,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func closeBytes(t *testing.T, reason string, n int64, digest string) []byte {
	t.Helper()
	b, err := json.Marshal(Close{Reason: reason, Bytes: n, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
