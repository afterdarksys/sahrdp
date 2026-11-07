// Threats: an agent that injects pixels, a lease for the wrong host or
// action, a grant that raises the caps, a nonce used twice, audio without
// the allow bit, and a tile forwarded when the recording write failed.
// Media is appended before it is sent. Input, clipboard, printers, and
// drive redirection have no decoder.
// Does NOT dial the control plane, hold an agent credential, listen, or
// start a display server. The systemapi agent does not know action
// `display` yet; this daemon still requires that action on the lease.
package session

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/afterdarksys/sahrdp/internal/frame"
	"github.com/afterdarksys/sahrdp/internal/lease"
	"github.com/afterdarksys/sahrdp/internal/record"
)

const idleFor = 900 * time.Second

var (
	hostRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sessionRe = regexp.MustCompile(`^dsp_[A-Za-z0-9_-]{16,64}$`)
	actorRe   = regexp.MustCompile(`^[A-Za-z0-9_.:@+-]{1,128}$`)
	codeRe    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	digestRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Allow is the daemon's half of dual control. Virtual is required.
// Audio is required before a lease with audio=1 is accepted.
type Allow struct {
	Virtual bool
	Audio   bool
}

// Config is the daemon's host material. The key and public key are copied.
type Config struct {
	HostID    string
	Pub       ed25519.PublicKey
	Allow     Allow
	RecordDir string
	RecordKey []byte
	MinFree   uint64
	Free      func(string) (uint64, error)
	Now       func() time.Time
}

// Status is the connected frame.
type Status struct {
	State     string `json:"state"`
	SessionID string `json:"session_id"`
	Width     uint16 `json:"width"`
	Height    uint16 `json:"height"`
	Audio     int    `json:"audio"`
	Actor     string `json:"actor"`
	MaxFPS    int    `json:"max_fps"`
	MaxWidth  int    `json:"max_width"`
}

// Close is the last frame. Digest is the recording's final HMAC.
type Close struct {
	Reason string `json:"reason"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

type terms struct {
	session  string
	deadline int64
	seat     string
	output   string
	audio    int
	fps      int
	width    int
	bytes    int64
	actor    string
}

func (t terms) same(g lease.Grant) bool {
	return t.session == g.SessionID &&
		t.deadline == g.DeadlineUnix &&
		t.seat == g.Seat &&
		t.output == g.Output &&
		t.audio == g.Audio &&
		t.fps == g.MaxFPS &&
		t.width == g.MaxWidth &&
		t.bytes == g.MaxBytes &&
		t.actor == g.Actor
}

type startRec struct {
	SessionID string `json:"session_id"`
	Actor     string `json:"actor"`
	Seat      string `json:"seat"`
	Output    string `json:"output"`
	Audio     int    `json:"audio"`
	Width     uint16 `json:"width"`
	Height    uint16 `json:"height"`
}

// Daemon is one display session. Its methods are not safe for concurrent use.
// Serve is the only caller that runs them, on one goroutine.
type Daemon struct {
	host    string
	pub     ed25519.PublicKey
	allow   Allow
	dir     string
	key     []byte
	minFree uint64
	free    func(string) (uint64, error)
	now     func() time.Time
	nonces  lease.Nonces

	client io.Writer
	hello  bool

	haveLease bool
	terms     terms
	leaseExp  int64

	width     uint16
	height    uint16
	connected bool
	rec       *record.Recorder
	media     int64
	lastMedia time.Time
	fpsWindow time.Time
	fpsCount  int

	stopped bool
	stopErr error
}

// New copies the key and the public key. An empty allow fails here, so Hello
// is never written for that daemon.
func New(cfg Config) (*Daemon, error) {
	if !cfg.Allow.Virtual {
		return nil, errors.New("target_denied_agent")
	}
	if !hostRe.MatchString(cfg.HostID) {
		return nil, errors.New("bad_host")
	}
	if len(cfg.Pub) != ed25519.PublicKeySize {
		return nil, errors.New("malformed")
	}
	if len(cfg.RecordKey) != 32 || cfg.RecordDir == "" {
		return nil, errors.New("recording_unavailable")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	minFree := cfg.MinFree
	if minFree == 0 {
		minFree = record.MinFreeDefault
	}
	pub := make(ed25519.PublicKey, len(cfg.Pub))
	copy(pub, cfg.Pub)
	return &Daemon{
		host:    cfg.HostID,
		pub:     pub,
		allow:   cfg.Allow,
		dir:     cfg.RecordDir,
		key:     append([]byte(nil), cfg.RecordKey...),
		minFree: minFree,
		free:    cfg.Free,
		now:     now,
	}, nil
}

// Hello writes SAHRDP1. A second hello is protocol_error.
func (d *Daemon) Hello(w io.Writer) error {
	if d.stopped {
		return d.stopErr
	}
	if d.hello {
		return d.stop("protocol_error")
	}
	if w == nil {
		d.stopped = true
		d.stopErr = errors.New("agent_disconnected")
		return d.stopErr
	}
	d.client = w
	if err := frame.Write(w, frame.Hello, []byte(frame.HelloMagic)); err != nil {
		d.stopped = true
		d.stopErr = err
		return err
	}
	d.hello = true
	return nil
}

// AcceptLease verifies one start grant. The nonce is remembered only after
// the shape, the signature, the phase, and the audio allow bit all pass.
func (d *Daemon) AcceptLease(payload []byte) error {
	if d.stopped {
		return d.stopErr
	}
	if !d.hello || d.haveLease {
		return d.stop("protocol_error")
	}
	g, err := lease.Parse(payload)
	if err != nil {
		return d.stop(err.Error())
	}
	if err := lease.Verify(d.pub, g, d.host, d.now()); err != nil {
		return d.stop(err.Error())
	}
	if g.Phase != "start" {
		return d.stop("bad_phase")
	}
	if g.Audio == 1 && !d.allow.Audio {
		return d.stop("target_denied_agent")
	}
	if err := d.nonces.Remember(g.NonceHex, d.now()); err != nil {
		return d.stop(err.Error())
	}
	d.terms = terms{
		session: g.SessionID, deadline: g.DeadlineUnix, seat: g.Seat, output: g.Output,
		audio: g.Audio, fps: g.MaxFPS, width: g.MaxWidth, bytes: g.MaxBytes, actor: g.Actor,
	}
	d.leaseExp = g.ExpiresUnix
	d.haveLease = true
	return nil
}

// AcceptGeometry opens the recording and then writes status.
func (d *Daemon) AcceptGeometry(payload []byte) error {
	if d.stopped {
		return d.stopErr
	}
	if !d.hello || !d.haveLease || d.connected {
		return d.stop("protocol_error")
	}
	if err := d.Poll(); err != nil {
		return err
	}
	var g frame.Size
	if frame.DecodeJSON(payload, &g) != nil {
		return d.stop("protocol_error")
	}
	if g.Width < 1 || int(g.Width) > d.terms.width || g.Height < 1 || int(g.Height) > d.terms.width {
		return d.stop("protocol_error")
	}
	hdr, err := json.Marshal(startRec{
		SessionID: d.terms.session, Actor: d.terms.actor, Seat: d.terms.seat,
		Output: d.terms.output, Audio: d.terms.audio, Width: g.Width, Height: g.Height,
	})
	if err != nil {
		return d.stop("recording_unavailable")
	}
	rec, err := record.Open(d.dir, d.terms.session, d.key, hdr, d.terms.bytes, d.minFree, d.now, d.free)
	if err != nil {
		return d.stop(err.Error())
	}
	d.rec = rec
	body, err := json.Marshal(Status{
		State: "connected", SessionID: d.terms.session, Width: g.Width, Height: g.Height,
		Audio: d.terms.audio, Actor: d.terms.actor, MaxFPS: d.terms.fps, MaxWidth: d.terms.width,
	})
	if err != nil {
		return d.stop("recording_unavailable")
	}
	now := d.now()
	d.width = g.Width
	d.height = g.Height
	d.lastMedia = now
	d.fpsWindow = now
	d.fpsCount = 0
	d.connected = true
	if err := frame.Write(d.client, frame.Status, body); err != nil {
		return d.stop("agent_disconnected")
	}
	return nil
}

// Control handles a frame from the agent pipe.
func (d *Daemon) Control(typ byte, payload []byte) error {
	if d.stopped {
		return d.stopErr
	}
	if !d.hello {
		return d.stop("protocol_error")
	}
	switch typ {
	case frame.Lease:
		return d.AcceptLease(payload)
	case frame.Renew:
		return d.acceptRenew(payload)
	case frame.Input:
		return d.stop("protocol_error")
	default:
		return d.stop("protocol_error")
	}
}

// Capture handles a frame from the capture pipe.
func (d *Daemon) Capture(typ byte, payload []byte) error {
	if d.stopped {
		return d.stopErr
	}
	if !d.hello {
		return d.stop("protocol_error")
	}
	if !d.connected {
		if typ != frame.Geometry {
			return d.stop("protocol_error")
		}
		return d.AcceptGeometry(payload)
	}
	switch typ {
	case frame.Video:
		return d.onVideo(payload)
	case frame.Audio:
		return d.onAudio(payload)
	default:
		return d.stop("protocol_error")
	}
}

// Poll applies the lease expiry, the deadline, and the idle limit.
// now == deadline stays up. now == expiry+30s stays up.
func (d *Daemon) Poll() error {
	if d.stopped {
		return d.stopErr
	}
	if !d.haveLease {
		return nil
	}
	now := d.now()
	if now.Unix() > d.leaseExp+int64(lease.Skew) {
		return d.stop("stopped")
	}
	if !d.connected {
		return nil
	}
	if now.Unix() > d.terms.deadline {
		return d.stop("max_duration")
	}
	if now.Sub(d.lastMedia) > idleFor {
		return d.stop("idle_timeout")
	}
	return nil
}

// Finish ends a session that the sync methods drove.
func (d *Daemon) Finish(reason string) error {
	if d.stopped {
		return d.stopErr
	}
	if !d.connected {
		return d.stop("protocol_error")
	}
	switch reason {
	case "closed", "stopped", "idle_timeout", "byte_cap", "max_duration",
		"recording_size_limit", "protocol_error", "agent_disconnected":
		err := d.stop(reason)
		if err != nil && err.Error() == reason {
			return nil
		}
		return err
	default:
		return d.stop("protocol_error")
	}
}

func (d *Daemon) acceptRenew(payload []byte) error {
	if !d.haveLease {
		return d.stop("protocol_error")
	}
	if d.now().Unix() > d.leaseExp+int64(lease.Skew) {
		return d.stop("stopped")
	}
	g, err := lease.Parse(payload)
	if err != nil {
		return d.stop(err.Error())
	}
	if err := lease.Verify(d.pub, g, d.host, d.now()); err != nil {
		return d.stop(err.Error())
	}
	if g.Phase != "renew" {
		return d.stop("bad_phase")
	}
	if !d.terms.same(g) {
		return d.stop("lease_binding")
	}
	if err := d.nonces.Remember(g.NonceHex, d.now()); err != nil {
		return d.stop(err.Error())
	}
	d.leaseExp = g.ExpiresUnix
	return nil
}

func (d *Daemon) onVideo(payload []byte) error {
	v, err := frame.ParseVideo(payload)
	if err != nil || !tileInside(v, d.width, d.height) {
		return d.stop("protocol_error")
	}
	if !d.allowFPS() {
		return d.stop("protocol_error")
	}
	if !d.room(len(payload)) {
		return d.stop(capReason(d.terms.bytes))
	}
	if err := d.rec.Append("video", payload); err != nil {
		return d.stop(err.Error())
	}
	d.media += int64(len(payload))
	d.lastMedia = d.now()
	d.fpsCount++
	return d.forward(frame.Video, payload)
}

func (d *Daemon) onAudio(payload []byte) error {
	a, err := frame.ParseAudio(payload)
	if err != nil || d.terms.audio != 1 || !d.allow.Audio || audioTooLong(a) {
		return d.stop("protocol_error")
	}
	if !d.room(len(payload)) {
		return d.stop(capReason(d.terms.bytes))
	}
	if err := d.rec.Append("audio", payload); err != nil {
		return d.stop(err.Error())
	}
	d.media += int64(len(payload))
	d.lastMedia = d.now()
	return d.forward(frame.Audio, payload)
}

func (d *Daemon) allowFPS() bool {
	now := d.now()
	if d.fpsWindow.IsZero() || now.Sub(d.fpsWindow) >= time.Second {
		d.fpsWindow = now
		d.fpsCount = 0
	}
	return d.fpsCount < d.terms.fps
}

func (d *Daemon) room(n int) bool {
	if n < 1 {
		return false
	}
	add := int64(n)
	if d.media > d.terms.bytes-add || d.media > record.HardMax-add {
		return false
	}
	return true
}

func (d *Daemon) forward(typ byte, payload []byte) error {
	if err := frame.Write(d.client, typ, payload); err != nil {
		return d.stop("agent_disconnected")
	}
	return nil
}

func (d *Daemon) stop(code string) error {
	if d.stopped {
		if d.stopErr != nil {
			return d.stopErr
		}
		return errors.New("protocol_error")
	}
	d.stopped = true
	code = publicCode(code)
	rec := d.rec
	d.rec = nil
	if rec != nil {
		meta, err := json.Marshal(struct {
			Reason string `json:"reason"`
		}{code})
		if err != nil {
			d.stopErr = errors.New("recording_unavailable")
			return d.stopErr
		}
		digest, err := rec.Finish(meta)
		if err != nil || !digestRe.MatchString(digest) {
			d.stopErr = errors.New("recording_unavailable")
			return d.stopErr
		}
		body, err := json.Marshal(Close{Reason: code, Bytes: d.media, Digest: digest})
		if err != nil {
			d.stopErr = errors.New("recording_unavailable")
			return d.stopErr
		}
		if d.client != nil {
			if werr := frame.Write(d.client, frame.Close, body); werr != nil {
				d.stopErr = errors.New("agent_disconnected")
				return d.stopErr
			}
		}
		d.stopErr = errors.New(code)
		return d.stopErr
	}
	if d.hello && d.client != nil {
		body, err := json.Marshal(struct {
			Code string `json:"code"`
		}{code})
		if err != nil {
			d.stopErr = errors.New("internal")
			return d.stopErr
		}
		if werr := frame.Write(d.client, frame.Reject, body); werr != nil {
			d.stopErr = errors.New("agent_disconnected")
			return d.stopErr
		}
	}
	d.stopErr = errors.New(code)
	return d.stopErr
}

func publicCode(s string) string {
	if codeRe.MatchString(s) {
		return s
	}
	return "internal"
}

func capReason(max int64) string {
	if max >= record.HardMax {
		return "recording_size_limit"
	}
	return "byte_cap"
}

func tileInside(v frame.Tile, w, h uint16) bool {
	if v.W == 0 || v.H == 0 {
		return false
	}
	if uint32(v.X)+uint32(v.W) > uint32(w) || uint32(v.Y)+uint32(v.H) > uint32(h) {
		return false
	}
	return true
}

func audioTooLong(a frame.PCM) bool {
	unit := int(a.Channels) * 2
	if unit <= 0 || a.Rate == 0 {
		return true
	}
	samples := len(a.PCM) / unit
	return uint64(samples) > uint64(a.Rate)
}

type frameMsg struct {
	typ byte
	p   []byte
	err error
}

// Serve reads the lease from control and the picture from capture, and writes
// the client frames to client. It closes control and capture when it returns.
// Capture EOF after status ends the session with reason closed.
func (d *Daemon) Serve(control io.ReadCloser, client io.Writer, capture io.ReadCloser) error {
	if control == nil || capture == nil {
		return errors.New("protocol_error")
	}
	stop := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	var capCh chan frameMsg
	var ctlCh chan frameMsg
	shutdown := func() {
		once.Do(func() {
			close(stop)
			_ = control.Close()
			_ = capture.Close()
		})
	}
	defer func() {
		shutdown()
		if capCh == nil {
			wg.Wait()
			return
		}
		// A read blocked on send must be able to finish after stop is closed.
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		for {
			select {
			case <-done:
				return
			case <-capCh:
			case <-ctlCh:
			}
		}
	}()
	if err := d.Hello(client); err != nil {
		return err
	}
	typ, p, err := frame.Read(control)
	if err != nil {
		if errors.Is(err, frame.ErrProtocol) {
			return d.stop("protocol_error")
		}
		return d.stop("agent_disconnected")
	}
	if err := d.Control(typ, p); err != nil {
		return err
	}
	typ, p, err = frame.Read(capture)
	if err != nil {
		if errors.Is(err, frame.ErrProtocol) {
			return d.stop("protocol_error")
		}
		return d.stop("display_unavailable")
	}
	if err := d.Capture(typ, p); err != nil {
		return err
	}
	capCh = make(chan frameMsg)
	ctlCh = make(chan frameMsg)
	wg.Add(2)
	go func() {
		defer wg.Done()
		readLoop(capture, capCh, stop)
	}()
	go func() {
		defer wg.Done()
		readLoop(control, ctlCh, stop)
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		var step error
		select {
		case m := <-capCh:
			step = d.takeCapture(m)
		case m := <-ctlCh:
			step = d.takeControl(m)
		case <-tick.C:
			step = d.Poll()
		}
		if step != nil {
			return step
		}
	}
}

func (d *Daemon) takeCapture(m frameMsg) error {
	if m.err != nil {
		if errors.Is(m.err, io.EOF) {
			return d.stop("closed")
		}
		if errors.Is(m.err, frame.ErrProtocol) || errors.Is(m.err, io.ErrUnexpectedEOF) {
			return d.stop("protocol_error")
		}
		return d.stop("display_unavailable")
	}
	return d.Capture(m.typ, m.p)
}

func (d *Daemon) takeControl(m frameMsg) error {
	if m.err != nil {
		if errors.Is(m.err, frame.ErrProtocol) || errors.Is(m.err, io.ErrUnexpectedEOF) {
			return d.stop("protocol_error")
		}
		return d.stop("agent_disconnected")
	}
	return d.Control(m.typ, m.p)
}

func readLoop(r io.Reader, ch chan<- frameMsg, stop <-chan struct{}) {
	for {
		type one struct {
			typ byte
			p   []byte
			err error
		}
		got := make(chan one, 1)
		go func() {
			typ, p, err := frame.Read(r)
			got <- one{typ, p, err}
		}()
		select {
		case <-stop:
			return
		case m := <-got:
			msg := frameMsg{typ: m.typ, p: m.p, err: m.err}
			select {
			case <-stop:
				return
			case ch <- msg:
			}
			if m.err != nil {
				return
			}
		}
	}
}
