// Threats: a peer that exceeds the leased ceilings, an unknown frame
// (clipboard, input, drive, printer), a close whose digest or byte count
// does not match the media, and a status that arrives after a reject.
// The client checks the ceilings again. It cannot verify the recording HMAC.
// Does NOT dial a host and does NOT listen.
package session

import (
	"errors"
	"io"
	"time"

	"github.com/afterdarksys/sahrdp/internal/frame"
	"github.com/afterdarksys/sahrdp/internal/lease"
)

// Event is one step of a client session.
type Event struct {
	Type   byte
	Status *Status
	Video  *frame.Tile
	Audio  *frame.PCM
	Close  *Close
	Reject string
}

// Client reads one sahrdp/1 session. It is not safe for concurrent use.
type Client struct {
	r         io.Reader
	now       func() time.Time
	step      int
	st        Status
	have      bool
	media     int64
	fpsWindow time.Time
	fpsCount  int
	failed    bool
	done      bool
	err       error
}

// NewClient reads from r. The clock is time.Now until SetClock.
func NewClient(r io.Reader) *Client {
	return &Client{r: r, now: time.Now}
}

// SetClock replaces the clock used for the frame-rate window.
func (c *Client) SetClock(now func() time.Time) {
	if now != nil {
		c.now = now
	}
}

// Next returns the next event. A reject or a protocol error is returned
// once. The following call returns io.EOF. A close frame is returned with a
// nil error; the call after that returns io.EOF.
func (c *Client) Next() (Event, error) {
	if c.done {
		return Event{}, io.EOF
	}
	if c.failed {
		c.done = true
		return Event{}, io.EOF
	}
	if c.r == nil || c.now == nil {
		return c.fail(errors.New("protocol_error"))
	}
	typ, p, err := frame.Read(c.r)
	if err != nil {
		return c.fail(errors.New("protocol_error"))
	}
	switch c.step {
	case 0:
		if typ != frame.Hello || string(p) != frame.HelloMagic {
			return c.fail(errors.New("protocol_error"))
		}
		c.step = 1
		return Event{Type: typ}, nil
	case 1:
		if typ == frame.Reject {
			return c.reject(p)
		}
		if typ != frame.Status {
			return c.fail(errors.New("protocol_error"))
		}
		var st Status
		if frame.DecodeJSON(p, &st) != nil || !validStatus(st) {
			return c.fail(errors.New("protocol_error"))
		}
		c.st = st
		c.have = true
		c.fpsWindow = c.now()
		c.fpsCount = 0
		c.step = 2
		cp := st
		return Event{Type: typ, Status: &cp}, nil
	case 2:
		switch typ {
		case frame.Video:
			return c.video(p)
		case frame.Audio:
			return c.audio(p)
		case frame.Close:
			return c.finish(p)
		default:
			return c.fail(errors.New("protocol_error"))
		}
	default:
		return c.fail(errors.New("protocol_error"))
	}
}

func (c *Client) video(p []byte) (Event, error) {
	v, err := frame.ParseVideo(p)
	if err != nil || !c.have || !tileInside(v, c.st.Width, c.st.Height) || !c.allowFPS() {
		return c.fail(errors.New("protocol_error"))
	}
	if !c.addMedia(len(p)) {
		return c.fail(errors.New("protocol_error"))
	}
	c.fpsCount++
	cp := v
	return Event{Type: frame.Video, Video: &cp}, nil
}

func (c *Client) audio(p []byte) (Event, error) {
	a, err := frame.ParseAudio(p)
	if err != nil || !c.have || c.st.Audio != 1 || audioTooLong(a) {
		return c.fail(errors.New("protocol_error"))
	}
	if !c.addMedia(len(p)) {
		return c.fail(errors.New("protocol_error"))
	}
	cp := a
	return Event{Type: frame.Audio, Audio: &cp}, nil
}

func (c *Client) finish(p []byte) (Event, error) {
	var cl Close
	if frame.DecodeJSON(p, &cl) != nil || !closeReason(cl.Reason) || !digestRe.MatchString(cl.Digest) || cl.Bytes != c.media {
		return c.fail(errors.New("protocol_error"))
	}
	c.done = true
	cp := cl
	return Event{Type: frame.Close, Close: &cp}, nil
}

func (c *Client) reject(p []byte) (Event, error) {
	var body struct {
		Code string `json:"code"`
	}
	if frame.DecodeJSON(p, &body) != nil || !codeRe.MatchString(body.Code) {
		return c.fail(errors.New("protocol_error"))
	}
	c.failed = true
	c.err = errors.New(body.Code)
	return Event{Type: frame.Reject, Reject: body.Code}, c.err
}

func (c *Client) fail(err error) (Event, error) {
	c.failed = true
	c.err = err
	return Event{}, err
}

func (c *Client) allowFPS() bool {
	now := c.now()
	if c.fpsWindow.IsZero() || now.Sub(c.fpsWindow) >= time.Second {
		c.fpsWindow = now
		c.fpsCount = 0
	}
	return c.fpsCount < c.st.MaxFPS
}

func (c *Client) addMedia(n int) bool {
	if n < 1 {
		return false
	}
	add := int64(n)
	if c.media > lease.MaxByte-add {
		return false
	}
	c.media += add
	return true
}

func validStatus(s Status) bool {
	if s.State != "connected" || !sessionRe.MatchString(s.SessionID) || !actorRe.MatchString(s.Actor) {
		return false
	}
	if s.Width < 1 || s.Height < 1 || int(s.Width) > lease.MaxWide || int(s.Height) > lease.MaxWide {
		return false
	}
	if s.MaxFPS < 1 || s.MaxFPS > lease.MaxFPS || s.MaxWidth < 1 || s.MaxWidth > lease.MaxWide {
		return false
	}
	if int(s.Width) > s.MaxWidth || int(s.Height) > s.MaxWidth {
		return false
	}
	if s.Audio != 0 && s.Audio != 1 {
		return false
	}
	return true
}

func closeReason(s string) bool {
	switch s {
	case "closed", "idle_timeout", "byte_cap", "max_duration", "recording_size_limit",
		"stopped", "protocol_error", "agent_disconnected", "lease_binding",
		"bad_signature", "expired", "replay", "payload_mismatch", "bad_host",
		"bad_action", "malformed", "bad_phase", "bad_caps", "bad_target",
		"bad_session_id", "bad_deadline", "bad_actor", "bad_nonce", "bad_expiry",
		"expiry_too_far", "target_denied_agent", "recording_unavailable",
		"display_unavailable", "internal":
		return true
	default:
		return false
	}
}
