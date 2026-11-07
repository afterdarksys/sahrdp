// Threats: a forged display lease, a lease for another host or action, an
// expired or over-long grant, a field swapped after signing, a v2 or intent
// lease, and a nonce replayed inside 10 minutes. Verify rejects tampered,
// expired, oversized, and wrong-key input and fails closed.
// Does NOT persist nonces. Does NOT accept an algorithm tag. The daemon does
// not mint leases.
package lease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	prefix  = "systemapi-lease-v1\n"
	Action  = "display"
	Skew    = 30
	MaxTTL  = 300
	MaxDead = 28800
	MaxFPS  = 5
	MaxWide = 1280
	MaxByte = int64(1) << 30
)

var (
	hostRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sessionRe = regexp.MustCompile(`^dsp_[A-Za-z0-9_-]{16,64}$`)
	actorRe   = regexp.MustCompile(`^[A-Za-z0-9_.:@+-]{1,128}$`)
	nonceRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hashRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Grant is a v1 display lease plus the fields the daemon rebuilds.
type Grant struct {
	V           int    `json:"v"`
	HostID      string `json:"host_id"`
	Action      string `json:"action"`
	ExpiresUnix int64  `json:"expires_unix"`
	NonceHex    string `json:"nonce_hex"`
	PayloadSHA  string `json:"payload_sha256"`
	IntentSHA   string `json:"intent_sha256,omitempty"`
	Signature   string `json:"signature"`

	SessionID    string `json:"session_id"`
	DeadlineUnix int64  `json:"deadline_unix"`
	Phase        string `json:"phase"`
	Seat         string `json:"seat"`
	Output       string `json:"output"`
	Audio        int    `json:"audio"`
	MaxFPS       int    `json:"max_fps"`
	MaxWidth     int    `json:"max_width"`
	MaxBytes     int64  `json:"max_bytes"`
	Actor        string `json:"actor"`
}

// Parse decodes one grant and refuses unknown fields, trailing data, and a
// body over 64 KiB.
func Parse(p []byte) (Grant, error) {
	if len(p) == 0 || len(p) > 65536 {
		return Grant{}, errors.New("malformed")
	}
	dec := json.NewDecoder(bytesReader(p))
	dec.DisallowUnknownFields()
	var g Grant
	if err := dec.Decode(&g); err != nil {
		return Grant{}, errors.New("malformed")
	}
	if dec.More() || dec.InputOffset() != int64(len(p)) {
		return Grant{}, errors.New("malformed")
	}
	return g, nil
}

// Sign fills the v1 envelope. now bounds the deadline. The daemon never calls this.
func (g Grant) Sign(priv ed25519.PrivateKey, now time.Time) (Grant, error) {
	if len(priv) != ed25519.PrivateKeySize || !hostRe.MatchString(g.HostID) {
		return Grant{}, errors.New("malformed")
	}
	if !nonceRe.MatchString(g.NonceHex) || g.ExpiresUnix <= 0 {
		return Grant{}, errors.New("bad_nonce")
	}
	payload, err := g.shape(now)
	if err != nil {
		return Grant{}, err
	}
	out := g
	out.V = 1
	out.Action = Action
	out.IntentSHA = ""
	out.PayloadSHA = payloadHash(payload)
	msg := canonical(out.HostID, out.ExpiresUnix, out.NonceHex, out.PayloadSHA)
	out.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	return out, nil
}

// Verify checks the shape, then the v1 signature. It does not remember the nonce.
func Verify(pub ed25519.PublicKey, g Grant, host string, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize || g.V != 1 || g.IntentSHA != "" {
		return errors.New("malformed")
	}
	payload, err := g.shape(now)
	if err != nil {
		return err
	}
	if !hostRe.MatchString(host) || !hostRe.MatchString(g.HostID) ||
		subtle.ConstantTimeCompare([]byte(g.HostID), []byte(host)) != 1 {
		return errors.New("bad_host")
	}
	if g.Action != Action {
		return errors.New("bad_action")
	}
	if g.ExpiresUnix <= 0 {
		return errors.New("bad_expiry")
	}
	if !nonceRe.MatchString(g.NonceHex) {
		return errors.New("bad_nonce")
	}
	nowUnix := now.Unix()
	if g.ExpiresUnix < nowUnix-Skew {
		return errors.New("expired")
	}
	if g.ExpiresUnix > nowUnix+MaxTTL {
		return errors.New("expiry_too_far")
	}
	if !hashEqual(payloadHash(payload), g.PayloadSHA) {
		return errors.New("payload_mismatch")
	}
	sig, err := base64.StdEncoding.DecodeString(g.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != g.Signature {
		return errors.New("bad_signature")
	}
	msg := canonical(g.HostID, g.ExpiresUnix, g.NonceHex, g.PayloadSHA)
	if !ed25519.Verify(pub, []byte(msg), sig) {
		return errors.New("bad_signature")
	}
	return nil
}

func (g Grant) shape(now time.Time) (string, error) {
	if !sessionRe.MatchString(g.SessionID) {
		return "", errors.New("bad_session_id")
	}
	if now.IsZero() || g.DeadlineUnix <= 0 {
		return "", errors.New("bad_deadline")
	}
	nowUnix := now.Unix()
	if g.DeadlineUnix <= nowUnix || g.DeadlineUnix > nowUnix+MaxDead {
		return "", errors.New("bad_deadline")
	}
	if g.Phase != "start" && g.Phase != "renew" {
		return "", errors.New("bad_phase")
	}
	if g.Seat != "virtual" || g.Output != "0" {
		return "", errors.New("bad_target")
	}
	if g.Audio != 0 && g.Audio != 1 {
		return "", errors.New("bad_caps")
	}
	if g.MaxFPS < 1 || g.MaxFPS > MaxFPS || g.MaxWidth < 1 || g.MaxWidth > MaxWide || g.MaxBytes < 1 || g.MaxBytes > MaxByte {
		return "", errors.New("bad_caps")
	}
	if !actorRe.MatchString(g.Actor) {
		return "", errors.New("bad_actor")
	}
	return strings.Join([]string{
		g.SessionID,
		strconv.FormatInt(g.DeadlineUnix, 10),
		g.Phase,
		g.Seat,
		g.Output,
		strconv.Itoa(g.Audio),
		strconv.Itoa(g.MaxFPS),
		strconv.Itoa(g.MaxWidth),
		strconv.FormatInt(g.MaxBytes, 10),
		g.Actor,
	}, "\n"), nil
}

func canonical(host string, expires int64, nonce, sum string) string {
	return prefix + host + "\n" + Action + "\n" + strconv.FormatInt(expires, 10) + "\n" + nonce + "\n" + sum + "\n"
}

func payloadHash(payload string) string {
	sum := sha256.Sum256([]byte(Action + "\n" + payload))
	return hex.EncodeToString(sum[:])
}

func hashEqual(a, b string) bool {
	if !hashRe.MatchString(a) || !hashRe.MatchString(b) {
		return false
	}
	ab, err1 := hex.DecodeString(a)
	bb, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil || len(ab) != len(bb) {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// Nonces remembers nonce hex for 10 minutes. It is not saved to disk.
type Nonces struct {
	mu sync.Mutex
	m  map[string]time.Time
}

// Remember returns replay when nonce was seen inside the last 10 minutes.
func (n *Nonces) Remember(nonce string, now time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.m == nil {
		n.m = map[string]time.Time{}
	}
	cutoff := now.Add(-10 * time.Minute)
	for k, seen := range n.m {
		if seen.Before(cutoff) {
			delete(n.m, k)
		}
	}
	if _, ok := n.m[nonce]; ok {
		return errors.New("replay")
	}
	n.m[nonce] = now
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
