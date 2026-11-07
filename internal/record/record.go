// Threats: a recording edited after the fact, a session that starts on a full
// disk, and a line that is forwarded when the write failed. Append refuses a
// line that does not fit. The key is the caller's 32 bytes; this package does
// not mint one.
// Does NOT verify as a PTY recording. The seed domain is display-specific, so
// a PTY verifier fails the MAC.
package record

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

const (
	seedDomain     = "systemapi-display-recording-v1\n"
	HardMax        = int64(1) << 30
	MinFreeDefault = uint64(1) << 30
	maxLine        = 256 * 1024
)

var (
	sessionRe = regexp.MustCompile(`^dsp_[A-Za-z0-9_-]{16,64}$`)
	macRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type recLine struct {
	Seq  uint64 `json:"seq"`
	T    int64  `json:"t"`
	Kind string `json:"k"`
	B64  string `json:"b64"`
	MAC  string `json:"mac"`
}

// Recorder is an append-only HMAC chain. It is not safe for concurrent use.
type Recorder struct {
	key     []byte
	path    string
	f       *os.File
	prev    string
	seq     uint64
	written int64
	max     int64
	closed  bool
	now     func() time.Time
}

// Open creates dir/sessionID.rec and writes the start line. header is the
// start payload. A start line that does not fit is removed and refused.
func Open(dir, sessionID string, key, header []byte, maxBytes int64, minFree uint64, now func() time.Time, free func(string) (uint64, error)) (*Recorder, error) {
	if len(key) != 32 || !sessionRe.MatchString(sessionID) || maxBytes < 1 || maxBytes > HardMax {
		return nil, errors.New("recording_unavailable")
	}
	if now == nil {
		now = time.Now
	}
	if free == nil {
		free = FreeBytes
	}
	if minFree == 0 {
		minFree = MinFreeDefault
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errors.New("recording_unavailable")
	}
	if err := checkDir(dir); err != nil {
		return nil, errors.New("recording_unavailable")
	}
	avail, err := free(dir)
	if err != nil || avail < minFree {
		return nil, errors.New("recording_unavailable")
	}
	name := sessionID + ".rec"
	path := filepath.Join(dir, name)
	if filepath.Base(path) != name {
		return nil, errors.New("recording_unavailable")
	}
	f, err := openExclusive(path)
	if err != nil {
		return nil, errors.New("recording_unavailable")
	}
	r := &Recorder{
		key:  append([]byte(nil), key...),
		path: path,
		f:    f,
		prev: recordingSeed(key, sessionID),
		max:  maxBytes,
		now:  now,
	}
	if err := r.writeLine("start", header, true); err != nil {
		_ = r.f.Close()
		os.Remove(path)
		if err.Error() == "byte_cap" || err.Error() == "recording_size_limit" {
			return nil, errors.New("recording_unavailable")
		}
		return nil, err
	}
	return r, nil
}

// Path is the recording file.
func (r *Recorder) Path() string { return r.path }

// Append writes one video or audio payload. The caller forwards only after this returns nil.
func (r *Recorder) Append(kind string, data []byte) error {
	if r == nil || r.closed || (kind != "video" && kind != "audio") || len(data) == 0 {
		return errors.New("recording_unavailable")
	}
	return r.writeLine(kind, data, true)
}

// Finish writes the end line even when it passes the cap by a small amount,
// and returns the final MAC.
func (r *Recorder) Finish(meta []byte) (string, error) {
	if r == nil || r.closed {
		return "", errors.New("recording_unavailable")
	}
	r.closed = true
	if err := r.writeLine("end", meta, false); err != nil {
		_ = r.f.Close()
		return "", err
	}
	digest := r.prev
	if err := r.f.Sync(); err != nil {
		_ = r.f.Close()
		return "", errors.New("recording_unavailable")
	}
	if err := r.f.Close(); err != nil {
		return "", errors.New("recording_unavailable")
	}
	return digest, nil
}

func (r *Recorder) writeLine(kind string, data []byte, capIt bool) error {
	seq := r.seq + 1
	b64 := base64.StdEncoding.EncodeToString(data)
	t := r.now().UnixMilli()
	mac := recordingMAC(r.key, r.prev, seq, t, kind, b64)
	line, err := json.Marshal(recLine{Seq: seq, T: t, Kind: kind, B64: b64, MAC: mac})
	if err != nil {
		return errors.New("recording_unavailable")
	}
	line = append(line, '\n')
	if capIt && r.written+int64(len(line)) > r.max {
		if kind == "start" {
			return errors.New("recording_unavailable")
		}
		if r.max >= HardMax {
			return errors.New("recording_size_limit")
		}
		return errors.New("byte_cap")
	}
	if _, err := r.f.Write(line); err != nil {
		return errors.New("recording_unavailable")
	}
	if err := r.f.Sync(); err != nil {
		return errors.New("recording_unavailable")
	}
	r.seq = seq
	r.prev = mac
	r.written += int64(len(line))
	return nil
}

func recordingSeed(key []byte, sessionID string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(seedDomain + sessionID))
	return hex.EncodeToString(m.Sum(nil))
}

func recordingMAC(key []byte, prev string, seq uint64, t int64, kind, b64 string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(prev + "\n" + strconv.FormatUint(seq, 10) + "\n" + strconv.FormatInt(t, 10) + "\n" + kind + "\n" + b64))
	return hex.EncodeToString(m.Sum(nil))
}

// Verify replays one display recording. Kinds are start, then video or audio, then end.
func Verify(path string, key []byte, sessionID string) (string, error) {
	if len(key) != 32 || !sessionRe.MatchString(sessionID) {
		return "", errors.New("recording_malformed")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	prev := recordingSeed(key, sessionID)
	var seq uint64
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	for sc.Scan() {
		var l recLine
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			return "", errors.New("recording_malformed")
		}
		seq++
		if l.Seq != seq {
			return "", errors.New("recording_sequence_broken")
		}
		if !macEqual(recordingMAC(key, prev, l.Seq, l.T, l.Kind, l.B64), l.MAC) {
			return "", errors.New("recording_mac_mismatch")
		}
		if seq == 1 {
			if l.Kind != "start" {
				return "", errors.New("recording_no_start")
			}
			raw, err := base64.StdEncoding.DecodeString(l.B64)
			var meta struct {
				SessionID string `json:"session_id"`
			}
			if err != nil || json.Unmarshal(raw, &meta) != nil || meta.SessionID != sessionID {
				return "", errors.New("recording_session_mismatch")
			}
		} else if last == "end" {
			return "", errors.New("recording_data_after_end")
		} else if l.Kind != "video" && l.Kind != "audio" && l.Kind != "end" {
			return "", errors.New("recording_malformed")
		}
		prev = l.MAC
		last = l.Kind
	}
	if err := sc.Err(); err != nil {
		return "", errors.New("recording_malformed")
	}
	if seq == 0 {
		return "", errors.New("recording_empty")
	}
	if last != "end" {
		return "", errors.New("recording_truncated")
	}
	return prev, nil
}

func macEqual(want, got string) bool {
	if !macRe.MatchString(want) || !macRe.MatchString(got) {
		return false
	}
	a, err1 := hex.DecodeString(want)
	b, err2 := hex.DecodeString(got)
	if err1 != nil || err2 != nil || len(a) != 32 || len(b) != 32 {
		return false
	}
	return hmac.Equal(a, b)
}
