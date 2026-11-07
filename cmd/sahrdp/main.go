// Threats: a world-readable or symlinked recording key, a symlink or socket
// used as capture, an allow list that omits virtual, and an error string that
// contains a filesystem path. The command prints a code. It does not listen
// and it does not dial.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/afterdarksys/sahrdp/internal/frame"
	"github.com/afterdarksys/sahrdp/internal/record"
	"github.com/afterdarksys/sahrdp/internal/session"
)

var (
	codeRe    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	sessionRe = regexp.MustCompile(`^dsp_[A-Za-z0-9_-]{16,64}$`)
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, in io.Reader, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errw, "usage")
		return 2
	}
	switch args[0] {
	case "daemon":
		return runDaemon(args[1:], in, out, errw)
	case "client":
		return runClient(args[1:], in, out, errw)
	case "verify":
		return runVerify(args[1:], out, errw)
	default:
		fmt.Fprintln(errw, "usage")
		return 2
	}
}

func runDaemon(args []string, in io.Reader, out, errw io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host-id", "", "")
	pubPath := fs.String("control-pub", "", "")
	allowS := fs.String("allow", "", "")
	dir := fs.String("record-dir", "", "")
	keyPath := fs.String("record-key", "", "")
	capture := fs.String("capture", "", "")
	minFreeS := fs.String("min-free", "0", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(errw, "usage")
		return 2
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if !visited["allow"] || *host == "" || *pubPath == "" || *dir == "" || *keyPath == "" || *capture == "" {
		fmt.Fprintln(errw, "usage")
		return 2
	}
	allow, code := parseAllow(*allowS)
	if code != "" {
		fmt.Fprintln(errw, code)
		return 2
	}
	minFree, err := strconv.ParseUint(*minFreeS, 10, 64)
	if err != nil {
		fmt.Fprintln(errw, "usage")
		return 2
	}
	key, err := readKey(*keyPath)
	if err != nil {
		fmt.Fprintln(errw, "bad_key")
		return 1
	}
	pub, err := readPub(*pubPath)
	if err != nil {
		fmt.Fprintln(errw, "malformed")
		return 1
	}
	if err := session.CheckCapture(*capture); err != nil {
		fmt.Fprintln(errw, "display_unavailable")
		return 1
	}
	d, err := session.New(session.Config{
		HostID: *host, Pub: pub, Allow: allow, RecordDir: *dir,
		RecordKey: key, MinFree: minFree,
	})
	if err != nil {
		return finish(errw, err)
	}
	capFile, err := session.OpenCapture(*capture)
	if err != nil {
		fmt.Fprintln(errw, "display_unavailable")
		return 1
	}
	return finish(errw, d.Serve(asCloser(in), plainWriter{out}, capFile))
}

func runClient(args []string, in io.Reader, out, errw io.Writer) int {
	_ = out
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("out", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" {
		fmt.Fprintln(errw, "usage")
		return 2
	}
	if err := prepareDir(*dir); err != nil {
		fmt.Fprintln(errw, "internal")
		return 1
	}
	c := session.NewClient(in)
	var st *session.Status
	var audioF *os.File
	tiles := 0
	defer func() {
		if audioF != nil {
			_ = audioF.Close()
		}
	}()
	for {
		ev, err := c.Next()
		if ev.Reject != "" {
			fmt.Fprintln(errw, ev.Reject)
			return statusOf(ev.Reject)
		}
		if ev.Close != nil {
			if st == nil || !sessionRe.MatchString(st.SessionID) {
				fmt.Fprintln(errw, "protocol_error")
				return 1
			}
			body, merr := json.Marshal(sessionFile{
				SessionID: st.SessionID, Width: st.Width, Height: st.Height, Audio: st.Audio,
				Actor: st.Actor, MaxFPS: st.MaxFPS, MaxWidth: st.MaxWidth,
				Reason: ev.Close.Reason, Bytes: ev.Close.Bytes, Digest: ev.Close.Digest,
			})
			if merr != nil {
				fmt.Fprintln(errw, "internal")
				return 1
			}
			if werr := writeNew(*dir, "session.json", append(body, '\n')); werr != nil {
				fmt.Fprintln(errw, "internal")
				return 1
			}
			fmt.Fprintln(errw, ev.Close.Reason)
			if ev.Close.Reason == "closed" {
				return 0
			}
			return 1
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(errw, "protocol_error")
				return 1
			}
			return finish(errw, err)
		}
		switch ev.Type {
		case frame.Hello:
		case frame.Status:
			if ev.Status == nil || !sessionRe.MatchString(ev.Status.SessionID) {
				fmt.Fprintln(errw, "protocol_error")
				return 1
			}
			st = ev.Status
		case frame.Video:
			if st == nil || ev.Video == nil {
				fmt.Fprintln(errw, "protocol_error")
				return 1
			}
			tiles++
			if tiles > 999999 {
				fmt.Fprintln(errw, "protocol_error")
				return 1
			}
			if werr := writeNew(*dir, fmt.Sprintf("%06d.jpg", tiles), ev.Video.JPEG); werr != nil {
				fmt.Fprintln(errw, "internal")
				return 1
			}
		case frame.Audio:
			if st == nil || ev.Audio == nil {
				fmt.Fprintln(errw, "protocol_error")
				return 1
			}
			if audioF == nil {
				f, oerr := createPrivate(*dir, "audio.s16le")
				if oerr != nil {
					fmt.Fprintln(errw, "internal")
					return 1
				}
				audioF = f
			}
			if _, werr := audioF.Write(ev.Audio.PCM); werr != nil {
				fmt.Fprintln(errw, "internal")
				return 1
			}
		default:
			fmt.Fprintln(errw, "protocol_error")
			return 1
		}
	}
}

func runVerify(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", "", "")
	keyPath := fs.String("key", "", "")
	sid := fs.String("session", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *file == "" || *keyPath == "" || *sid == "" {
		fmt.Fprintln(errw, "usage")
		return 2
	}
	key, err := readKey(*keyPath)
	if err != nil {
		fmt.Fprintln(errw, "bad_key")
		return 1
	}
	digest, err := record.Verify(*file, key, *sid)
	if err != nil {
		fmt.Fprintln(errw, verifyCode(err))
		return 1
	}
	fmt.Fprintln(out, digest)
	return 0
}

type sessionFile struct {
	SessionID string `json:"session_id"`
	Width     uint16 `json:"width"`
	Height    uint16 `json:"height"`
	Audio     int    `json:"audio"`
	Actor     string `json:"actor"`
	MaxFPS    int    `json:"max_fps"`
	MaxWidth  int    `json:"max_width"`
	Reason    string `json:"reason"`
	Bytes     int64  `json:"bytes"`
	Digest    string `json:"digest"`
}

type plainWriter struct{ w io.Writer }

func (p plainWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if err != nil {
		return n, errors.New("agent_disconnected")
	}
	return n, nil
}

func asCloser(r io.Reader) io.ReadCloser {
	if r == nil {
		return nil
	}
	if rc, ok := r.(io.ReadCloser); ok {
		return rc
	}
	return io.NopCloser(r)
}

func parseAllow(s string) (session.Allow, string) {
	if strings.TrimSpace(s) == "" {
		return session.Allow{}, "target_denied_agent"
	}
	seen := map[string]bool{}
	var allow session.Allow
	for _, part := range strings.Split(s, ",") {
		tok := strings.TrimSpace(part)
		if tok == "" || seen[tok] {
			return session.Allow{}, "bad_allow"
		}
		seen[tok] = true
		switch tok {
		case "virtual":
			allow.Virtual = true
		case "audio":
			allow.Audio = true
		default:
			return session.Allow{}, "bad_allow"
		}
	}
	if !allow.Virtual {
		return session.Allow{}, "target_denied_agent"
	}
	return allow, ""
}

func finish(errw io.Writer, err error) int {
	if err == nil {
		return 0
	}
	code := err.Error()
	var pe *os.PathError
	if errors.As(err, &pe) || !codeRe.MatchString(code) {
		code = "internal"
	}
	fmt.Fprintln(errw, code)
	return statusOf(code)
}

func verifyCode(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) || !codeRe.MatchString(err.Error()) {
		return "recording_unavailable"
	}
	return err.Error()
}

func statusOf(code string) int {
	switch code {
	case "usage", "bad_allow", "target_denied_agent":
		return 2
	case "closed":
		return 0
	default:
		return 1
	}
}
