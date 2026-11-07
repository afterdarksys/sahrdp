//go:build unix

package session

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCaptureFileModes(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sahrdp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	if err := CheckCapture(""); err == nil || err.Error() != "display_unavailable" {
		t.Fatal(err)
	}
	if err := CheckCapture(dir); err == nil || err.Error() != "display_unavailable" {
		t.Fatal(err)
	}

	good := filepath.Join(dir, "pic")
	if err := os.WriteFile(good, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckCapture(good); err != nil {
		t.Fatal(err)
	}
	f, err := OpenCapture(good)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != "capture" {
		t.Fatal(f.Name())
	}
	f.Close()

	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckCapture(loose); err == nil || err.Error() != "display_unavailable" {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckCapture(link); err == nil || err.Error() != "display_unavailable" {
		t.Fatal(err)
	}
	if _, err := OpenCapture(link); err == nil || err.Error() != "display_unavailable" {
		t.Fatal(err)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckCapture(fifo); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	if err := CheckCapture(sock); err == nil || err.Error() != "display_unavailable" {
		t.Fatal(err)
	}
	if _, err := OpenCapture(sock); err == nil || err.Error() != "display_unavailable" {
		t.Fatal(err)
	}
}
