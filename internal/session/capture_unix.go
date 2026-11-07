//go:build unix

package session

import (
	"errors"
	"os"
	"syscall"
)

// CheckCapture accepts a regular file or a FIFO, mode 0600, owned by the
// effective uid. A symlink or a socket is display_unavailable.
func CheckCapture(path string) error {
	if path == "" {
		return errors.New("display_unavailable")
	}
	st, err := os.Lstat(path)
	if err != nil || !captureInfo(st) {
		return errors.New("display_unavailable")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != uint32(os.Geteuid()) {
		return errors.New("display_unavailable")
	}
	return nil
}

func captureInfo(st os.FileInfo) bool {
	if st == nil || st.Mode()&os.ModeSymlink != 0 || st.Mode()&os.ModeSocket != 0 {
		return false
	}
	reg := st.Mode().IsRegular()
	fifo := st.Mode()&os.ModeNamedPipe != 0
	if !reg && !fifo {
		return false
	}
	return st.Mode().Perm() == 0o600
}

// OpenCapture opens path read-only after CheckCapture and checks the fd again.
func OpenCapture(path string) (*os.File, error) {
	if err := CheckCapture(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("display_unavailable")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, errors.New("display_unavailable")
	}
	kind := st.Mode & syscall.S_IFMT
	if (kind != syscall.S_IFREG && kind != syscall.S_IFIFO) || kind == syscall.S_IFSOCK ||
		os.FileMode(st.Mode&0o777) != 0o600 || st.Uid != uint32(os.Geteuid()) {
		_ = syscall.Close(fd)
		return nil, errors.New("display_unavailable")
	}
	return os.NewFile(uintptr(fd), "capture"), nil
}
