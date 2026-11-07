//go:build unix

package record

import (
	"errors"
	"os"
	"syscall"
)

func checkDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return errors.New("recording_unavailable")
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return errors.New("recording_unavailable")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != uint32(os.Geteuid()) {
		return errors.New("recording_unavailable")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return errors.New("recording_unavailable")
	}
	return nil
}

func openExclusive(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, errors.New("recording_unavailable")
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		syscall.Close(fd)
		os.Remove(path)
		return nil, errors.New("recording_unavailable")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		syscall.Close(fd)
		os.Remove(path)
		return nil, errors.New("recording_unavailable")
	}
	return os.NewFile(uintptr(fd), path), nil
}

// FreeBytes is the space available on path's filesystem.
func FreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, errors.New("recording_unavailable")
	}
	bsize := int64(st.Bsize)
	if bsize <= 0 {
		return 0, errors.New("recording_unavailable")
	}
	return uint64(st.Bavail) * uint64(bsize), nil
}
