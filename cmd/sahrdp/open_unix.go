//go:build unix

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func readKey(path string) ([]byte, error) {
	b, err := readLimited(path, true)
	if err != nil {
		return nil, errors.New("bad_key")
	}
	if len(b) == 32 {
		return b, nil
	}
	if len(b) == 65 && b[64] == '\n' {
		b = b[:64]
	}
	if len(b) != 64 {
		return nil, errors.New("bad_key")
	}
	out := make([]byte, 32)
	if _, err := hex.Decode(out, b); err != nil {
		return nil, errors.New("bad_key")
	}
	return out, nil
}

func readPub(path string) (ed25519.PublicKey, error) {
	b, err := readLimited(path, false)
	if err != nil {
		return nil, errors.New("malformed")
	}
	if len(b) == 32 {
		return ed25519.PublicKey(append([]byte(nil), b...)), nil
	}
	if len(b) != 64 {
		return nil, errors.New("malformed")
	}
	out := make([]byte, 32)
	if _, err := hex.Decode(out, b); err != nil {
		return nil, errors.New("malformed")
	}
	return ed25519.PublicKey(out), nil
}

func readLimited(path string, strict bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("bad")
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return nil, errors.New("bad")
	}
	if st.Size() < 32 || st.Size() > 128 {
		return nil, errors.New("bad")
	}
	if strict {
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || st.Mode().Perm() != 0o600 || sys.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("bad")
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("bad")
	}
	var fst syscall.Stat_t
	if err := syscall.Fstat(fd, &fst); err != nil || fst.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = syscall.Close(fd)
		return nil, errors.New("bad")
	}
	if strict && (os.FileMode(fst.Mode&0o777) != 0o600 || fst.Uid != uint32(os.Geteuid())) {
		_ = syscall.Close(fd)
		return nil, errors.New("bad")
	}
	f := os.NewFile(uintptr(fd), "key")
	b, err := io.ReadAll(io.LimitReader(f, 129))
	cerr := f.Close()
	if err != nil || cerr != nil || len(b) == 0 || len(b) > 128 {
		return nil, errors.New("bad")
	}
	return b, nil
}

func prepareDir(path string) error {
	if path == "" {
		return errors.New("internal")
	}
	st, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.New("internal")
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return errors.New("internal")
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return errors.New("internal")
		}
		st, err = os.Lstat(path)
		if err != nil {
			return errors.New("internal")
		}
	}
	return dirOK(st)
}

func dirOK(st os.FileInfo) error {
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return errors.New("internal")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != uint32(os.Geteuid()) {
		return errors.New("internal")
	}
	return nil
}

func writeNew(dir, name string, data []byte) error {
	f, err := createPrivate(dir, name)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return errors.New("internal")
	}
	return nil
}

func createPrivate(dir, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return nil, errors.New("internal")
	}
	path := filepath.Join(dir, name)
	if filepath.Base(path) != name {
		return nil, errors.New("internal")
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, errors.New("internal")
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		_ = syscall.Close(fd)
		_ = os.Remove(path)
		return nil, errors.New("internal")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || os.FileMode(st.Mode&0o777) != 0o600 {
		_ = syscall.Close(fd)
		_ = os.Remove(path)
		return nil, errors.New("internal")
	}
	return os.NewFile(uintptr(fd), "out"), nil
}
