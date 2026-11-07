//go:build !unix

package session

import (
	"errors"
	"os"
)

// CheckCapture is unavailable on this OS.
func CheckCapture(string) error { return errors.New("display_unavailable") }

// OpenCapture is unavailable on this OS.
func OpenCapture(string) (*os.File, error) {
	return nil, errors.New("display_unavailable")
}
