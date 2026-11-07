//go:build !unix

package record

import (
	"errors"
	"os"
)

func checkDir(string) error { return errors.New("recording_unavailable") }

func openExclusive(string) (*os.File, error) {
	return nil, errors.New("recording_unavailable")
}

// FreeBytes is unavailable on this OS.
func FreeBytes(string) (uint64, error) { return 0, errors.New("recording_unavailable") }
