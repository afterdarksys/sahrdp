//go:build !unix

package main

import (
	"crypto/ed25519"
	"errors"
	"os"
)

func readKey(string) ([]byte, error) { return nil, errors.New("bad_key") }

func readPub(string) (ed25519.PublicKey, error) {
	return nil, errors.New("malformed")
}

func prepareDir(string) error { return errors.New("internal") }

func writeNew(string, string, []byte) error { return errors.New("internal") }

func createPrivate(string, string) (*os.File, error) {
	return nil, errors.New("internal")
}
