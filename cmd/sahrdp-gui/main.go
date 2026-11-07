//go:build desktop

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/afterdarksys/sahrdp/internal/desktop"
)

func main() {
	fs := flag.NewFlagSet("sahrdp-gui", flag.ContinueOnError)
	stdin := fs.Bool("stdin", false, "read a live sahrdp/1 stream from stdin")
	full := fs.Bool("fullscreen", false, "start fullscreen (Escape exits fullscreen)")
	title := fs.String("title", "SAH Remote Desktop", "window title")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: sahrdp-gui [options] [-- transport-executable arg ...]\nWith no stream source, opens the connection dialog.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		os.Exit(2)
	}
	if *stdin && fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "--stdin and a transport command are mutually exclusive")
		os.Exit(2)
	}
	desktop.Run(desktop.Options{Stdin: *stdin, Fullscreen: *full, Title: *title, Command: fs.Args()})
}
