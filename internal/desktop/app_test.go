//go:build desktop

package desktop

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestConnectionFormAndFullscreen(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := newWindow(a, Options{Title: "Test desktop"})
	defer w.Close()
	var entries []*widget.Entry
	buttons := map[string]*widget.Button{}
	var labels []*widget.Label
	var walk func(fyne.CanvasObject)
	walk = func(obj fyne.CanvasObject) {
		switch o := obj.(type) {
		case *fyne.Container:
			for _, child := range o.Objects {
				walk(child)
			}
		case *widget.Form:
			for _, item := range o.Items {
				walk(item.Widget)
			}
		case *widget.Entry:
			entries = append(entries, o)
		case *widget.Button:
			buttons[o.Text] = o
		case *widget.Label:
			labels = append(labels, o)
		}
	}
	walk(w.Content())
	if len(entries) != 2 || buttons["Connect"] == nil || buttons["Disconnect"] == nil {
		t.Fatal("missing connection controls")
	}
	if !buttons["Disconnect"].Disabled() {
		t.Fatal("disconnect enabled without a session")
	}
	test.Tap(buttons["Connect"])
	hasLabel := func(text string) bool {
		for _, l := range labels {
			if strings.Contains(l.Text, text) {
				return true
			}
		}
		return false
	}
	if !hasLabel("Choose a transport") {
		t.Fatal("missing executable validation")
	}
	entries[0].SetText("never-execute-this")
	entries[1].SetText("not json")
	test.Tap(buttons["Connect"])
	if !hasLabel("Arguments must be") || buttons["Connect"].Disabled() {
		t.Fatal("invalid arguments did not stay in connection form")
	}
	test.Tap(buttons["Fullscreen (F11)"])
	if !w.FullScreen() {
		t.Fatal("fullscreen did not activate")
	}
	w.Canvas().OnTypedKey()(&fyne.KeyEvent{Name: fyne.KeyEscape})
	if w.FullScreen() {
		t.Fatal("Escape did not exit fullscreen")
	}
}
