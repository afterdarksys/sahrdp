//go:build desktop

package desktop

import (
	"errors"
	"net/url"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestApplicationLauncherValidatesBeforeOpening(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	var opened []*url.URL
	fail := false
	content := applicationLauncher(func(u *url.URL) error {
		opened = append(opened, u)
		if fail {
			return errors.New("sensitive OS diagnostic")
		}
		return nil
	}).(*fyne.Container)
	form := content.Objects[1].(*widget.Form)
	origin := form.Items[0].Widget.(*widget.Entry)
	host := form.Items[1].Widget.(*widget.Entry)
	button := content.Objects[2].(*widget.Button)
	status := content.Objects[3].(*widget.Label)
	test.Tap(button)
	if len(opened) != 0 || status.Text == "" {
		t.Fatal("empty origin opened")
	}
	origin.SetText("https://panel.example?ticket=secret")
	test.Tap(button)
	if len(opened) != 0 {
		t.Fatal("secret-bearing URL opened")
	}
	origin.SetText("https://panel.example")
	host.SetText("host-1")
	test.Tap(button)
	if len(opened) != 1 || opened[0].String() != "https://panel.example/panel/gui/host-1" {
		t.Fatal(opened)
	}
	fail = true
	test.Tap(button)
	if status.Text != "Could not open the browser. Open the panel address manually." {
		t.Fatal(status.Text)
	}
}
