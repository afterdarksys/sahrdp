//go:build desktop

package desktop

import (
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/afterdarksys/sahrdp/internal/launch"
)

func applicationLauncher(open func(*url.URL) error) fyne.CanvasObject {
	origin := widget.NewEntry()
	origin.SetPlaceHolder("https://landing.sah.sh")
	host := widget.NewEntry()
	host.SetPlaceHolder("Optional — leave blank to select a host")
	message := widget.NewLabel("Open an interactive application in your browser. Sign in to the SAH panel, then choose a permitted host and app. Browser sessions are separate from the native display stream.")
	message.Wrapping = fyne.TextWrapWord
	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	button := widget.NewButton("Open SAH panel", func() {
		u, err := launch.PanelURL(origin.Text, host.Text)
		if err != nil {
			status.SetText(err.Error())
			return
		}
		if err = open(u); err != nil {
			status.SetText("Could not open the browser. Open the panel address manually.")
			return
		}
		status.SetText("Opened in browser. If login returns to the fleet, select the host there. Close the browser application view to end its session.")
	})
	return container.NewVBox(message, widget.NewForm(widget.NewFormItem("Panel address", origin), widget.NewFormItem("Host ID", host)), button, status)
}

func showApplications(a fyne.App, w fyne.Window) {
	d := dialog.NewCustom("SAH applications · Browser", "Close", applicationLauncher(a.OpenURL), w)
	d.Resize(fyne.NewSize(600, 330))
	d.Show()
}
