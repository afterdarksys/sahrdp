//go:build desktop

// Package desktop contains the native GUI. All widget updates run on Fyne's
// event goroutine; stream parsing and JPEG decoding run in the background.
package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/afterdarksys/sahrdp/internal/viewer"
)

type Options struct {
	Stdin, Fullscreen bool
	Title             string
	Command           []string
}

func Run(opts Options) {
	a := app.NewWithID("com.afterdarksys.sahrdp")
	newWindow(a, opts).ShowAndRun()
}

func newWindow(a fyne.App, opts Options) fyne.Window {
	w := a.NewWindow(opts.Title)
	w.Resize(fyne.NewSize(1024, 720))
	w.SetFullScreen(opts.Fullscreen)
	w.Canvas().SetOnTypedKey(func(k *fyne.KeyEvent) {
		if k.Name == fyne.KeyEscape {
			w.SetFullScreen(false)
		}
		if k.Name == fyne.KeyF11 {
			w.SetFullScreen(!w.FullScreen())
		}
	})
	status := widget.NewLabel("Ready · View only · Audio muted")
	status.Wrapping = fyne.TextWrapWord
	picture := canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 1, 1)))
	picture.FillMode = canvas.ImageFillContain
	viewport := container.NewStack(picture)
	executable := widget.NewEntry()
	executable.SetPlaceHolder("Path to SAH display transport")
	arguments := widget.NewEntry()
	arguments.SetText("[]")
	arguments.SetPlaceHolder(`["argument", "value"]`)
	if len(opts.Command) > 0 {
		executable.SetText(opts.Command[0])
		b, _ := json.Marshal(opts.Command[1:])
		arguments.SetText(string(b))
	}
	info := widget.NewLabel("Open a SAH display stream using a transport executable.\nThe current protocol supports viewing only; remote input is unavailable.")
	info.Wrapping = fyne.TextWrapWord
	form := container.NewVBox(widget.NewLabelWithStyle("SAH Remote Desktop", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), info,
		widget.NewForm(widget.NewFormItem("Transport", executable), widget.NewFormItem("Arguments (JSON)", arguments)))
	var cancel context.CancelFunc
	var generation uint64
	var connect, disconnect *widget.Button
	stop := func() {
		generation++
		if cancel != nil {
			cancel()
			cancel = nil
		}
	}
	connect = widget.NewButton("Connect", nil)
	disconnect = widget.NewButton("Disconnect", func() {
		stop()
		status.SetText("Disconnected · View only · Audio muted")
		picture.Image = image.NewRGBA(image.Rect(0, 0, 1, 1))
		picture.Refresh()
		form.Show()
		connect.Enable()
		disconnect.Disable()
	})
	disconnect.Disable()
	start := func(argv []string, stdin bool) {
		stop()
		id := generation
		ctx, halt := context.WithCancel(context.Background())
		cancel = halt
		connect.Disable()
		disconnect.Enable()
		form.Hide()
		picture.Image = image.NewRGBA(image.Rect(0, 0, 1, 1))
		picture.Refresh()
		status.SetText("Connecting… · View only · Audio muted")
		go func() {
			var r io.ReadCloser
			var err error
			if stdin {
				r = os.Stdin
			} else {
				r, err = viewer.StartTransport(ctx, argv, os.Stderr)
			}
			if err == nil {
				// Closing the reader unblocks parsing, including a silent transport.
				finished := make(chan struct{})
				go func() {
					select {
					case <-ctx.Done():
						_ = r.Close()
					case <-finished:
					}
				}()
				err = viewer.Read(ctx, r, func(u viewer.Update) {
					// Backpressure bounds queued images even if rendering is slow.
					fyne.DoAndWait(func() {
						if id != generation || ctx.Err() != nil {
							return
						}
						if u.Image != nil {
							picture.Image = u.Image
							picture.Refresh()
						}
						if u.Status != nil {
							status.SetText(fmt.Sprintf("Connected · %s · %d × %d · View only · Audio muted", u.Status.Actor, u.Status.Width, u.Status.Height))
						}
						if u.Close != nil {
							status.SetText("Session ended: " + u.Close.Reason + " · View only")
						}
					})
				})
				close(finished)
				_ = r.Close()
			}
			fyne.Do(func() {
				if id != generation || ctx.Err() != nil {
					return
				}
				if err != nil {
					status.SetText("Connection failed: " + err.Error())
				}
				disconnect.Disable()
				form.Show()
				if !stdin {
					connect.Enable()
				}
			})
		}()
	}
	connect.OnTapped = func() {
		var args []string
		if executable.Text == "" {
			status.SetText("Choose a transport executable.")
			return
		}
		if err := json.Unmarshal([]byte(arguments.Text), &args); err != nil {
			status.SetText(`Arguments must be a JSON array, for example ["--host", "my-host"].`)
			return
		}
		start(append([]string{executable.Text}, args...), false)
	}
	fullscreen := widget.NewButton("Fullscreen (F11)", func() { w.SetFullScreen(!w.FullScreen()) })
	w.SetContent(container.NewBorder(container.NewVBox(form, container.NewHBox(connect, disconnect, fullscreen)), status, nil, nil, viewport))
	w.SetOnClosed(stop)
	if opts.Stdin || len(opts.Command) > 0 {
		w.Show()
		start(opts.Command, opts.Stdin)
	}
	return w
}
