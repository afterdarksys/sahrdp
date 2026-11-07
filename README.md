# SAH Remote Desktop

`sahrdp` provides the sahrdp/1 daemon and stream-export client. `sahrdp-gui`
adds a native desktop window for macOS, Linux, and Windows, using Fyne.
It opens a connection form when launched without arguments, or immediately
opens a stream supplied on the command line.

**Current scope:** live, view-only JPEG tile display, aspect-preserving window
resizing, fullscreen, disconnect and reconnect. Audio frames are validated but
muted. Keyboard/mouse control is not implemented by the existing protocol;
clipboard, drives and printers are not supported. This is not an MS-RDP client.
The SAH display control-plane/agent integration is still pending (see PLAN.md).

## Build and launch

Go 1.26 or newer is required. The GUI also needs a C compiler and platform
graphics development libraries. See [Fyne prerequisites](https://docs.fyne.io/started/).
On macOS, install Xcode Command Line Tools. Linux requires the OpenGL and X11
development packages; Windows requires an appropriate MinGW C compiler.
Build on each target OS, or use Fyne's cross-compilation tooling.

```sh
# Existing daemon/export client, no GUI toolchain required:
go build -o sahrdp ./cmd/sahrdp

# Native GUI (use sahrdp-gui.exe on Windows):
go build -tags desktop -o sahrdp-gui ./cmd/sahrdp-gui
./sahrdp-gui
```

The `desktop` build tag keeps native graphics dependencies out of normal
headless daemon builds and tests. Build the GUI without the `ci` tag to get
an actual desktop window.

## Command-line connections

```sh
# A transport adapter writes a live sahrdp/1 stream on stdout:
./sahrdp-gui --title 'My remote desktop' -- /path/to/display-transport --host my-host

# Or pipe that stream into the viewer:
/path/to/display-transport --host my-host | ./sahrdp-gui --stdin --fullscreen

./sahrdp-gui --help
```

`display-transport` is a placeholder for your SAH adapter, not an included or
currently implemented SAH command. No default SAH subcommand/API is assumed.
The adapter must handle SAH authentication, host resolution, authorization,
tickets and renewal, and output only the binary sahrdp/1 daemon-to-client stream
on stdout. Diagnostic output belongs on stderr. It must not detach from the
viewer; closing the stream/terminating the adapter must release its remote session.
The viewer starts the adapter directly with an argument vector, without a shell,
and closes its pipe and terminates/reaps the adapter on disconnect or window close.
The viewer neither opens a listening port nor dials an RDP port.

In the connection dialog, enter the executable path and arguments as a JSON
array, for example `["--host", "my-host"]`. Commands and credentials are not
saved. Use the adapter's existing credential store rather than putting secrets
in arguments. A stdin connection is consumed once; launch a fresh process to
connect another stdin stream.

F11 or the toolbar toggles fullscreen; Escape leaves fullscreen. All keys remain
local. Remote session close reasons and connection failures appear below the
picture. The last image remains visible after a remote close; Disconnect clears
it. Reconnecting starts a new framebuffer. Reported recording digests are not
cryptographically verified by the GUI; use `sahrdp verify` on the recording.

## Verification

```sh
go test -race ./...
go test -tags desktop,ci ./...   # GUI compilation and headless widget tests
go vet -tags desktop,ci ./...
```

The viewer tests cover tile placement, immutable rendered frames, invalid JPEGs,
JPEG/header dimension mismatch, out-of-bounds tiles, reject/truncated streams,
literal subprocess arguments, and transport termination. Native packaging and
live SAH end-to-end testing must also be performed on each release platform.
