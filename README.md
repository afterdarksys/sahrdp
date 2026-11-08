# SAH Remote Desktop

`sahrdp` provides the sahrdp/1 daemon and stream-export client. `sahrdp-gui`
adds a native desktop window for macOS, Linux, and Windows, using Fyne.
It opens a connection form when launched without arguments, or immediately
opens a stream supplied on the command line.

**Current scope:** live, view-only JPEG tile display, aspect-preserving window
resizing, fullscreen, disconnect and reconnect. Granted audio can be played using the “Play session audio” checkbox; playback
starts muted. Keyboard/mouse control is not implemented by the existing protocol;
clipboard, drives and printers are not supported. This is not an MS-RDP client.
The SAH display control-plane/agent integration is still pending (see PLAN.md).

## Build and launch

Go 1.26 or newer is required. The GUI also needs a C compiler and platform
graphics development libraries. See [Fyne prerequisites](https://docs.fyne.io/started/).
On macOS, install Xcode Command Line Tools. Linux requires the OpenGL and X11
development packages and ALSA development headers for audio; Windows requires an appropriate MinGW C compiler.
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

## Interactive GUI roadmap and audio

[GUI_ROADMAP.md](GUI_ROADMAP.md) tracks the interactive application milestone
and the remaining hub, agent, input and accelerated media work.

Audio playback is local and opt-in; it cannot enable audio on a host whose
lease does not grant it. The viewer converts supported PCM rates to 48 kHz
stereo using sample-hold conversion. Its local queue retains at most 200 ms,
discarding oldest playback samples on overflow and supplying silence on
underflow. This does not modify host recording. Mute clears the local queue;
a small amount already submitted to the device may finish playing. Each
session closes its player when it ends. Device initialization failure leaves
video usable and reports audio unavailable.

Playback uses [Oto](https://github.com/ebitengine/oto). Audio/video timestamp
synchronization and high-quality resampling are still pending. Native audible
playback has not yet been verified on all three supported client platforms.

## Interactive applications through the SAH panel

The **SAH applications…** button opens a browser launcher. Enter your panel's
HTTPS origin (for example `https://landing.sah.sh`) and optionally a host ID.
Leaving the host blank opens the fleet selector. The browser handles OAuth
login, permitted app selection, and the `gui:open` ticket. No credential or
ticket is passed through the browser launch URL. HTTP is accepted only on
loopback for local development.

This uses the existing `/panel/gui/:hostId` route on SystemAPI's `gui-panel`
branch, which already incorporates `gui-server` and `gui-agent`. The server
must have that integration deployed, its separate GUI origin configured, and
an enrolled Linux host with the sahx11ws helper, xpra, user mapping, and app
policy. Opening a URL does not verify those deployment prerequisites. If login
returns to the fleet instead of the requested host, select the host there.

Applications render in the browser's xpra client, separately from the native
sahrdp/1 display stream. Closing the launcher does not end a browser session;
close the application view in the browser. The existing xpra helper disables
audio, so the native PCM playback feature does not add audio to browser apps.
