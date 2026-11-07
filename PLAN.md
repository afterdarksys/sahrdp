# Display channel plan

Status: the control plane is not wired, 2026-11-07. This directory has the sahrdp/1 host daemon and operator client. Their local contract is PROTOCOL.md. Audio there is a leased bit. Clipboard, printers, and drive redirection stay out. systemapi.io is unchanged. `~/development/systemapi.io/docs/sah-suite.md` is the authority on what exists today. This file stays the proposal for the GUI pillar. It becomes the brief for a protocol contract only after the decisions in §2 are marked.

Mark each row in §2 with `OK` or a replacement. An unmarked row is not approved. When the marks are in, the next session writes `systemapi.io/docs/sah-display-protocol.md` and wires the control plane from that contract. The helper in this directory is not that wiring.

## 1. What approval means

Approval means a new `display` channel on the systemapi agent. The operator sees a Linux virtual desktop in the existing dashboard. The host opens no listening port. The agent execs a separate `sahrdp` helper as the seat user, under a purpose-scoped ticket and a signed lease. The helper records the frames on the host and stops if it cannot.

`sahlink rdp` stays the unrecorded TCP forward to a remote desktop server that is already listening. This plan does not change it. A Guacamole-style gateway stays the unimplemented note in `sahlink/docs/recorded-rdp-gateway.md`. Build that gateway only for a Windows host that already runs Remote Desktop and has no agent. That case is not scheduled here.

## 2. Decisions to mark

| ID | Recommendation | Why | Mark |
|---|---|---|---|
| D1 | The channel is `display`. Purposes are `display:view` and `display:input`. | Keeps pixels off `tcp:open` and off the PTY socket. A port grant must not show the screen, and a video stream must not take a PTY slot. | |
| D2 | Phase 1 is view only. Input is phase 2, its own change. | Capture, recording, and the deny path can be reviewed before a grant can type. | |
| D3 | Phase 1 seat is `virtual` on Linux: Xvfb, a small window manager, capture of that display only. | The enrolled fleet has no monitor. Xvfb runs in CI without a GPU. A console ticket on a headless host returns `display_unavailable` and does not start Xvfb. | |
| D4 | The v1 client is one view in the systemapi dashboard, next to the terminal. | The operator's machine is already cross-platform in the browser. `mstsc` and `xfreerdp` stay on the `sahlink rdp` path. | |
| D5 | Recording is mandatory. A policy that asks for an unrecorded display is refused. The session ends with `recording_unavailable` when the file cannot be written. | Same fail-closed rule as the PTY. The helper owns the pixels, so the "ciphertext, do not record" reason in the TCP contract does not apply. | |
| D6 | Recording uses the PTY rules: HMAC-SHA256 chain, root-owned `0700` directory, refuse below 1 GiB free, stop at a 1 GiB file, digest in the audit row, verify on the host. Frames live under `--display-record-dir`, default `/var/lib/systemapi/recordings/display`. | One retention story. A new directory so `verify-recording` for PTY lines is not asked to parse video. | |
| D7 | Server policy and the agent's `--display-allow` both have to allow the session. Either one empty means deny. | Same dual control as `tcp_policy` and `--tcp-allow`. A server grant cannot turn capture on by itself. | |
| D8 | A live session paints a mark naming the actor into the framebuffer, including the recording. | The person who later watches the recording can see that the session was a SAH view, and a console user can see it on the glass. | |
| D9 | Lease TTL 60 s, renew every 30 s, each renewal re-checks actor, scope, and policy. Idle 900 s. Max duration default 3600 s, ceiling 28800 s. | A forgotten view is a standing camera. 1 h is the default; an admin can raise it up to the PTY maximum and no further. | |
| D10 | Lease caps the picture: one output, `max_fps` 5, `max_width` 1280. Policy may lower these. It cannot raise them past the server ceiling. | Bounds bandwidth and the size of the recording. | |
| D11 | v1 frames are JPEG tiles. H264 waits until a real session shows JPEG as the limit. | Tiles are debuggable and easy to record. A codec change should not be part of the first grant. | |
| D12 | Clipboard, file copy, printers, and drive redirection are out. Audio is a leased bit on the helper (`audio` 0 or 1) and only when `--allow` includes `audio`. Drive stays on `sahsync`. Audio in the helper is not a control-plane feature until §2 is marked. | Clipboard is how secrets leave a desktop. The file channel already has a policy. | |
| D13 | `sahrdp` is module `github.com/afterdarksys/sahrdp`. The agent execs it and does not import it. | Matches the sash rule in `sah-suite.md`: the agent does not link the session program. | |
| D14 | Console attach is phase 3, one OS per change: Linux X11, then Linux Wayland, then Windows, then macOS. | Each capture backend has its own consent bug. They do not share a phase. | |
| D15 | Windows capture runs in the interactive user session, never in session 0. macOS capture needs Screen Recording TCC in a GUI launch agent; the server grant does not replace it. Wayland console capture uses the RemoteDesktop portal. | A service grab of the secure desktop looks like success and is black. Root cannot click a macOS or portal prompt. | |

## 3. Where things stand

The suite already has a recorded shell (`sahconnect`, purpose `terminal:open`), a file channel (`sahsync`), a TCP forward (`sahlink`, purpose `tcp:open`), and a mesh of those TCP streams (`sahmesh`). Device login is `controlplane/oauth.js`. Dashboard login is Authentik. Channel policy is deny by default.

`sahlink rdp HOST` listens on `127.0.0.1` and the agent dials port 3389. The TCP contract (`docs/sah-tcp-protocol.md` §9) does not record those bytes, because RDP between the operator's client and the host is ciphertext. `sahlink/docs/recorded-rdp-gateway.md` says a later gateway could terminate RDP. It also says that gateway is a new trust boundary, must not hold the agent's credential, and must not put Windows passwords on a command line.

The agent advertises `pty`, `file`, `tcp`, `xfer`, and the sys capabilities. The Windows family is deferred: service, package, config, and tweak fail closed. Darwin has a launchd backend and fails closed on unit overrides. The first enrolled host is miniapps1, Debian 12, with no graphical seat.

## 4. Channel sketch

This sketch is what phase 1 must satisfy. The contract file, written after §2 is marked, is the authority the code is checked against. Where the contract and this sketch disagree, the contract wins.

Auth matches the PTY and TCP channels.

1. `GET /api/v1/hosts/resolve?name=`
2. `POST /api/v1/ws-ticket` with `{"host_id","purpose":"display:view","target":{"seat":"virtual","output":"0"}}`. The ticket is bound to host, purpose, and target. It is single-use and valid for 60 s. The credential is a header. The ticket is the only query-string secret.
3. `wss://<systemapi>/api/v1/systems/display/<host_id>?ticket=&purpose=display:view`

The server refuses the ticket when the actor lacks `display:view`, the host policy does not allow that seat, or the target is not exactly `seat=virtual` and `output=0` in phase 1. Any other seat or output is `bad_target` until phase 3.

The signed lease action is `display`. The payload names session id, deadline, phase (`start` or `renew`), seat, output, `max_fps`, `max_width`, and `max_bytes`. The helper captures only the seat and output in the lease.

Frames, phase 1:

| Direction | Frame | Meaning |
|---|---|---|
| server → client | `display_status` `connecting`, then `connected` with `session_id` and geometry | No JPEG is sent before `connected`, and `connected` is not sent before the `display_start` audit row. |
| server → client | binary, at most 64 KiB | One JPEG tile: 8-byte header (`x`, `y`, `w`, `h` as uint16) then the JPEG. A larger tile is split only on JPEG boundaries; a single tile over 64 KiB is scaled down. |
| client → server | none that change the desktop | View has no input frames. An input frame on a view socket is `protocol_error` and closes the session. |
| server → client | `display_close` with reason, byte counts, digest | Then close code 1000. |

Error codes follow the TCP set where the meaning is the same (`ticket_invalid`, `scope_denied`, `agent_offline`, `lease_required`, `cap_reached`, `protocol_error`, `internal`), plus `display_unavailable` (no virtual seat could be started), `agent_unsupported` (helper missing or this OS), and `recording_unavailable`.

Close reasons: `closed`, `idle_timeout`, `byte_cap`, `max_duration`, `recording_size_limit`, `agent_disconnected`, `stopped`. `stopped` covers an admin kill and a grant withdrawn at renewal.

Caps, enforced on the server and the agent: 1 live display per actor per host in phase 1, and 2 display helpers per agent, so a view cannot exhaust the host. These counters are not the PTY slot counters.

Audit rows, hashed into the existing chain: `ticket_issued` (actor, host, purpose, target), `display_start` (session id, seat, output, geometry, recording path) before the first tile, `display_end` (reason, duration, bytes, digest). A failed `display_start` write ends the session with `internal` and no tile goes out.

The helper is killed, and its Xvfb process group with it, when the lease lapses, the client disconnects, or a stop arrives. A restart of the agent does not resume the session.

## 5. Virtual seat

Phase 1 starts the seat only after a valid view lease.

1. The helper, running as `pty_user`, starts Xvfb on a display number it chooses from the free range above 100. It does not open `:0`.
2. It starts a window manager on that display. The plan's default is `openbox`.
3. It maps a mark window, always on top, that reads `SAH view` and the actor. The mark is inside the captured pixels.
4. It captures with `XShmGetImage` and damage events, encodes changed tiles as JPEG, and writes each tile to the recording before sending it.
5. On exit it kills the process group it started. A leftover Xvfb from this helper is a failed test.

`pty_user` unset is `pty_user_unset`, the same code as the terminal. The helper does not run the virtual seat as root.

Phase 2 adds `display:input` on this same seat. Pointer and key frames are accepted only when the ticket purpose is `display:input` and `--display-allow` contains `input`. A view grant cannot be upgraded on a live socket. Input is delivered with `XTest` to that X server only. Phase 2's done test is: a view-only ticket that sends a key is closed with `protocol_error`, and an input ticket can launch a program the window manager shows.

## 6. Later capture backends

Each row is a later change. None of them is phase 1. The protocol target grows a new `seat` value only in the change that implements it.

| When | Seat | Capture | Input | Local consent the server cannot skip |
|---|---|---|---|---|
| Phase 3a | Linux console, X11 | `XShm` on the existing display | `XTest` as the seat user | The mark window. The helper does not run as root. |
| Phase 3b | Linux console, Wayland | `xdg-desktop-portal` RemoteDesktop and PipeWire | the same portal session | The portal dialog. A root grab of the compositor socket is a bug, not a fallback. No portal means `display_unavailable`. |
| Phase 3c | Windows console | `Windows.Graphics.Capture` in the interactive session | `SendInput` from that user helper | The capture border stays on. Session 0 is `display_unavailable`. Blocked until the agent has a real Windows family; today that family fails closed. |
| Phase 3d | macOS console | ScreenCaptureKit in a GUI launch agent | posted events | Screen Recording TCC, and Accessibility for input. A launch daemon cannot hold them. Fleet Macs get them from an MDM PPPC profile. |

A virtual Wayland seat may replace Xvfb later behind `seat=virtual`. That replacement is allowed only when the phase 1 tests still pass. It is not a second seat name.

## 7. Build order

Phase 1 is the only work this approval starts.

1. Add `docs/sah-display-protocol.md` on systemapi.io, matching §4 and the marked rows in §2. Done when the file is the contract a test can cite.
2. Add the `sahrdp` helper: virtual seat, JPEG tiles, HMAC recording, mark window, process-group cleanup. Done when a local test starts Xvfb, writes a recording, and leaves no Xvfb behind.
3. Teach the agent to advertise `display` only when the helper is installed and Xvfb can be exec'd, to spawn the helper under the lease, and to refuse otherwise with `agent_unsupported`. Done when a host without the helper does not report the capability.
4. Add the ticket, lease, policy, audit rows, and WebSocket on the control plane. Default policy allows nothing. Done when a missing policy, a missing scope, and a withdrawn grant each fail closed in tests.
5. Add the dashboard view. Done when a browser session against a test host shows the mark window and the recording's digest matches the audit row.
6. Add the suite contract row for the new call in the same change that wires it. Done when `sah-suite.md` names the purpose, the helper, and the recording rule.

Phase 2 starts only after phase 1 is accepted in use. Phase 3 starts only after phase 2 is accepted. H264 starts only after a phase 1 session is limited by JPEG size or CPU.

## 8. Files

| Piece | Home | Phase |
|---|---|---|
| This plan | `sahrdp/PLAN.md` | now |
| Protocol contract | `systemapi.io/docs/sah-display-protocol.md` | 1 |
| Helper | `sahrdp`, module `github.com/afterdarksys/sahrdp` | 1 |
| Agent spawn and capability | `systemapi.io/systemapi-agent` | 1 |
| Ticket, lease, policy, audit, socket | `systemapi.io/controlplane` | 1 |
| Dashboard view | `systemapi.io/frontend` | 1 |
| Suite row | `systemapi.io/docs/sah-suite.md` | 1, in the change that wires the call |
| Input frames | helper, agent, control plane, dashboard | 2 |
| Console backends | helper, one OS per change | 3 |

`sahlink` does not grow a display subcommand. A CLI that saves tiles can wait; the dashboard is the phase 1 client.

## 9. Threats the phase 1 tests have to show

The helper must refuse these. A test that skips one of them is not phase 1.

| Threat | Required behavior |
|---|---|
| Server grant, agent flag empty | Helper never starts. `target_denied_agent`. |
| Agent flag set, server policy empty | Ticket refused. `target_denied`. |
| View socket sends a key or pointer | `protocol_error`. Desktop unchanged. |
| Recorder cannot create the file, or free space is under 1 GiB | `recording_unavailable` before any tile. |
| Recorder falls behind or the file hits 1 GiB | Session ends. No tile is dropped to keep the session alive. |
| Client asks for `:0` or a console seat | `bad_target` in phase 1. Xvfb is not started. |
| Lease renewal fails the grant check | `stopped`. Helper and Xvfb are dead. |
| Helper dies | No leftover Xvfb. Audit `display_end` still written. |
| Tile claims a geometry outside the leased width | Agent drops the session as `protocol_error`. |
| Actor over the per-host display cap | `cap_reached`. Existing PTY sessions stay up. |

## 10. Not in this plan

- Changing `sahlink rdp` or recording TCP byte streams.
- Building the RDP gateway described in `sahlink/docs/recorded-rdp-gateway.md`.
- Clipboard, printers, and drive redirection. Audio in the helper is a leased bit (`audio` 0 or 1) and is not a control-plane feature until §2 is marked.
- A WebRTC peer path. Media hops through the control plane so a withdrawn grant stops the relay at the next renewal.
- Opening 3389, 5900, or any other port on the host.
- Starting a virtual seat because a console capture failed.
- Windows or macOS in phase 1. Both stay fail-closed until their own phase 3 change.

## 11. Next

The helper in this directory is the client and the daemon for sahrdp/1. It does not start a virtual seat and it does not listen. Until the §2 marks are in, do not add `systemapi.io/docs/sah-display-protocol.md`, and do not wire the agent, the control plane, or the dashboard. Do not mark §2 rows OK.
