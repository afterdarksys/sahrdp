# Interactive SAH GUI delivery

Direction authorized November 8, 2026: deliver interactive Linux, macOS and
Windows applications and desktops over SAH, including audio and accelerated
video, with OAuth authentication and scoped, renewable grants.

This roadmap supersedes PLAN.md's view-only scope as the product destination.
PROTOCOL.md remains the implemented sahrdp/1 wire contract. The old plan's
unmarked decisions are historical proposals, not evidence of implemented work.

## First usable vertical slice

An operator logs in, selects an allowed Linux application on an enrolled host,
interacts with its window and hears its audio. Revoking its grant terminates
access. No raw command is accepted from the operator. A server allowlist maps
an application name to argv, and authorization binds that selection to the host,
actor and purpose. Local host policy must also permit the operation.

Reuse sahconnect's credential handling and sahx11ws's existing grant-bound
application launcher. Do not treat its opaque xpra stream as sahrdp/1: they are
different protocols. Before implementing an adapter, verify the deployed hub's
GUI routes, ticket exchange, media framing and agent capabilities against its
current contract. The native viewer must advertise only capabilities it supports.

## Delivery milestones and acceptance evidence

1. **Native viewer audio.** Consume validated, granted PCM, expose local mute,
   bound playback memory and close the player on session termination. Tests must
   reject audio without a grant and prove mute clears queued samples. Actual
   audible playback needs a native device test on each supported OS.
2. **Authenticated connection.** Replace the transport-executable form's normal
   workflow with host/application selection and existing OAuth credentials.
   Implement against verified hub routes, including fresh purpose-bound tickets,
   renewal, cancellation and diagnostic errors. No tokens in argv, logs or URLs
   other than the contract's short-lived socket ticket. Prove grant withdrawal
   closes the running application session.
3. **Interactive Linux application.** Version the protocol for keyboard/pointer
   input and enforce its permission at the server, agent and helper. Specify key
   encoding, coordinate mapping, focus loss, stuck-key release and bounded input
   queues. A view-only grant must never inject input. Reuse the existing xpra
   application path only through an explicitly compatible adapter/client.
4. **Audio capture and accelerated video.** Negotiate codecs and actual capture,
   encoder and decoder capabilities. Preserve a software fallback and enforce
   lease ceilings. Add media timestamps, keyframe recovery and synchronization;
   current JPEG/PCM framing does not provide synchronized A/V. Measure capture,
   encode, transit, decode and presentation separately. Initial lab targets to
   validate: 1080p at 30 FPS and p95 input-to-display under 100 ms on a 20 ms RTT
   link, with explicit hardware, workload and bandwidth recorded in results.
5. **Recovery.** Implement the lifecycle and impairment tests in
   SAH_MOBILE_ENHANCEMENTS.md, including fresh authorization on reattachment,
   current-frame refresh, bounded state and no duplicate input. Disconnect today
   still terminates the stream; reconnect is not session resume.
6. **Windows and macOS hosts.** Implement capture/input in the interactive user
   session with platform permissions and real device tests. A client build on
   these OSes does not establish support for hosting a desktop there.

## Current implementation status

- Native JPEG viewer and protocol validation exist.
- This change adds opt-in native PCM playback, a 200 ms local queue and a
  process-wide audio device with separate players per session. Sample-hold
  conversion supports the existing rates; higher-quality resampling remains.
- A browser application launcher now links to the existing authenticated panel
  and its host/app selector without passing credentials. The `gui-panel` branch
  already includes `gui-server` and `gui-agent`; reconciliation between those
  three branches is not needed. Deployment into the target environment remains
  to be verified. Browser xpra and native sahrdp/1 remain distinct paths.
- Native OAuth GUI connection, input, capture integration, accelerated video, media
  synchronization and persistent session recovery are not implemented here.
- No live end-to-end application/audio/revocation acceptance run has passed.

The release gate is the complete first-slice acceptance test above, followed by
recording and revocation failure tests. Unit tests alone do not meet that gate.
