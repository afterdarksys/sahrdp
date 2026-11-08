# SAH mobile network enhancements

Status: proposal, 2026-11-07. Deferred until the current batches are complete.
This document records future work; it does not authorize implementation or
change existing session, lease, recording, or protocol behavior.

## Objective

Make cellular network disruptions feel like a brief pause rather than a lost
terminal or desktop session. Address intermittent connectivity, packet loss,
variable latency and bandwidth, NAT rebinding, and network changes such as
Wi-Fi to 4G/5G.

The central design choice is to separate the lifetime of a remote session from
the lifetime of the connection carrying it. Transport improvements complement
session recovery; they cannot replace it.

## Current foundation

The SAH suite contract in `../systemapi.io/docs/sah-suite.md` describes agent
PTY sessions, TCP forwarding, file operations, and mesh streams through the
control plane. Operator channels currently use WebSockets. Host agents connect
outbound, and terminal recording takes place on the host.

```text
Operator laptop ── cellular connection ── SAH hub ── outbound agent ── session
```

When only the operator connection fails, the hub and agent may still be able
to communicate. This creates an opportunity to preserve the remote session
while the operator reconnects.

SAHRDP currently has a native viewer and a validated, view-only sahrdp/1 stream.
Its display control-plane integration is unfinished. The current protocol
rejects remote input, and the GUI validates but mutes audio. Mobile recovery
must not be represented as an existing capability.

## Options

| Approach | Helps with | Limits |
| --- | --- | --- |
| Heartbeats and appropriate timeouts | Idle connection expiry and detection of broken connections | Does not restore lost sessions or enable roaming |
| Persistent sessions and secure reattachment | Brief outages, laptop sleep, reconnecting on another network | Requires explicit session ownership, retention, and resume semantics |
| QUIC with connection migration | Address changes and NAT rebinding | Requires migration support and a fallback where UDP is unavailable |
| Mosh-style terminal synchronization | Responsive terminals over lossy, high-latency links | Terminal-specific; not a general desktop or file transport |
| Adaptive desktop delivery | Maintaining a useful picture as bandwidth changes | Requires explicit frame recovery and delivery semantics |

## First priority: persistent sessions and secure reattachment

Build recovery over the existing WebSocket transport first. This delivers value
without requiring a transport replacement and remains useful with QUIC later.

Example flow:

1. The operator starts a command and temporarily loses cellular connectivity.
2. The client displays `Connection lost — reconnecting` and retries with
   bounded backoff and jitter.
3. The agent preserves the same PTY and process for a bounded grace period.
4. Host recording continues and authorization remains enforced.
5. The client reconnects, authenticates, and obtains a fresh authorization to
   attach to the existing session.
6. Output resumes from an acknowledged position, or the terminal receives a
   consistent current-state snapshot.

A two-minute operator-disconnection grace period is a possible starting point,
not an approved default. Retention must be bounded by policy, resource limits,
the session deadline, and valid authorization.

### Authorization and lifecycle

Distinguish operator connection loss from loss of the agent's authorization:

- Operator disconnected, agent and hub connected: an explicitly permitted
  grace period may preserve the session while leases continue to be checked.
- Agent cannot renew its lease: existing lease-expiry enforcement still applies.
- Scope or policy revoked, administrator stops the session, recording fails,
  or the session deadline is reached: preservation must not bypass termination.

A session identifier alone must not authorize attachment. Reattachment must
check the actor, tenant, host, purpose, current policy, and session ownership.
Use a fresh, short-lived attachment authorization rather than reusing a spent
WebSocket ticket. Define whether concurrent viewers are permitted and which
attachment, if any, owns input. A replaced connection must lose input authority.

Audit disconnect, reattach, expiry, and termination events while retaining one
logical session identity. Grace periods and buffers must count against session
and resource limits.

### Output and input recovery

Track output positions and retain a bounded replay buffer. Define what happens
when the client falls behind that buffer: restore a consistent terminal state
or explicitly report that replay is unavailable. Do not silently omit arbitrary
PTY bytes; terminal escape sequences and application state can span chunks.

Use sequence numbers, acknowledgments, and deduplication to prevent transport
retries from applying input twice within a surviving session. Reconnection must
not accidentally repeat an Enter key or a command. Acknowledgment semantics
must distinguish receipt of input from completion of a command.

If an agent or session process crashes, command outcome may be unknown. Do not
claim exactly-once execution across crashes or automatically rerun a command
whose outcome cannot be established. Likewise, arbitrary forwarded TCP sessions
cannot be resumed merely by opening a replacement socket; each channel needs
its own recovery contract.

Avoid silently accumulating unlimited offline input. The UI should clearly
indicate whether typing is disabled, locally predicted, or pending delivery.

## Second priority: recovery-aware delivery

### Terminals

Mosh provides a useful design reference: synchronize terminal state and use
predictive local echo to reduce the perceived delay of typing. Prediction must
remain visibly provisional and reconcile with the authoritative remote state.
It is not proof that a command ran and must respect terminal echo behavior.

Stock Mosh bootstraps over SSH and then uses UDP. Adopting it directly would
require integration with SAH authorization, relaying, and recording. Borrowing
its state-synchronization ideas does not mean exposing a new inbound host port
or bypassing the SAH control plane.

### SAHRDP

Desktop recovery should restore the current picture rather than play back a
long backlog of obsolete screen updates:

- Adapt frame rate and JPEG quality to available bandwidth, within lease caps.
- Prioritize control messages and, when separately implemented and authorized,
  remote input over image traffic.
- After reconnecting, send a complete current framebuffer before incremental
  updates. A full refresh can consist of multiple bounded tiles.
- Define a frame generation or equivalent recovery boundary so updates from an
  old picture cannot corrupt a newly restored framebuffer.
- Keep host recording mandatory while separately adapting viewer delivery.

The existing sahrdp/1 contract tightly couples recording and forwarding and
checks frame-rate ceilings at the client. Dropping obsolete delivery updates,
changing recovery framing, or sending a full refresh needs an explicit protocol
change that respects those ceilings. Incremental tiles cannot simply be dropped:
the client might permanently miss a changed region.

Remote keyboard and pointer input remain separate future functionality. If
added, recovery must handle stale input and stuck key/button state without
replaying obsolete gestures after a reconnect.

## Third priority: QUIC with a TCP fallback

Introduce QUIC where supported, initially focusing on the mobile operator-to-hub
hop. QUIC connection IDs and path validation can support address changes and
NAT rebinding without replacing the logical connection. Verify that the selected
implementation and deployment configuration actually support migration.

Retain TLS/WebSocket over TCP 443 as a fallback for networks that block or impair
UDP. Switching transports must use the same authenticated session-resume
mechanism and must not create two active input owners.

QUIC cannot eliminate radio outages. Connection idle timeouts, endpoint restarts,
or sufficiently long disconnections still require application-level recovery.
Reliable QUIC streams also retain ordering within each stream; using QUIC does
not automatically make obsolete desktop updates disappear. Stream scheduling
and any use of unreliable media delivery require a separate design.

## Heartbeats and observability

Use heartbeats to detect dead paths and help maintain idle mappings, with
timeouts that tolerate expected mobile interruptions. Aggressive timeouts can
turn a short outage into unnecessary disconnects. Balance detection time,
battery consumption, and mobile data use.

Measure reconnect duration, resume success, round-trip latency, output backlog,
buffer exhaustion, and transport fallback. Distinguish operator network loss,
agent disconnection, lease expiry, and authorization rejection in diagnostics.
Do not assume every cellular stall has the same cause.

## Acceptance tests

Exercise both terminal and desktop paths under controlled network impairment:

| Scenario | Expected result |
| --- | --- |
| Switch from Wi-Fi to cellular | Same logical session survives migration or authenticated reattachment |
| Interrupt connectivity for 30 seconds | Client shows reconnecting and returns to the same permitted session |
| Lose an input acknowledgment before reconnect | Input is not applied twice |
| Reconnect after a grace period expires | Old session cannot be silently revived |
| Revoke access while the operator is disconnected | Reattachment is refused and termination follows policy |
| Disconnect the agent from the hub | Lease expiry remains enforced; operator grace does not extend it |
| Fail host recording during an outage | Session stops according to the recording contract |
| Exceed the terminal replay buffer | Explicit recovery or failure; no silent byte loss |
| Reconnect the desktop after many screen changes | Full current picture appears without replaying stale updates |
| Add latency, packet loss, and bandwidth limits | Memory stays bounded and controls remain usable where connectivity permits |
| Block UDP | Authorized TCP fallback works without duplicate sessions or input owners |
| Crash the agent or restart the hub | Defined recovery or explicit session loss; no blind command replay |
| Reconnect simultaneously from two clients | Ownership policy is enforced and stale connections cannot inject input |

The primary product acceptance test is: switch networks, interrupt connectivity
for 30 seconds, then return to the same session with no duplicated input,
continuous required recording, and authorization still enforced.

## Implementation order

1. Finish the current batches before starting this work.
2. Specify session lifecycle, authorization, retention, and recovery contracts.
3. Implement persistent terminal sessions and secure reattachment over WebSockets.
4. Add terminal recovery and desktop full-refresh/adaptive delivery semantics.
5. Introduce QUIC migration with TCP fallback using the same resume contract.
6. Validate mobile behavior, resource bounds, recording, and revocation under
   network impairment before enabling it broadly.

Changes across clients, the hub, and agents must be coordinated and reflected in
the SAH suite contract. This proposal does not mark existing display-plan
decisions approved or imply that cross-repository integrations are wired.

## References

- Current SAH architecture: `../systemapi.io/docs/sah-suite.md`.
- Current display contract: [PROTOCOL.md](PROTOCOL.md).
- Display integration proposal: [PLAN.md](PLAN.md).
- [Mosh](https://mosh.org/) and its
  [state-synchronization paper](https://mosh.org/mosh-paper.pdf).
- [QUIC connection migration, RFC 9000 §9](https://www.rfc-editor.org/rfc/rfc9000.html#section-9).
- [QUIC applicability, RFC 9308](https://datatracker.ietf.org/doc/html/rfc9308).
- [OpenSSH ServerAliveInterval](https://man.openbsd.org/ssh_config#ServerAliveInterval).
