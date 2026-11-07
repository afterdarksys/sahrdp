# sahrdp/1

The host daemon and the operator client. The systemapi agent execs the daemon and relays these bytes. It does not link this module. The daemon does not listen. The client does not dial the host. A session is one display lease, action `display`, verified with the pinned Ed25519 control key.

Video is JPEG tiles. Audio is PCM and only when the lease says `audio=1` and the daemon was started with `audio` allowed. Clipboard, printers, drive redirection, and input are refused. This interface does not speak MS-RDP and it does not take a Windows password.

## Frame

A frame is a big-endian uint32 length, then that many bytes. The first byte is the type. The length counts the type byte and the payload. The length is at least 1 and at most 65537. A larger length is `protocol_error` and is rejected before the body is read.

| Type | Value | Direction | Payload |
|---|---|---|---|
| hello | 1 | daemon to client | `SAHRDP1` |
| status | 2 | daemon to client | JSON, below |
| video | 3 | daemon to client | uint16 x, y, w, h, then a JPEG |
| audio | 4 | daemon to client | uint32 rate, uint16 channels, uint16 format, then PCM |
| close | 5 | daemon to client | JSON, below |
| lease | 6 | agent to daemon | one start grant |
| renew | 7 | agent to daemon | one renew grant |
| input | 8 | either | refused with `protocol_error` |
| reject | 9 | daemon to client | `{"code":"<code>"}` before the session is up |
| geometry | 10 | capture to daemon | `{"width":N,"height":N}` |

No video or audio byte is written to the client before `status`. `status` is not written before the recording `start` line.

`status` is `{"state":"connected","session_id","width","height","audio","actor","max_fps","max_width"}`. `close` is `{"reason","bytes","digest"}`. `bytes` counts video and audio payloads only. `digest` is the recording's final HMAC, 64 lowercase hex characters.

Audio `format` is 1 (`s16le`). Rate is 8000, 16000, 44100, or 48000. Channels are 1 or 2. One audio payload is at most 16384 bytes. One video payload, header included, is at most 65536 bytes. The JPEG starts with `FF D8` and ends with `FF D9`.

## Lease

The grant JSON is the v1 lease plus the fields the daemon rebuilds. Unknown fields are refused.

```
session_id
deadline_unix
start|renew
seat
output
audio
max_fps
max_width
max_bytes
actor
```

`session_id` matches `dsp_[A-Za-z0-9_-]{16,64}`. Phase 1 seat is `virtual` and output is `0`. `audio` is `0` or `1`. `max_fps` is 1..5. `max_width` is 1..1280. `max_bytes` is 1..1 GiB. `actor` matches `[A-Za-z0-9_.:@+-]{1,128}`. The deadline is in the future and at most 28800 seconds out. A renew cannot change any of those fields.

The signed text is `systemapi-lease-v1`, the same bytes the agent uses for a v1 lease. The payload hash is SHA-256 of `display\n` plus the payload above. The signature is standard Ed25519, standard base64, 64 bytes. A v2 lease is `malformed`. The daemon keeps nonces in memory for 10 minutes and does not persist them.

Ceilings are enforced again on the daemon after the signature checks. A capture tile outside the geometry, a sixth frame inside one second when `max_fps` is 5, or audio past one second of PCM, ends the session. The frame is not recorded and not forwarded.

## Recording

Directory mode `0700`, file mode `0600`, no symlink. The daemon refuses to start a session when the filesystem has less than 1 GiB free. Each line is JSON `seq`, `t`, `k`, `b64`, `mac`. The MAC is HMAC-SHA256 over the previous MAC and the line fields, keyed by the 32-byte recording key. The chain seed is `systemapi-display-recording-v1\n` plus the session id, so a PTY verifier does not report this file as a terminal recording. Kinds are `start`, `video`, `audio`, and `end`. Media is appended before it is forwarded. A full file or a failed write ends the session. Nothing is dropped to keep the picture up.

## Close reasons

`closed`, `idle_timeout` (900 s), `byte_cap`, `max_duration`, `recording_size_limit`, `stopped`, `protocol_error`, `agent_disconnected`.

Reject codes before `status`: `target_denied_agent`, `bad_target`, `recording_unavailable`, `display_unavailable`, `bad_signature`, `expired`, `replay`, `payload_mismatch`, `bad_host`, `bad_action`, `malformed`, `protocol_error`.

An empty `--allow` never writes a hello. `virtual` is required. `audio` is required before a lease with `audio=1` is accepted. Shape codes are `bad_caps`, `bad_session_id`, `bad_deadline`, `bad_phase`, `bad_actor`, `lease_binding`, `expiry_too_far`, `bad_nonce`, and `bad_expiry`, and a renew failure after status closes with the lease code.
