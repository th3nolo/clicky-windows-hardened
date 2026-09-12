# Notebook worker foundation

This is the first executable boundary between InkNotes and Clicky. It is a
development worker with an explicit demo provider, not an AI tutor. It runs
without Qt, a microphone, credentials, network access or third-party packages.
The existing Clicky desktop entry point is unchanged.

The first milestone proves framing, context identity, cancellation and child
process shutdown before adding audiovisual capture or an inference endpoint.

## Run and verify

From this repository checkout, using the project's supported Python runtime:

```console
python -m clicky_core
```

The worker reads one UTF-8 JSON command per line on stdin and writes JSON events
to stdout. Diagnostics belong on stderr. The parent keeps stdin open while it
waits for replies; EOF closes the worker and cancels active work.

For example, send:

```json
{"protocol_version":1,"request_id":"caps-1","type":"capabilities"}
{"protocol_version":1,"request_id":"ask-1","type":"submit","turn_id":"turn-1","text":"Review this step","context":{"scope":"notebook","notebook_id":"book-1","page_id":"page-1","revision":7}}
```

Wait for `done` before submitting another turn. The demo response is marked
`[Demo]`; it echoes the request and does not evaluate the mathematics. To end
the process, send:

```json
{"protocol_version":1,"request_id":"stop-1","type":"shutdown"}
```

Do not pipe a submit followed by immediate EOF when testing a completed reply:
EOF intentionally cancels the in-flight turn.

Run the offline tests:

```console
python -m unittest -v tests.test_notebook_worker tests.test_turn_coordinator
```

## Protocol v1

Every command has `protocol_version: 1`, a non-empty `request_id` (at most 128
characters), and `type`. Identifiers are host-generated opaque strings, not
paths. All output events include `protocol_version`, `request_id`, and `type`.

| Command | Additional fields | Result |
| --- | --- | --- |
| `capabilities` | None | `capabilities`, with `provider: "demo"`, `inputs: ["text"]`, `audio_in_video: false`, `tts: false` |
| `submit` | `turn_id`, `text`, `context` | `state` / processing, `text_delta`, then `done` / completed |
| `cancel` | `turn_id` | Active submit receives `done` / cancelled; cancellation request receives `ack` / cancelled |
| `shutdown` | None | Cancel active work, `ack` / shutdown, then exit even if stdin is still open |

`turn_id` is non-empty and at most 128 characters. `text` is non-empty and at
most 8,000 characters. This version accepts exactly these context forms:

```json
{"scope":"notebook","notebook_id":"book-1","page_id":"page-1","revision":7}
```

```json
{"scope":"desktop"}
```

Notebook identifiers are non-empty and at most 128 characters; revision is a
non-negative integer, not a JSON boolean. Unknown context fields are rejected.
Desktop scope here is only context identity: it grants no screen access and
does not trigger any capture.

Every per-turn event preserves the originating submit's `request_id`,
`turn_id`, and `context`. A cancel acknowledgement uses the cancellation
command's own `request_id`. The host should generate fresh IDs, reject events
from a prior worker instance, and compare the notebook/page/revision before
displaying or applying a result.

Only one turn runs at a time. Another submit returns `error` with `code: busy`.
A cancel for a different turn returns `turn_not_active` and leaves the active
turn unchanged. Invalid input returns `invalid_request`; a missing or invalid
request identifier is returned as `null`. Malformed JSON does not end the
session. Lines over 65,536 bytes cause an error and terminate the session so
input memory stays bounded. No media fields or implicit provider fallback are
accepted in this version.

## Ownership and compatibility

`clicky_core` reuses the existing `turn_coordinator.py`; it does not copy or
move that implementation. The worker's reasoning provider is injectable for
development and tests, but the CLI only selects the demo provider. A future
packaged worker must include the existing coordinator module. This checkout
is not yet a standalone wheel or an installed InkNotes integration.

Cancellation invalidates the active turn before replacement work can start.
The input loop remains responsive while a response is pending. Child exit
must not affect notebook persistence. A host must drain stdout and stderr
concurrently and terminate a non-responsive child after a bounded shutdown
timeout; it must not automatically replay a request after a crash.

## Next increment: attach InkNotes

Keep C# responsible for its UI, page state and persistence. Add a small worker
client service with redirected stdio and a view-model-owned current request.
Launch with an explicit executable/argument list rather than a shell command.
Marshal display updates onto WPF's dispatcher. Expose send, cancel and worker
status in a developer-only panel until the integration is validated.

Acceptance: start the child, request capabilities, send a selected page's
identity and typed question, display a demo reply, cancel a second turn, and
close/restart the child without losing notebook edits. Windows build, native
UI testing and the InkNotes repository's required checks remain necessary.

The following increment replaces the demo with one tested multimodal provider
and a finite audiovisual clip: activation -> selected source plus microphone
-> stop -> model text -> independent TTS. Both notebook and desktop hosts will
use that same flow. Capturing video, preserving its audio timeline, local or
remote TTS, OCR/LaTeX, exercise grading and packaged distribution are not
implemented by this foundation.
