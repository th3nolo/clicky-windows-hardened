# Notebook worker

The worker reuses Clicky's existing inference providers and turn coordinator
without importing the desktop UI. Production has no demo provider or fallback.
It currently sends text only; InkNotes UI, audiovisual clips, OCR/LaTeX and
TTS are still unimplemented. This is not an installed or packaged integration.

## Run

Use the repository's locked Windows environment, installed through `build.bat`.
Select both the provider and model explicitly:

```console
uv run --no-sync python -m clicky_core --provider openai --model gpt-4o-mini
```

That example uses the existing OpenAI provider and its configured credentials.
`--help` lists the supported provider IDs, including local Ollama and LM Studio.
Local providers retain their existing endpoint/model configuration checks.
There is no automatic model selection, provider fallback, capture, or upload of
notebook identifiers. A valid-looking model ID is not proof of model access;
provider errors surface as a failed turn. Provider initialization failures exit
with a generic diagnostic on stderr. No live endpoint has been verified as
part of this refactor.

Send one UTF-8 JSON command per line on stdin; read JSON events from stdout.
Keep stdin open while waiting for a reply. EOF cancels active work.

```json
{"protocol_version":1,"request_id":"caps-1","type":"capabilities"}
{"protocol_version":1,"request_id":"ask-1","type":"submit","turn_id":"turn-1","text":"Help me understand x squared equals four","context":{"scope":"notebook","notebook_id":"book-1","page_id":"page-1","revision":7}}
```

Wait for `done` before another submission. To stop:

```json
{"protocol_version":1,"request_id":"stop-1","type":"shutdown"}
```

## Contract and ownership

Every command requires integer `protocol_version: 1`, a nonblank `request_id`
of at most 128 characters, and `type`. Unknown or missing fields are rejected.

| Command | Additional fields | Result |
| --- | --- | --- |
| `capabilities` | None | Actual selected provider name; text input, no video/audio or TTS |
| `submit` | `turn_id`, `text`, `context` | Processing event, streamed text, completion or failure |
| `cancel` | `turn_id` | Matching turn completes as cancelled before the cancellation acknowledgement |
| `shutdown` | None | Active turn cancelled, acknowledgement, exit without waiting for stdin EOF |

`turn_id` follows the same identifier constraints as `request_id`; text is
nonblank and at most 8,000 characters. Context is exactly one of:

```json
{"scope":"notebook","notebook_id":"book-1","page_id":"page-1","revision":7}
```

```json
{"scope":"desktop"}
```

Notebook IDs follow the same identifier rules. Revision must be a nonnegative
integer; booleans and floats are rejected. Context is validated, immutable and
retained locally for response correlation. Desktop scope does not grant screen
access or trigger capture. Every turn event carries its originating request,
turn and context. The host should compare page/revision before displaying a
result and reject events from an old worker instance.

Only one turn runs at a time. Concurrent submission reports `busy`; mismatched
cancellation reports `turn_not_active`. Cancellation invalidates the turn before
another can start. Late provider output cannot complete or update a newer turn.

Malformed requests report `invalid_request` without echoing payloads. A valid
request ID is preserved on schema errors; otherwise it is null. Duplicate JSON
fields and nonfinite constants are rejected. Input lines are bounded to 65,536
bytes including newline; oversized input produces an error and ends the worker.
The input queue is bounded and applies backpressure without polling.

A private buffered stdin duplicate avoids holding Python's standard-input lock
at interpreter shutdown. A daemon reader is necessary because Windows stdin
cannot reliably use the POSIX asyncio pipe transport. It may remain blocked
until process exit when the parent keeps the pipe open. The host must drain
stdout/stderr concurrently and enforce a bounded child shutdown timeout.

## Python conventions

- Schemas validate external data once; internal commands use immutable typed models.
- `ReasoningProvider` is a small structural interface: a name and a stream of text
  from a typed `Submit`. `ClickyProvider` adapts the existing backend contract.
- Dispatch matches command types exhaustively. Separate methods own cancellation,
  submission and completion. Runtime state guards remain where behavior needs them.
- New code must not introduce `Any`, unparameterized containers, or type-check
  suppression. `object` is for untrusted input before validation; `JsonValue`
  is for serialized event payloads. Older modules still have typing debt.
- Fake providers belong in tests. No generic plugin registry or inheritance tree
  is needed to exchange a reasoning implementation.

Run from an environment containing Pydantic:

```console
python -W error::ResourceWarning -m unittest tests.test_notebook_worker tests.test_turn_coordinator tests.test_dependency_policy
mypy --config-file pyproject.toml
```

Mypy configuration checks `clicky_core` strictly and rejects explicit `Any`.
Its Pydantic plugin generates typed constructors. Mypy is an external development
tool, not part of the locked runtime or an automated CI gate yet. The Windows
locked-environment test job runs the worker tests; the standard-library-only
job deliberately excludes them. Test subprocesses use a provider defined only
in `tests/notebook_worker_runner.py` and make no external calls.

Next product increment: connect the WPF client on Windows, then implement the
requested synchronized video/microphone input and independent TTS. Existing
Clicky inference adapters accept text/JPEG; they do not establish Muse Spark
video/audio API support.
