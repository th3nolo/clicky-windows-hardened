# Screen + voice and clipboard input

Continues merged PR #75. Runtime validation is tracked in [issue #76](https://github.com/th3nolo/clicky-windows-hardened/issues/76).

## Use it

1. Provide `OPENROUTER_API_KEY` in the process environment before launching Clicky. Keys are not saved in preferences or read from `.env` files.
2. Select **OpenRouter** and either `meta/muse-spark-1.2-contributor` or `meta/muse-spark-1.3-contributor` in the model picker.
3. Enable microphone, cloud speech and screen sharing in **Privacy permissions**. Select your microphone using the existing device picker.
4. Choose **Ask with screen + voice…** from the tray. Move the dialog onto the display containing InkNotes, click **Start recording**, then speak and demonstrate your work.
5. Click **Send recording**. The clip also sends automatically at 60 seconds, as disclosed in the dialog. **Cancel**, closing the dialog, or **Escape** discards an active recording. A stale dialog cannot send or cancel a replacement turn.

The microphone and screen capture share a monotonic timeline. This is one recorded request, not a continuous live connection. It starts at the explicit recording action; it does not record the wake-word pre-roll. Ordinary push-to-talk and global dictation retain their STT behavior.

**Send clipboard…** snapshots text or an image only when selected. Review the copy, optionally enter a question, then click **Send**. Later clipboard changes do not change that request. File paths, HTML and clipboard history are not ingested. Image sharing requires screen/model sharing permission and an image-capable model.

## Provider contract

The adapter uses the existing OpenAI-compatible transport at the fixed `https://openrouter.ai/api/v1` endpoint. It sends the MP4 as a `video_url` content part with a `data:video/mp4;base64,...` URL and streams text back. Redirects, SDK retries and OpenRouter provider fallback are disabled.

The request format was checked against [OpenRouter's video-input documentation](https://openrouter.ai/docs/guides/overview/multimodal/videos). Embedded-audio support for the two Muse model IDs is based on the project owner's endpoint verification. No live authenticated Muse request was run in this environment; do not treat synthetic encoding and mocked transport tests as endpoint validation.

Audio stays inside the MP4; the video path does not call a separate STT provider, strip silence, or substitute screenshots after a failure. Responses appear in the panel and use the existing selected TTS path. They do not run skills, control markup, or tools. Action execution still requires the existing Task Center workflow and its approvals.

## Bounds and lifecycle

- One pinned display, captured at 6 fps, at most 1280 × 720; H.264 video and mono 16 kHz AAC audio.
- 60-second capture ceiling, 24 MiB capture-buffer ceiling, 16 MiB encoded MP4 ceiling. Capacity failures discard the request rather than truncate it silently.
- Frames and PCM stay in memory; no temporary recordings or media journal entries are written.
- Input-device ADC timestamps preserve audio latency and discontinuities. Screen-frame timestamps preserve missed-frame time rather than speeding the video up.
- Permissions and the existing sensitive-window check are evaluated repeatedly. Display-layout or model changes reject the clip. Clicky's windows are excluded through the existing capture-exclusion boundary.
- Cancellation stops microphone/frame delivery and is checked during encoding and before upload. Cancelling after transmission cannot retract bytes already received remotely.

## Notebook worker

Run the existing worker with an explicit selection:

```powershell
python -m clicky_core --provider openrouter --model meta/muse-spark-1.3-contributor
```

The protocol retains version 1 and adds an optional `video` object to `submit`: `mime_type` must be `video/mp4`, and `data` contains base64 MP4 bytes. `text`, `context`, `request_id` and `turn_id` retain their existing requirements. The `capabilities` event reports `inputs: ["text", "video"]` and `audio_in_video: true` only for the two supported selections. Other providers reject video rather than dropping it.

JSONL lines are bounded at the maximum base64 clip size plus 64 KiB for the command envelope. The input queue holds at most two lines. Media and credentials are never echoed in worker events; invalid commands and provider failures retain content-free errors.

This changes the Python worker and the Clicky desktop app. The InkNotes WPF client still needs its own connection to the worker; meanwhile the desktop recording action can capture InkNotes on screen.

## Verification

Focused tests cover a real encoded MP4 with both tracks, decoded audio amplitude, start offset and timestamp gaps; provider payload and stream closure; worker routing; capture ownership, stale sends, cancellation, permission/model changes; clipboard snapshots and rejected files. Existing microphone, routing, barge-in, tray, privacy, capture-exclusion and dependency checks also pass locally.

Strict mypy covers the worker plus the new media schema, recorder and UI. Runtime dependencies and the lockfile are unchanged; PyAV was already pinned and its package collection is now explicit in `clicky.spec`.

Before merging/releasing, complete issue #76's native Windows, packaged-codec, handwriting-legibility and live-provider checks. Local UI tests run offscreen on Linux and use synthetic audio rather than physical recording devices.

The focused run executed 150 tests: 149 passed and one Windows process-boundary
test was skipped. The full standard-library CI selection also exposed two
Windows PowerShell path assertions that fail on Linux; both failures were
reproduced on unchanged base commit `a2f3188`. The new provider metadata remains
dependency-free so that this CI job does not need Pydantic installed.
