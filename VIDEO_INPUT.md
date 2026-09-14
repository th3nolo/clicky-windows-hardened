# Screen + voice and clipboard input

Continues merged PR #75. Runtime validation is tracked in [issue #76](https://github.com/th3nolo/clicky-windows-hardened/issues/76).

## Use it

1. Provide `OPENROUTER_API_KEY` in the process environment before launching Clicky. Keys are not saved in preferences or read from `.env` files.
2. Select **OpenRouter** and either `meta/muse-spark-1.2-contributor` or `meta/muse-spark-1.3-contributor` in the model picker.
3. Enable microphone, cloud speech and screen sharing in **Privacy permissions**. Select your microphone using the existing device picker.
4. Choose **Ask with screen + voice…** from the tray. Move the dialog onto the display containing InkNotes, click **Start recording**, then speak and demonstrate your work.
5. Click **Send recording**. The clip also sends automatically at 60 seconds, as disclosed in the dialog. **Cancel**, closing the dialog, or **Escape** discards an active recording. A stale dialog cannot send or cancel a replacement turn.

The microphone and screen capture share a monotonic timeline. This is one recorded request, not a continuous live connection. It starts at the explicit recording action; it does not record the wake-word pre-roll. Ordinary push-to-talk and global dictation retain their STT behavior.

The entire selected display is recorded, including other visible apps and notifications; this is not limited to the InkNotes window or notebook. The dialog keeps the destination, automatic-send limit and model notices visible during recording. If cloud speech output is enabled, the response text also goes to the separately selected speech service. It does not receive the original MP4 through this path.

## Model privacy and audio limitations

Checked against the official pages on 2026-09-13: both [Muse Spark 1.2 Contributor](https://openrouter.ai/meta/muse-spark-1.2-contributor) and [Muse Spark 1.3 Contributor](https://openrouter.ai/meta/muse-spark-1.3-contributor) disclose that prompts and outputs may be used to improve Meta products. The 1.3 page also warns that audio understanding is not fully supported and audio-containing requests may produce degraded answers. The recording dialog shows these notices for the exact selected model; accepting a video request is not a guarantee that the model understood the audio. Both selections remain available.

An optional **OpenRouter only: require no data collection and zero-retention policies** choice is available in Privacy permissions. It starts off to preserve existing model compatibility. When enabled, Clicky requests `provider.zdr: true` and `provider.data_collection: "deny"` for OpenRouter model requests. A selected model may become unavailable under those restrictions; Clicky does not retry with weaker restrictions or substitute another model. Other model providers and speech services are unaffected.

This local choice does not inspect or modify account settings. [OpenRouter documents](https://openrouter.ai/docs/guides/features/zdr) that account or guardrail rules may already enforce ZDR even when the request flag is absent. Its ZDR definition permits implicit in-memory prompt caching and does not cover separate third-party tools/plugins or Clicky's speech services. Verify the actual model/endpoint policy and account restrictions before sending confidential material; enabling the option does not establish that a Contributor endpoint remains eligible.

**Send clipboard…** snapshots text or an image only when selected. Review the copy, optionally enter a question, then click **Send**. Later clipboard changes do not change that request. File paths, HTML and clipboard history are not ingested. Image sharing requires screen/model sharing permission and an image-capable model.

## Provider contract

Custom OpenAI-compatible chat routers and Anthropic-compatible routers remain available through explicit Clicky-owned process variables: `CLICKY_OPENAI_BASE_URL` (include the API prefix such as `/v1`) and `CLICKY_ANTHROPIC_BASE_URL` (the SDK adds `/v1` itself). Configure the matching `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` intentionally for that destination. Defaults remain the official provider endpoints; the direct OpenRouter provider remains fixed. Local HTTP endpoints are allowed for explicit local services. Embedded URL credentials, queries, fragments, control characters and missing hosts are rejected. Endpoints are not persisted in preferences.

Shared SDK variables such as `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL` and `OPENAI_CUSTOM_HEADERS` do not select Clicky's endpoint or authentication. With a custom chat router, provide a separate `OPENAI_SPEECH_API_KEY` if using official OpenAI speech; the chat-router credential is not reused for it. This preserves intentional routing while separating unrelated process configuration. No account setting is changed by configuring these process inputs.

For custom OpenAI routers, discovery recognizes explicit image capability metadata: boolean `vision: true`, boolean `capabilities.vision: true`, or an `image` entry in `input_modalities` / `architecture.input_modalities`. If a router omits this metadata, declare verified image-capable model IDs with `CLICKY_OPENAI_VISION_MODELS`, a comma-separated list used together with `CLICKY_OPENAI_BASE_URL`. This declaration is bound to that exact endpoint, does not persist to preferences or become cached capability evidence, and can be removed without clearing the cache. Unknown models remain text-only; OpenAI-looking aliases alone do not enable images. This setting does not enable MP4 input or promise live model comprehension.

The adapter uses the existing OpenAI-compatible transport at the fixed `https://openrouter.ai/api/v1` endpoint. It sends the MP4 as a `video_url` content part with a `data:video/mp4;base64,...` URL and streams text back. Redirects, SDK retries and OpenRouter provider fallback are disabled.

The request format was checked against [OpenRouter's video-input documentation](https://openrouter.ai/docs/guides/overview/multimodal/videos). Embedded-audio support for the two Muse model IDs is based on the project owner's endpoint verification. No live authenticated Muse request was run in this environment; do not treat synthetic encoding and mocked transport tests as endpoint validation.

Audio stays inside the MP4; the video path does not call a separate STT provider, strip silence, or substitute screenshots after a failure. Responses appear in the panel and use the existing selected TTS path. They do not run skills, control markup, or tools. Action execution still requires the existing Task Center workflow and its approvals.

## Bounds and lifecycle

Clipboard submissions, reviewed region handoffs, and screen-and-voice recordings
retain the accepted provider, effective endpoint, model and selection revision.
Changing that selection while work is queued rejects the request, including a
change away and back to the same model. Clipboard image data is copied at
submission. Immediately before dispatch, Clicky rechecks the relevant sharing
permission and image capability, acquires the matching backend/model pair, and
uses that pair for the stream. A later switch affects new requests; it does not
redirect an already acquired request. There is no cross-provider fallback.

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

The intended InkNotes workflow runs the apps separately and uses Clicky's desktop recording action. A direct WPF-to-worker connection and automatic notebook editing are separate, unimplemented features; they are not prerequisites for screen-and-voice capture.

## Native and packaged readiness checklist

The following are acceptance steps, not claims that this revision has executed them:

- [ ] Review the selected model's current data-use policy and applicable account/guardrail restrictions locally without exposing keys. If strict routing is enabled, verify eligibility or a clear failure without a weaker retry.
- [ ] Use a disposable notebook and non-sensitive display content. Confirm the intended microphone and display, legible handwriting and synchronized audio. Other visible apps/notifications must be suitable to share.
- [ ] For **each** Muse model separately, write `2 + 2`, erase it, write `3 + 3`, and say a word never shown onscreen. Record whether the response correctly distinguishes the earlier writing, replacement and spoken-only word. An HTTP success is insufficient.
- [ ] Cancel before sending with Cancel, Escape and window close; verify no cancelled recording later produces a response. Test microphone disconnection and display changes. Cancellation cannot retract bytes already transmitted.
- [ ] Confirm the visible model notices and 60-second automatic-send behavior. Test text/image clipboard preview consistency after changing the clipboard.
- [ ] Record the built package's identity and repeat a short audiovisual/cancellation test in that package. Source test success and a packaged build alone do not verify packaged codecs or the physical workflow.
- [ ] If spoken answers are desired, verify the separate speech provider/key and permission. Otherwise leave cloud speech output disabled. With a custom OpenAI-compatible chat endpoint, OpenAI STT/TTS and realtime speech require a separate `OPENAI_SPEECH_API_KEY` for the fixed OpenAI speech endpoint; keys remain process inputs, not preferences. A normal OpenAI chat key remains usable for OpenAI speech when chat uses the default official endpoint.

## Verification

### Earlier feature-validation record

The following results describe the earlier screen-and-voice implementation, including its Linux offscreen run; they are not new physical, packaged or live-provider validation of the current credential-isolation revision.

Focused tests cover a real encoded MP4 with both tracks, decoded audio amplitude, start offset and timestamp gaps; provider payload and stream closure; worker routing; capture ownership, stale sends, cancellation, permission/model changes; clipboard snapshots and rejected files. Existing microphone, routing, barge-in, tray, privacy, capture-exclusion and dependency checks also pass locally.

Strict mypy covers the worker plus the new media schema, recorder and UI. Runtime dependencies and the lockfile are unchanged; PyAV was already pinned and its package collection is now explicit in `clicky.spec`.

Before merging/releasing, complete issue #76's native Windows, packaged-codec, handwriting-legibility and live-provider checks. Local UI tests run offscreen on Linux and use synthetic audio rather than physical recording devices.

The focused run executed 150 tests: 149 passed and one Windows process-boundary
test was skipped. The full standard-library CI selection also exposed two
Windows PowerShell path assertions that fail on Linux; both failures were
reproduced on unchanged base commit `a2f3188`. The new provider metadata remains
dependency-free so that this CI job does not need Pydantic installed.

### Credential-isolation revision: focused local checks

On 2026-09-13, the focused notice/configuration suite passed **24/24** tests (`tests.test_media_privacy_notice` and `tests.test_privacy_consent`) in the existing Windows Python environment, with disposable preferences and synthetic credentials/endpoints. It checks default-preserving private routing, exact-model notices, separate speech credentials, and explicit local/custom router URL validation. This is neither a physical UI/recording test nor live account/provider or installed-package acceptance; the checklist above remains necessary. Provider request serialization and speech client isolation have separate focused transport tests.
