# User workflow acceptance

A component test is not proof of a working desktop workflow. Record the exact provider, model, speech provider, audio format, permissions, runtime, and application revision. Configured, model-verified, provider-tested, and physically tested are distinct results.

## OpenRouter-only acceptance matrix

| User action | Required result | Regression coverage |
| --- | --- | --- |
| Start with only an OpenRouter key | Select OpenRouter; do not require Ollama | test_setup_provider_flow |
| Skip local setup | Visible provider handoff; no false readiness claim | test_setup_provider_flow |
| Review permissions | Core input/output choices first; unrelated features optional; existing grants visible | test_first_run_feedback, test_privacy_consent |
| Select Muse 1.2 without an explicit STT choice | Use OpenRouter transcription; preserve explicit speech choices | test_setup_provider_flow, test_stt_preflight |
| Hold/release Ctrl+Windows | One capture per key cycle, regardless of press order/repeat | test_hotkey_events, test_companion_barge_in |
| Start without prerequisites | Actionable feedback; no upload without permissions | test_stt_preflight |
| Change destination/policy during capture | Reject before upload; never reuse a stale cloud client | test_stt_preflight, test_dictation_pipeline |
| Transcribe audio | Fixed endpoint/model, real declared format, bounded input/output, isolated key, no fallback | test_openrouter_stt |
| Empty response or service failure | Persistent actionable panel error | test_first_run_feedback |
| TTS fails after an answer | Preserve the readable answer | test_first_run_feedback, test_tts_failure_fallback |
| Retry successfully | Clear old errors; preserve new same-turn errors | test_first_run_feedback |

Speech hotkeys and screen-video recording remain different inputs. They share selection and privacy rules, but their different payloads require separate evidence. A valid MP4 with an audio track does not prove the model understood that track.

## Live and physical checks

1. Use a capped test key and synthetic speech through the actual production encoder and STT class. Record expected words, transcript, downstream answer, and usage; never the key.
2. Test each video model using a known visual sequence and spoken-only word. HTTP success and visual correctness do not pass audio comprehension. Keep unverified capabilities explicitly qualified in the UI.
3. Verify physical Windows hotkey delivery, selected microphone, capture cancellation, panel feedback, and audible playback in the exact application build. Synthetic key events and offscreen Qt do not complete this gate.
4. Retain explicit local-router, OpenAI, Anthropic, and other provider choices. Do not install a model or switch cloud destinations silently to pass a test.

Run the standard unittest discovery suite with the existing reviewed runtime, a disposable profile, and offscreen Qt. Live checks are separate opt-in runs and must not execute in ordinary CI. The test suite must use synthetic credentials and block unintended external requests.

## Spatial teacher workflow

Clicky owns the spoken question, model selection, explanation and teaching sequence. InkNotes exposes native-ink operations through its current-user Windows named pipe MCP server. Clicky's standard-library stdio adapter carries MCP requests; it does not replace the user's notebook with a chat surface.

The production manager captures notebook ID, page ID and revision when the recording is released, before transcription and explanation generation. It supplies that snapshot to `write_explanation`. A mismatch on the planner's first read stops writing to a different or edited page. Each subsequent mutation also checks a fresh page identity/revision immediately before dispatch; the InkNotes server enforces the supplied revision atomically.

The default `verified` loop uses the actual page image plus bounded stroke geometry and the image-to-page transform. Handwritten symbol interpretation remains a model judgment. Tools available to the planner are:

- `inknotes_read_page`: observe the page or a close-up region.
- `inknotes_annotate`: draw a colored ellipse, rectangle, underline, bracket or arrow around page bounds or identified strokes.
- `inknotes_write_at`: place handwriting in a specified page rectangle.
- `inknotes_draw_path`: create a native pen path.
- `inknotes_remove_annotation`: remove only an annotation created by this teaching session.
- `inknotes_add_handwriting`: retain complete-note writing compatibility.
- `inknotes_save`: save an existing notebook location.

After a mutation, Clicky reads the full page again before presenting the successful step narration. Completion requires a model checklist against the resulting full-page image and structural read-back of session annotations. A cropped image cannot establish whole-page completion: Clicky supplies the full page for another assessment. Final messages distinguish a model visual assessment from deterministic structural checks and confirmed saving; neither establishes mathematical correctness by itself.

The loop defaults to 24 model turns and 300 seconds, including awaited step narration. It checks cancellation while streaming, before dispatch, and again after the awaited preflight read. Already completed operations remain undoable ink; cancellation cannot retract a request already executing in InkNotes. Ambiguous transport failures are not retried. Explicit rejected operations may be corrected twice only after a fresh read confirms unchanged identity/revision. Repeated identical mutations are deduplicated, and saving is revision-aware. Spatial teaching currently stays on one page rather than silently moving the explanation to another page.

`baseline` and `geometry` are experimental comparison modes, not measured winners. Baseline sends no images and writes the complete supplied explanation using the legacy tool. Geometry supplies images and spatial tools but does not request a final visual self-assessment. A provider without vision support takes the baseline fallback and reports that limitation. Keep model, synthetic task, initial notebook and budgets equal when comparing modes.

### Validation

Run focused regressions with the existing reviewed Python environment and dependency lock; no installation is required:

```powershell
python -B -m unittest tests.test_teaching_planner -v
python -B -m unittest tests.test_teacher_manager tests.test_original_voice_video -v
```

Manager/UI tests need the existing Qt runtime, a disposable profile, and offscreen Qt for automated runs. Run the repository's full offline discovery checks separately. These tests establish planner and manager behavior, not physical microphone, Windows shortcut, audible playback, or live model quality.

Dynamic acceptance must start through Clicky's interface with both applications running on a synthetic notebook. Record runtime identities, model and provider, source revision, observed operations and final rendered page. Check semantic annotation targets, preservation of original ink, readable placement, narration, interruption, undo/redo and save/reopen. Compare the complete result against an independent mathematical oracle. Treat direct MCP component tests and live model-to-MCP tests as supporting evidence, separately from the complete two-app user workflow.
