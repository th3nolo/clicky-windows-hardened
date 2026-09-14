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
