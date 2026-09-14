# Desktop orchestration cleanup

The desktop manager previously classified commands, located screen targets,
parsed streamed drawing markup, and coordinated playback inside one long
processing method. This change gives those operations named boundaries and
removes duplicated code without introducing a service framework or new runtime
dependencies.

## Ownership

| Concern | Owner | Interface |
| --- | --- | --- |
| Local command recognition | `tutor.py` | `classify_voice_command(str) -> VoiceCommand \| None` |
| Command execution, capture and playback coordination | `companion_manager.py` | Named async phases using the current `TurnSession` |
| Cancellation and shared application state | `turn_coordinator.py` | `TurnCoordinator`, `TurnSession`, `AppState` |
| Incremental visible response text | `ai/response_text.py` | `ResponseText.feed()` and `finish()` |
| Speech output | `audio/tts/base_tts.py` | `BaseTTS` protocol with async `speak(str)` |
| Concrete speech provider selection | `audio/tts/factory.py` | Typed factory; existing lazy provider imports |
| Tray, voice selection and microphone meter | `ui/` | Qt signals and typed callbacks |
| Capability definitions and OAuth scopes | `capability_registry.py` | One definition per capability; derived immutable scope mapping |
| Desktop action transport | `automation/action_broker.py` and `action_protocol.py` | Existing authenticated command and receipt boundary |

The manager imports application state from the coordinator. `ui.panel` reexports
the same enum for existing callers. UI rendering therefore does not own the
orchestrator's state type.

## Behavior and size

- Built-in commands are classified once, with STOP first and walkthrough NEXT
  ahead of lesson NEXT. A repeat request without history still falls through.
- Both tutor response paths share incremental markup filtering. Streams close
  when processing exits, including stale turns and cancellation.
- Local target detection still precedes remote fallback. Optional locator setup
  failures now follow the existing no-target path, allowing narration to proceed.
- Nine tray toggle constructors share one small helper. Microphone stop messages,
  OAuth callback rejection and worker authentication-key validation each have one
  implementation.
- Capability-to-scope associations are declared beside their capability, removing
  a separately maintained lookup table.
- The main processing method falls from 666 to 495 lines. Across changed production
  Python files, including the new response parser, the net reduction is 104 lines.

No demo provider or runtime dependency is added. The disabled-TTS implementation
continues to enforce the existing speech permission setting.

## Boundaries retained

Task-model collection and its configured provider adapter each own their acquired
iterator through `tasks/stream_lifecycle.py`. Cleanup is awaited when iteration
finishes or fails, while iterators without a callable `aclose` remain supported.
An existing validation, provider, or cancellation error wins over a cleanup
error; cleanup-only failure prevents a successful broker result. This owns stream
cleanup attempts, not provider-client disposal or a new cleanup timeout policy.

`security/filesystem.py` owns the shared link/reparse predicates, directory
protection and no-follow tree cleanup. Task workspaces, artifact adoption and
workspace adoption use that public interface while retaining their separate
root checks, authorization, rollback and error reporting. The extraction does
not change native ACL behavior or establish new containment guarantees.

Microphone diagnostics remain local and separate from transcription and capture.
OAuth consent, scope validation, token storage, action approval, worker isolation,
and authenticated receipts keep their existing responsibilities. The CI build,
verification, scanning and cleanup jobs retain their separate authority.

Simple guards remain where they express a condition directly. Dispatch tables or
additional classes would not simplify every branch. The manager still contains
substantial capture and playback orchestration; this is a bounded cleanup, not a
claim that the entire repository is fully typed or decomposed.

## Verification

Focused regression tests cover command precedence, chunk-boundary parsing, stale
stream closure, local pointing, barge-in, microphone diagnostics, voice selection,
tray toggles, OAuth callback methods, capability grants, desktop receipts and
quarantine/dependency validation. The default strict mypy target expands to 14
source files, with explicit `Any` disallowed and no new type suppressions.

Local checks use offscreen Qt on Linux. Native Windows capture, microphone
hardware, packaged startup and actual provider endpoints require Windows/runtime
validation; unit tests do not establish those outcomes.
