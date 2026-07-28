# Clicky for Windows — Hardened

Clicky is a Windows desktop teaching assistant that can listen to a question, inspect the current screen, answer through a selected AI provider, and point to visible interface elements.

This repository is an independent security-hardened derivative of [Bitshank-2338/clicky-windows](https://github.com/Bitshank-2338/clicky-windows) at source commit `09208d88740db7ba593eb6b95085b63e92a59772`. It is not an official release of, affiliated with, or endorsed by the upstream project.

The upstream MIT license permits modification and redistribution. The original copyright and permission notice remain in [LICENSE](LICENSE).

## Project status

There are no releases yet. The repository contains source and CI configuration for review. Do not treat a local build as a trusted release artifact.

No codebase can be guaranteed completely safe. This derivative reduces the specific source, dependency, network, secret-storage, model-loading, and packaging risks documented in [SECURITY.md](SECURITY.md).

## Supported environment

The reviewed toolchain is narrow by design:

- Windows 10 or 11, x86-64
- CPython `3.12.10` only
- uv `0.11.19` only
- dependencies from the checked-in `uv.lock`
- PyPI wheels only; source builds, Git dependencies, path dependencies, and package upgrades are refused

Do not install this project with pip. See [SETUP.md](SETUP.md).

## What it does

- Push-to-talk voice questions through the global hotkey.
- Push-to-talk barge-in that cancels the owned turn before a replacement capture.
- Replayable synthetic hotkey and pointing practice from setup or the tray.
- Screen capture that excludes Clicky-owned windows, identity-based multi-monitor
  routing, mixed-DPI coordinate mapping, and a click-through PyQt overlay.
- Pointing and drawing instructions produced by supported vision models.
- Cloud LLM support for Anthropic, OpenAI, Gemini, GitHub Copilot, Kimi Code,
  MiniMax Token Plan, DeepSeek, and standard-rate Qwen.
- Optional Codex and Qwen Code read-only response providers through
  already-installed official CLIs. They cannot edit files, run tools, or
  perform external actions. CLI execution has its own explicit permission.
- Local LLM support through an already-installed Ollama or LM Studio server.
- True Deepgram streaming speech-to-text, explicit cloud-batch modes, and local batch speech-to-text fallbacks.
- A fixed local Windows voice status when an approved cloud narration request fails.
- Default-off login startup support for both classic and Microsoft Store installs.
- Optional document context, OCR, lesson recording, per-app conversation history, and quiz mode.
- Optional web search and a local learning journal. Both are off by default.

The application does not provide a fully offline guarantee. Cloud AI providers receive the data needed for the selected request. Cloud speech-to-text, Edge TTS, and web search also require network access. Microphone access, cloud speech-to-text, cloud text-to-speech, and screen capture each remain disabled until the first-run privacy dialog records an explicit choice.

Normal response narration still uses only the explicitly selected cloud TTS
provider. If that approved request fails, Clicky shows the error and uses an
allowlisted local Windows `winrt` or `sapi` voice only for the fixed status
message; response content is not sent to that fallback and barge-in cancels it.

## Hardened defaults

### Dependencies and builds

- Runtime and build dependencies use exact versions in `pyproject.toml`.
- `uv.lock` records SHA-256 artifact hashes.
- Resolution is restricted to 64-bit Windows and the official PyPI index.
- The dependency cutoff is `2026-07-22T00:00:00Z`; CI also reconciles every locked artifact with live PyPI metadata and rejects missing, yanked, mismatched, future-dated, or under-72-hour artifacts.
- GitHub Actions are pinned to full commit hashes.
- CI validates live dependency provenance, runs standard-library security tests, parses every Python file, and performs an unsigned smoke build that is deleted afterward.

### Secrets and local state

- The application does not load `.env` or `.env.local` files.
- Provider API keys are read from the current process environment only.
- Reusable, bounded Windows DPAPI primitives encrypt application secrets for
  the current user, reject corrupt or foreign-user ciphertext explicitly, and
  delete only bounded regular files without following symlinks. GitHub Copilot
  OAuth tokens retain their existing DPAPI file path, format, application
  entropy, verified write, and legacy-migration behavior.
- Non-secret preferences are allowlisted and stored in `%LOCALAPPDATA%\Clicky\preferences.json`.
- The selected model is stored independently for each provider. Saved IDs are
  restored only while they remain in that provider's validated model list.
- Writing-style profiles do not exist until the user creates or imports one.
  SQLite stores only stable IDs, timestamps, enabled state, schema version, and
  DPAPI-protected payloads; names, rules, approved examples, and executable
  identity scopes remain encrypted for the current Windows user. Disabled,
  deleted, corrupt, or out-of-scope profiles cannot be returned by the
  prompt-facing application lookup. Management APIs explicitly cover create,
  inspect, update, enable/disable, delete, single export/import, and complete
  export/import without passive learning or plaintext file storage.
- Microphone access, cloud speech-to-text, cloud text-to-speech, screen capture,
  and external read-only response-provider CLI execution require independent
  persisted permission. Microphone permission alone never authorizes cloud
  transcription.
- Unfinished action capabilities have separate build availability, versioned
  user permission, and per-run grants. All seven action build flags are off in
  the baseline release, and no one layer can authorize another capability.
- Workspace coding remains default-off and unavailable in release builds. The
  source now contains the reviewed Git-selection identity, secret-filtered
  isolated-copy, typed broker, exact two-mapping Windows Sandbox configuration,
  and result-verification contracts. Its only V1 execution boundary is a
  fresh, network-disabled Windows Sandbox; there is no normal-process,
  worktree-only, AppContainer, or path-check fallback. The original repository
  is not mapped, dependencies cannot be installed, commands are typed and
  separately approved. The source also contains host-derived exact diff review
  and a distinct one-use `workspace.apply` authority with stale-original
  detection, a private backup/replacement journal, rollback, post-Apply
  verification, and safe Discard. Those contracts are not exposed in release
  builds. The packaged Sandbox launcher/worker integration and interactive
  Windows evidence remain required. See
  [WORKSPACE_CODING_SECURITY.md](WORKSPACE_CODING_SECURITY.md).
- Desktop automation remains default-off and unavailable in release builds.
  Its source now defines an immutable, review-digest-bound UI Automation target
  identity and a fail-closed policy for same-integrity foreground controls.
  Credential, two-factor, payment, purchase, security, administrator,
  account-change, secure-desktop, destructive, hidden, disabled, protected,
  background, unsupported-pattern, and changed targets are denied. Raw
  mouse/keyboard input and an action executor do not exist. The source also
  contains a metadata-only focused-control inspector, mixed-DPI target
  routing, a non-activating click-through review highlight, immediate exact
  revalidation, a handle-specific Escape hotkey, and run/queue cancellation.
  A missing or expired highlight and a changed target fail closed. Policy or
  review eligibility grants no action authority. See
  [DESKTOP_AUTOMATION_SECURITY.md](DESKTOP_AUTOMATION_SECURITY.md).
- The build-gated Global Dictation session uses a dedicated configurable
  hotkey and the same exclusive turn owner as tutor push-to-talk. Its state
  indicator contains no transcript text, and only a final transcript can
  advance toward insertion. The end-to-end route reuses the explicitly
  selected batch or live STT provider but never calls a response model,
  screenshot path, conversation history, web search, skill, or Task Agent.
  Hotkey-down binds the focused
  editable control by process, executable-path digest, top-level window, UI
  Automation runtime ID, focus, desktop, and process integrity level. Password,
  protected, read-only, disabled, sensitive, elevated, secure-desktop, Clicky,
  changed, and unverifiable targets fail closed before a commit token exists.
  The insertion broker chooses at most one ordered adapter. UIA `SetValue`
  requires an explicit whole-value replacement intent and exact readback;
  Unicode input and clipboard paste are never called verified without a
  readable postcondition. Clipboard fallback requires separate approval and
  a Clicky-owned window handle; it restores only an unchanged, exactly
  restorable text snapshot. Unsupported controls remain unchanged and expose a
  one-use preview-copy action. Result UI names only the destination application
  and truthfully distinguishes verified insertion from an attempted but
  unverifiable insertion. Dictated text stays hidden until the user explicitly
  chooses the recovery preview or copy action. The reviewed baseline build flag
  remains unavailable until the documented interactive Windows matrix passes.
- Screen-Aware Compose has an independent, build-gated draft-generation
  contract. It requires its own action permission and per-run grant plus the
  separate screen-capture permission before capturing only the explicitly
  authorized screens. It revalidates a metadata-only destination lease before
  capture and before generation, accepts only a reviewed model with validated
  image-input support, and sends no conversation history, clipboard, document,
  web, or destination-identity data. Its bounded result contains plain draft
  text and content-free provenance only; it has no insertion, send, submit,
  click, or run authority. Its non-activating preview retains the remembered
  target lease, names the destination application, provider, writing profile,
  and character count, and offers only Insert, Copy, Regenerate, and Cancel.
  Insert creates a one-use typed approval only after target revalidation; the
  preview itself imports no insertion or clipboard implementation. The
  separately permissioned Compose insertion service consumes that approval
  once, rechecks the same target lease again, and routes the draft through the
  exact dictation insertion broker and ordered adapters. It does not authorize
  clipboard fallback, retry a mutation, auto-insert by application, or treat
  Global Dictation permission as Compose authority. Result logs contain only
  the run ID, destination application, status, adapter, and result code.
  Cancel, close, and expiry clear the draft without requesting an action. The
  baseline build flag remains unavailable.
- Speech fallback is off by default and can target only one explicitly selected,
  pre-provisioned local batch recognizer; cross-cloud fallback is refused.
- Journal logging and web search are disabled until the user enables them in the tray.

### Network requests

Web search accepts HTTPS destinations only. It rejects local, private, link-local, reserved, multicast, and unspecified IP addresses before connecting, repeats the check for every redirect, and verifies the actual connected socket peer. Response types, redirects, and decoded byte counts are bounded. Environment proxies are not used.

Deepgram live speech uses only the fixed `wss://api.deepgram.com/v1/listen` endpoint after both microphone and cloud-STT permissions are granted. The tray labels live, cloud-batch, and local-batch modes separately. Live sessions bound PCM frame size, frame rate, queued frames, transcript size, and total duration; they do not reconnect. Fallback is off by default. If the user explicitly selects one verified local batch fallback in the readiness window, Clicky visibly retries the same captured PCM locally after a selected-provider failure. It never falls across cloud providers.

Additional OpenAI-compatible providers use fixed reviewed destinations:

- Kimi Code: `https://api.kimi.com/coding/v1`
- MiniMax Token Plan: `https://api.minimax.io/v1`
- DeepSeek standard API: `https://api.deepseek.com`
- Qwen standard API: `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`

Clicky disables environment proxies and redirects for these direct provider
clients. Their keys are provider-specific and are never reused across billing
realms. Qwen Coding Plan is not exposed as a generic application backend.
Instead, an explicitly selected, already-installed Qwen Code read-only response
provider receives only `BAILIAN_CODING_PLAN_API_KEY`, the selected allowlisted
plan model, and Alibaba's fixed international Coding Plan endpoint.

The transcription vocabulary editor is an explicit approval boundary. Clicky
ships only its own product name, accepts at most 63 custom terms of 64 characters
each, and sends the resulting bounded list only to Deepgram live or batch modes
and OpenAI batch transcription. Unsupported providers ignore vocabulary.
Clicky does not derive terms from window titles, screenshots, clipboard data,
documents, or conversations.

Clicky declares per-monitor-v2 DPI awareness before Qt starts. Each captured image
is labeled with its Windows display number, stable hardware identity when exposed
by Qt, logical rectangle, scale, and focused/primary role. Explicit requests such
as “screen 2” are routed only to that screen; otherwise the foreground-window
screen is selected, with the primary screen as the sole deterministic fallback.
Disagreement between MSS, Win32, and Qt monitor identity aborts capture instead of
silently substituting the first screenshot.

If a provider removes a saved model, Clicky visibly selects only a reviewed
low-cost model that is still present in the validated provider list. Copilot
fallbacks additionally require a reported zero billing multiplier. If no such
fallback exists, requests remain blocked until the user explicitly chooses an
available model; list order is never treated as a cost signal.

### Local code and models

- Bundled skill source must match the checked-in SHA-256 manifest before execution. Python skills under `~/.clicky/skills` run only when `allowlist.json` approves the exact filename and SHA-256 digest.
- Local speech models must already exist. Faster-whisper uses a deterministic digest covering every regular file in the model directory; whisper.cpp verifies the selected model file.
- Ollama models must match both the configured tag and the immutable digest reported by the local Ollama API.
- Clicky does not download, install, start, or pull Ollama, speech models, or other executables.

## Provider configuration

Set only the keys needed for the current PowerShell process:

~~~powershell
$env:ANTHROPIC_API_KEY = "..."
$env:OPENAI_API_KEY = "..."
$env:GOOGLE_API_KEY = "..."
$env:KIMI_CODE_API_KEY = "..."
$env:MINIMAX_API_KEY = "..."
$env:DEEPSEEK_API_KEY = "..."
$env:DASHSCOPE_API_KEY = "..."
$env:BAILIAN_CODING_PLAN_API_KEY = "..."
$env:DEEPGRAM_API_KEY = "..."
$env:ELEVENLABS_API_KEY = "..."
$env:TAVILY_API_KEY = "..."
~~~

Do not place keys in this repository or in a sidecar configuration file.
GitHub Copilot uses the tray device-login flow and stores its resulting token
with DPAPI.

Codex read-only response-provider mode requires an official `codex` executable
already on `PATH` and an explicit login completed through that CLI. Clicky uses
ephemeral non-interactive runs, ignores user Codex configuration and rules,
selects a read-only sandbox, supplies prompts through stdin, and leaves
authentication storage and token refresh entirely to Codex. It never reads
`auth.json`.

Qwen Code read-only response-provider mode requires an official `qwen`
executable already on `PATH` and `BAILIAN_CODING_PLAN_API_KEY`. Clicky uses
Qwen Code's safe headless mode, plan approval mode, bounded turns, output, and
runtime, a temporary working directory, and the fixed international Coding
Plan endpoint. These integrations return responses only: they are not Task
Agents and cannot edit files, run tools, or perform external actions through
Clicky. Clicky never installs either CLI. Selecting a direct or read-only
response provider never silently falls back to a different billing realm.

See [SETUP.md](SETUP.md) for the frozen environment and model-integrity steps.

## User skill approval

A user skill is disabled unless `%USERPROFILE%\.clicky\skills\allowlist.json` contains its exact filename and lowercase SHA-256 value:

~~~json
{
  "version": 1,
  "approved": {
    "my_skill.py": "<64 lowercase hexadecimal characters>"
  }
}
~~~

Calculate the digest before approval:

~~~powershell
(Get-FileHash -Algorithm SHA256 "$HOME\.clicky\skills\my_skill.py").Hash.ToLowerInvariant()
~~~

Editing the skill changes its digest and disables it until reviewed and approved again. A skill is arbitrary Python code; a matching hash proves identity, not safety.

## Features not included in the locked build

- `pynput` is excluded because its dependency chain does not provide the required wheel-only resolution. Workflow capture is therefore unavailable.
- `langdetect` is excluded for the same policy reason. Unicode-script language detection remains, but automatic distinction between Latin-script languages is unavailable.
- Workflow replay is not implemented.

Do not install these packages separately into the reviewed environment. Adding them requires a new dependency review and lock update.

## Build and distribution

`build.bat` creates an unsigned local smoke-test artifact from the frozen lock,
and `build.bat store-rc` is the clean-tree construction entry point. The actual
release-bound onedir must be built once by the reviewed Windows Sandbox
`-StoreReleaseCandidate` path so the authenticated commit, runtime evidence,
exported full tree, executable SHA-256, and CycloneDX SBOM all describe the same
immutable bytes used for Microsoft Store MSIX packaging.

There is no public release. The release design uses legal publisher Manuel Parra
and developed-by brand th3nolo, but Store packaging still requires the three
exact Product identity values from Partner Center. Submission, certification,
Store signing, and post-certification exact-byte verification are not automated
or claimed complete. Unsigned executables, onedir trees, and MSIX packages must
not be distributed. Never instruct a recipient to bypass SmartScreen or add an
antivirus exclusion. See [BUILD.md](BUILD.md).

Installing Clicky never enables login startup. The disabled classic installer
reference uses an unchecked per-user startup-shortcut task, while the MSIX
manifest declares a disabled Windows startup task. The tray opens Windows
Startup Apps so the user can review or change that Windows-owned setting.

## Documentation

- [SETUP.md](SETUP.md): reviewed local setup and model provisioning
- [BUILD.md](BUILD.md): frozen build and signing gates
- [TESTING.md](TESTING.md): automated and manual verification
- [SECURITY.md](SECURITY.md): reporting and security boundaries
- [WORKSPACE_CODING_SECURITY.md](WORKSPACE_CODING_SECURITY.md): approved
  Windows Sandbox boundary for the default-off coding-agent implementation
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution requirements

## Credits and license

The original Windows implementation is [Bitshank-2338/clicky-windows](https://github.com/Bitshank-2338/clicky-windows), based on the Clicky concept by [farzaa/clicky](https://github.com/farzaa/clicky).

Licensed under MIT. The preserved upstream notice is in [LICENSE](LICENSE).
