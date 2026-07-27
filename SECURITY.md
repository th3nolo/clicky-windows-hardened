# Security policy

## Status

Clicky for Windows — Hardened has no releases yet. No released version is currently supported. The current `main` branch is development source for review and does not carry a security-support guarantee.

This project is an independent derivative of [Bitshank-2338/clicky-windows](https://github.com/Bitshank-2338/clicky-windows) at source commit `09208d88740db7ba593eb6b95085b63e92a59772`. It is not affiliated with or maintained by the upstream project.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability reporting:

https://github.com/th3nolo/clicky-windows-hardened/security/advisories/new

Include:

- the affected commit and file
- the operating-system and toolchain versions
- the smallest reproducible steps
- expected and observed behavior
- impact and required preconditions
- logs with tokens, API keys, device codes, screenshots, and personal data removed
- a proposed remediation, if available

Do not send real credentials or exploit third-party accounts.

Reports are reviewed as maintainer capacity permits. This project does not promise acknowledgment, assessment, remediation, disclosure, or release deadlines.

## In scope

- Python application code in this repository
- dependency, lock, CI, PyInstaller, and installer configuration
- provider credential and GitHub Copilot token handling
- web-search URL validation, redirects, content limits, and connected-peer checks
- local model identity checks
- skill loading and approval
- journal and preference storage
- behavior of a future artifact built from the documented pipeline

Third-party provider services, Ollama, LM Studio, model publishers, Python, uv, PyPI, GitHub Actions, Inno Setup, and Windows are maintained elsewhere. A vulnerability in Clicky’s integration with one of them remains in scope. A vulnerability solely in the third-party product should also be reported to that vendor.

## Security boundaries

### Dependencies

- Python `3.12.10` and uv `0.11.19` are the reviewed toolchain.
- Direct dependencies use exact versions.
- `uv.lock` contains SHA-256 hashes and is restricted to the official PyPI index and 64-bit Windows wheels.
- Source builds, Git dependencies, path dependencies, managed Python downloads, package upgrades, and unreviewed package indexes are refused by the supported build.
- The publication cutoff is `2026-07-22T00:00:00Z`. CI additionally matches every locked artifact URL, filename, size, and SHA-256 against live PyPI version metadata and rejects yanked, future-dated, or under-72-hour artifacts.
- Live PyPI TLS is bound to the reviewed `certifi==2026.6.17` CA bundle tracked with its upstream license; ambient host roots and TLS bypass variables are not accepted by the supported gate.
- GitHub Actions use reviewed full commit hashes and do not persist checkout credentials.

These controls reduce dependency substitution and fresh-package risk. They do not prove that a locked dependency is free from malicious or vulnerable code.

### Secrets

- Clicky does not load `.env` or `.env.local`.
- Cloud provider keys are accepted from the current process environment only.
- GitHub Copilot tokens are encrypted with current-user Windows DPAPI and stored in `%LOCALAPPDATA%\Clicky\github_token.dpapi`.
- Device authorization codes are displayed transiently and are not written to the login log.
- Non-secret settings are restricted to allowlisted fields in `%LOCALAPPDATA%\Clicky\preferences.json`.

DPAPI does not protect a token from malware already running as the same Windows user. Overwriting and deleting a legacy plaintext file cannot guarantee removal from SSD wear-leveling, backups, snapshots, or forensic copies.

### Network access

Cloud AI, speech, text-to-speech, and search features send data to their configured third-party services. Review the service policy and account settings before enabling a provider.

Web search is disabled by default. When enabled, page fetches:

- require HTTPS
- reject credentials in URLs
- reject local, private, link-local, reserved, multicast, and unspecified addresses
- validate every DNS result before each request
- verify the actual connected socket peer before redirect or body processing
- validate every redirect
- reject unexpected content types
- cap redirect count and decoded response bytes
- ignore environment proxy settings

These checks reduce server-side request forgery and unbounded-download risk. They do not make arbitrary web content trustworthy. Search content is untrusted input to the selected model.

### Local executable code

Bundled skills are part of the reviewed application and execute only when every bundled source file matches the checked-in SHA-256 manifest. CI verifies that the manifest covers exactly the packaged bundled skills. User skills are arbitrary Python code and are disabled by default. A user skill runs only when its exact filename and SHA-256 digest appear in `~/.clicky/skills/allowlist.json`. A matching digest identifies reviewed bytes; it does not establish that those bytes are safe.

### Models and external programs

Clicky does not download, install, start, or pull Ollama or local speech models.

- A faster-whisper directory must match a deterministic SHA-256 covering every regular file, relative path, and size; symlinks, junctions, and linked descendants are refused. A whisper.cpp model file must match its configured SHA-256.
- An Ollama model must match its configured model tag and the exact digest returned by the local Ollama API.
- Missing, ambiguous, changed, or unverifiable models fail closed.

Model hashes establish file or artifact identity. They do not establish model quality, license compliance, training-data provenance, or resistance to malicious prompts. Digest verification does not lock the model directory: another process with the same user's write access could replace files between verification and the native runtime's load. Keep reviewed model directories write-protected from other same-user processes when that local threat is in scope.

### Privacy defaults

Microphone access, cloud speech-to-text, cloud text-to-speech, and screen capture are independently off until the current first-run privacy notice records an explicit choice. Closing the dialog grants nothing, and accepting an older notice version grants nothing after the permission model changes. Microphone permission covers local wake-word listening and deliberate capture only; cloud STT permission separately covers captured audio sent to a selected cloud transcription provider. Screen permission covers capture of every monitor and disclosure that cloud LLM providers receive those images; cloud TTS permission covers response text sent to Microsoft Edge TTS, OpenAI, or ElevenLabs.

Temporary local-transcription WAV files are created in a protected per-user directory, removed after use, and swept after a terminated-process crash. Deletion cannot guarantee forensic erasure from SSDs, backups, snapshots, or other same-user processes that read a file while it existed.

Web search and journal logging are also off by default. After explicit activation, the setting persists in the non-secret preferences file. The journal can contain questions, answers, provider and model names, active-application identifiers, and window titles. It is a local plaintext SQLite database.

The Privacy Guard uses window-title matching. It can miss sensitive content and is not a substitute for closing or hiding confidential windows. Explicit screen permission is still required, but permission does not make the title heuristic comprehensive.

Clicky applies Windows `WDA_EXCLUDEFROMCAPTURE` affinity to every current-
process Qt top-level window and re-enumerates current-process native windows
before each screenshot. If Windows cannot apply and verify that affinity, the
capture boundary snapshots, hides, verifies, and compositor-flushes every
visible Clicky-owned top-level window before capturing, then restores placement,
visibility, and foreground state in `finally`. Any hide, verification, flush,
or restoration failure is explicit and aborts the capture. The same guard
covers LLM screenshots, OCR fallback captures, and lesson-recorder frames.

Each microphone capture and generated response has one process-local turn
identity. Starting a replacement push-to-talk turn invalidates the prior
identity before cancelling its recording, transcription, generation, and
playback resources. Late callbacks from an invalidated turn are refused before
they can update Clicky's state or response UI.

Deepgram live transcription uses a provider-neutral open/send-frame/finalize/
cancel lifecycle owned by that turn. It connects only to the reviewed Deepgram
WebSocket endpoint with environment proxies and redirects disabled, sends the
process-environment credential only in the authorization header, and bounds
frame size and rate, queue depth, session bytes and duration, provider-message
size, transcript size, and every connection/finalization timeout. A disconnect,
timeout, capacity failure, or provider error is surfaced explicitly. The live
session does not reconnect and does not silently invoke batch or local STT.
Partial and final transcript UI updates carry the turn sequence so queued
updates from an interrupted turn are rejected.

Monitor routing joins physical MSS rectangles, Win32 display identities, and Qt
logical rectangles before a capture is accepted. Clicky does not use list
position as monitor identity. It preserves negative origins and independent
horizontal/vertical scale ratios, and it scopes OCR, accessibility lookup,
figure detection, lesson recording, pointer coordinates, and model instructions
to the requested or foreground-window monitor. Unknown display numbers,
ambiguous hardware identities, or topology changes fail explicitly. Per-monitor
v2 awareness is declared in both startup code and the executable manifest.

Model selections are bounded, syntax-validated non-secret preferences stored
separately for Claude, OpenAI, Gemini, Copilot, Ollama, and LM Studio. A saved
cloud model is restored only when its exact ID remains in the validated model
list. Removed IDs can fall back only to reviewed low-cost aliases; Copilot
requires an explicit zero multiplier from its model metadata. Without an
eligible fallback, Clicky blocks the request and asks for a visible selection
instead of using a provider default or the first list entry.

Transcription vocabulary contains the shipped `Clicky` term plus only terms the
user entered and saved in the dedicated editor. Custom terms are normalized,
deduplicated, limited to 63 entries and 64 printable characters each, and stored
in the allowlisted non-secret preference file. Only Deepgram live and batch
requests receive the bounded list. Other STT providers ignore it. Clicky never
mines vocabulary from window titles, screenshots, clipboard content, attached
documents, conversation history, or transcripts.

## Release and executable policy

There are no release artifacts. `build.bat` creates unsigned smoke-test binaries
for local validation; `build.bat store-rc` creates a distinct clean-tree,
commit-bound onedir that is only an input to future Microsoft Store packaging.
Unsigned executables, onedir trees, and MSIX packages must not be distributed or
sideloaded.

A future release requires a completed Windows Sandbox runtime gate, passing
post-run host verification, and exact-hash static scans of the commit-bound
source archive, exported full distribution, and exported executable with
Malwarebytes and VirusTotal. Any malicious or suspicious verdict blocks release;
unsupported engines and scan failures must be recorded as non-votes rather than
hidden by repackaging the artifact.

The Store MSIX packager requires a caller-supplied Windows SDK `MakeAppx.exe`
whose SHA-256 matches an explicitly reviewed value. It copies the entire onedir
into a new preserved staging tree, generates only the manifest, identity record,
and visual assets, packages without signing, unpacks the MSIX, and compares the
manifest and Clicky subtree to staging. It never discovers a tool by newest
version, installs an SDK, signs, submits, uploads, or overwrites prior outputs.

The legal publisher decision is Manuel Parra and the developed-by brand is
th3nolo. Store mode still requires the exact Identity Name, Publisher DN, and
PublisherDisplayName copied from Partner Center Product identity. Guessed or
validation-only identities are refused for Store input. Microsoft Store
submission, certification, and signing are user-interactive gates.

Consumer Malwarebytes scanning is a manual review gate, not a cryptographically authenticated automated attestation. Record the artifact SHA-256, scanner/product version, scan time, result, and exported report or screenshot. VirusTotal reports are supplementary multi-engine evidence and may share uploaded samples with security partners; look up the hash first and upload only artifacts that are safe to disclose.

After certification, obtain the exact Store-delivered signed MSIX rather than
reusing the submitted bytes. Verify, hash, and scan that MSIX and separately
extract, hash, and scan its exact inner `Clicky.exe`. The Store package signature
does not prove that the inner executable has an Authenticode signature.

Never ask a user to bypass SmartScreen, disable antivirus, or add an exclusion.

## License

The software is provided under the MIT license without warranty. [LICENSE](LICENSE) preserves the upstream copyright and permission notice. The license terms do not replace the security limits described here.
