# Testing Clicky for Windows — Hardened

Testing establishes behavior under stated conditions. It does not prove the absence of malicious code, unknown vulnerabilities, provider-side failures, or unsafe model behavior.

Use Windows x86-64, Python `3.12.10`, uv `0.11.19`, and the checked-in lock. Unit tests and static checks must not install packages, contact public services, access real secrets, or run the desktop application. The isolated Windows Sandbox gate is the explicit dynamic exception described below.

## Prepare the locked environment

~~~powershell
uv lock --check --offline --no-build --no-sources --no-python-downloads --python "3.12.10"
uv sync --frozen --group build --no-build --no-managed-python --no-python-downloads --python "3.12.10" --default-index "https://pypi.org/simple" --index-strategy first-index --keyring-provider disabled --link-mode copy --no-cache
~~~

Registry-only dependency sourcing is enforced by the checked-in `tool.uv.no-sources = true` setting. With uv 0.11.19, do not repeat `--no-sources` on a frozen sync because that flag combination is invalid.

Do not use pip or modify the environment to make a failing test pass.

## Required automated checks

### Dependency and CI policy

~~~powershell
uv run --frozen --no-sync --python "3.12.10" python tools/check_dependency_policy.py
~~~

This check validates exact dependency pins, the publication cutoff, the sole index, Windows wheel coverage, artifact hashes, the SBOM, non-installable legacy requirement files, hardened build flags, and commit-pinned GitHub Actions.

Live PyPI validation must use the reviewed CA bundle explicitly:

~~~powershell
uv run --frozen --no-sync --python "3.12.10" python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem
~~~

The bundle is `certifi/cacert.pem` extracted without execution from the already locked `certifi==2026.6.17` wheel. The wheel SHA-256 is `2227dcbaafe0d2f59279d1762ddddc37783ed4354594f194ffc31d20f41fc3db`; the tracked PEM SHA-256 is `bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0`. Its upstream license is retained beside it. The policy binds that exact wheel version, filename, size, and SHA-256 to `uv.lock`, and rejects a missing, reparse-point, oversized, altered, or invalid bundle and passes the resulting certificate-verifying, hostname-checking SSL context directly to every PyPI request. Ambient Windows roots and TLS override variables are not trusted for this gate. A network that requires a private inspection CA therefore fails closed unless that trust decision receives a separate explicit review.

### Standard-library test suite

~~~powershell
uv run --frozen --no-sync --python "3.12.10" python -m unittest discover -s tests -p "test_*.py" -v
~~~

The suite covers live dependency provenance logic, URL and IP rejection, redirect handling, connected-peer verification, bounded response reads, bundled and user skill integrity, DPAPI token storage and migration, explicit privacy permissions, private audio cleanup, complete local-model hashing, and Ollama model identity.

Network behavior is tested with fakes. A unit test must not make a live external request. Use generated dummy tokens and temporary files only.

### Parse every Python file

~~~powershell
@'
import ast
from pathlib import Path

files = sorted(Path(".").rglob("*.py"))
if not files:
    raise SystemExit("No Python source files found")
for path in files:
    ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
print(f"AST validation OK: {len(files)} Python files")
'@ | uv run --frozen --no-sync --python "3.12.10" python -
~~~

### Diff hygiene

~~~powershell
git diff --check
git status --short
~~~

Review every changed and untracked file. Confirm that generated environments, model files, tokens, databases, recordings, build output, and local preferences are absent.

## CI

`.github/workflows/dependency-policy.yml` runs on Windows Server 2022. Third-party actions are pinned to full commit hashes and checkout credentials are not persisted.

CI has two paths:

- a standard-library validation job for policy, tests, and source parsing
- a locked-build job that installs the frozen wheel-only environment, repeats tests and parsing, performs an unsigned PyInstaller smoke build, and deletes the output

The CI artifact is not a release and is not retained for distribution.

## Isolated Windows Sandbox validation

The runtime gate uses a commit-exact archive rather than mapping the Git checkout. Candidate Python and uv tools are never executed on the host. `tools/prepare-windows-sandbox.ps1` authenticates these exact inputs before use:

- CPython `3.12.10` Windows x86-64 embeddable archive from `https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip`, SHA-256 `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3`
- uv `0.11.19` Windows x86-64 executable, SHA-256 `cd628b46729d01ad110146a647a633a6e5de0e091d73db46afaeee6fcb4ba648`
- the reviewed Git for Windows executable and Authenticode signer pinned in the preparer

The Python archive may be downloaded to an untrusted staging path, but do not extract or execute it on the host. Do not substitute a Microsoft Store App Execution Alias, a different tool version, or a self-calculated replacement digest.

~~~powershell
$pythonArchive = "$env:TEMP\python-3.12.10-embed-amd64.zip"
$uvExe = "$env:USERPROFILE\.local\bin\uv.exe"
$gitExe = "C:\Program Files\Git\cmd\git.exe"
.\tools\prepare-windows-sandbox.ps1 `
  -PythonRuntimeArchive $pythonArchive `
  -UvExe $uvExe `
  -GitExe $gitExe `
  -StoreReleaseCandidate
~~~

`-StoreReleaseCandidate` is mandatory for the one release-bound build. It
records `store` in the authenticated read-only input. Omit it only for a
disposable local smoke-validation run that cannot become Store input.

The preparer refuses inherited `GIT_*` variables, executable FSMonitor configuration, replace refs, grafts, object alternates, a dirty tree, or any hook path other than the repository-local `NUL`. It verifies Git objects, runs replacement-disabled commands through the authenticated absolute Git path, archives the exact HEAD commit, and extracts the bootstrap bytes from that archive. Preparation occurs in a temporary directory and is atomically published only after every check passes.

The generated `.wsb` has exactly two mappings: a read-only input directory and a fresh writable results directory. The complete hash-pinned Python archive and uv executable are inside the input mapping; no host toolchain directory is exposed. Before launch, run the host verifier in prepared-only mode with a separately trusted Python interpreter. It independently regenerates the exact commit archive with the authenticated Git executable and rejects duplicate/overlapping mappings, reparse points, unexpected inputs, oversized files, malformed archives, or a nonempty results directory.

~~~powershell
python .\tools\verify_windows_sandbox_results.py <run-directory> `
  --prepared-only `
  --expected-commit <40-character-commit> `
  --repo-root . `
  --git-exe "C:\Program Files\Git\cmd\git.exe"
~~~

Launching the generated configuration disables vGPU, host microphone and camera input, clipboard and printer redirection, and enables Protected Client mode. Networking is a controlled exception because live PyPI provenance and an actual post-consent Edge TTS destination test require internet access. Microsoft documents that network-enabled Windows Sandbox can also reach networks available to the host. Run this gate only on a trusted or isolated network. The TTS test sends only the fixed text `Clicky synthetic privacy validation.` to `speech.platform.bing.com`; no API key or personal content is used.

The fresh results directory is the only writable host mapping. The bootstrap and host verifier enforce an exact bounded result-file allowlist and reject reparse points and oversized evidence. Windows Sandbox mapped folders do not provide a per-folder disk quota, so a compromised process could still attempt to consume free space before shutdown. Ensure adequate free space and monitor the disposable run; this is a documented residual containment limitation.

Inside the sandbox, `tools/windows-sandbox-validate.cmd` verifies the source, uv, complete Python archive, requested release mode, and exact commit before the first candidate execution; extracts the runtime and source; confirms the bootstrap is byte-identical to the archived script; validates the lock; verifies the commit-tracked CA bundle before passing it explicitly to the live PyPI provenance check; installs only frozen wheels; runs tests and compilation; and builds the unsigned PyInstaller directory. In Store mode it replaces the local-only marker with the exact reviewed Store-input marker and commit file before any packaged execution. `tools/windows_runtime_validation.py` then rejects a missing, mixed, stale, or mismatched release identity. After the runtime controls pass, the harness exports a deterministic archive of that exact unchanged distribution and an exact copy of the executable for separate host-side static scanning. The runtime harness verifies:

- source and packaged DPAPI protect/store/read behavior with synthetic data, including a second packaged process
- denied, granted, actively revoked, and re-granted microphone paths using a stateful synthetic listener while host audio input remains disabled
- denied and granted manager-controlled screen capture against a known synthetic window, plus the same capture path inside `Clicky.exe`
- captured-image labels, requested/foreground monitor selection, and physical-to-logical routing for the sandbox monitor topology
- denied cloud TTS before consent and packaged/source destination evidence after consent, restricted to the pinned Microsoft hostname with DNS-to-TCP peer correlation
- crash-abandoned WAV cleanup, a hard 24-hour privacy TTL resistant to PID reuse, and locale-independent directory/file ACL evidence
- native packaged startup, first-run privacy dialog before manager/skill construction, no external pre-consent TCP destination, embedded bundled-skill trust anchoring, and unsigned Authenticode status
- a domain-separated whole-tree digest before and after packaged execution, followed by a hash-bound deterministic export of that unchanged tree

Only `sandbox-validation.log`, `runtime-validation.json`, `Clicky-unsigned.exe`, `clicky-unsigned-onedir.zip`, the source/archive/executable identity files, and one `PASS.txt` or `FAIL.txt` marker are expected in the fresh results directory. Treat extra, oversized, non-regular, or reparse-point output as a failed containment check. The sandbox automatically shuts down after the run. After shutdown, rerun the host verifier without `--prepared-only`; it streams and validates the distribution archive without extracting or executing it. Only that post-run result is authoritative for the runtime gate.

### Post-sandbox static scan gate

The Sandbox `PASS.txt` is runtime and containment evidence, not an antivirus verdict. After the post-run host verifier succeeds:

1. Record the SHA-256 values reported for the commit-bound source archive, `clicky-unsigned-onedir.zip`, and `Clicky-unsigned.exe`.
2. In Malwarebytes, keep **Scan within archives** enabled and manually scan the full distribution archive or the fresh results directory. Save the report or a screenshot with the scanner version and time.
3. Query VirusTotal by SHA-256 first. Upload only an unknown artifact that is safe to disclose; public VirusTotal uploads may be shared with security partners.
4. Scan the standalone executable so engines that do not support ZIP archives can inspect the PE file directly. Do not repackage the source archive merely to turn unsupported-engine results into votes: repackaging changes its commit-bound hash and creates a different artifact.
5. Require zero malicious and zero suspicious verdicts. Record unsupported engines and engine failures explicitly as non-votes.

A clean static scan is additional evidence, not proof that the software is malware-free. The executable and full distribution must remain unsigned and undistributed until the release policy in `SECURITY.md` is satisfied.

### MSIX construction

Do not rebuild the onedir after the isolated runtime and exact-byte scan gates.
Record the SHA-256 of the selected Windows SDK `MakeAppx.exe`, review it, and
pass both its path and exact digest to `tools\build_msix.py`.

First exercise `--validation-only` with a new staging directory, MSIX path, and
report path. Confirm MakeAppx validation succeeds; unpacking reproduces the exact
Clicky subtree; all six PNG assets have the declared dimensions; the package has
no `AppxSignature.p7x`; and its marker says validation-only.

For Store input, obtain Package/Identity/Name, Package/Identity/Publisher, and
Package/Properties/PublisherDisplayName from Partner Center Product identity.
Pass them verbatim with `--partner-center-confirmed`. Confirm the generated report
binds the commit, complete onedir tree, inner executable, preserved staging tree,
MakeAppx executable, and unsigned MSIX.

Do not sideload or distribute the unsigned package. After Store certification,
download the exact Store-delivered MSIX, verify its package signature, then hash
and scan that exact package and its separately extracted inner `Clicky.exe`.

## Manual security checks

Use synthetic screen content, test accounts, and temporary process-scoped keys. Do not expose a real password manager, private document, production account, or personal conversation during testing.

### Privacy defaults

1. Start with no existing `%LOCALAPPDATA%\Clicky\preferences.json`.
2. Launch Clicky and confirm the privacy dialog appears before microphone or hotkey capture starts.
3. Close the dialog and confirm the microphone is unopened, speech is silent, and no screenshot is taken. Restart and confirm the dialog returns.
4. Choose **Keep all disabled** and confirm all four denials persist.
5. Grant only microphone permission. Confirm local microphone capture works while cloud STT, cloud TTS, and screen capture remain blocked.
6. Grant cloud STT separately. Confirm this permission alone sends nothing until a cloud speech mode is explicitly selected.
7. Grant cloud TTS using synthetic text and verify only the selected provider destination.
8. Grant screen capture while displaying synthetic content on every monitor; verify local providers keep images local and the selected cloud provider receives them only after permission.
9. Confirm **Web Search** and **Journal Logging** are off in the tray and no `journal.db` or search request appears.
10. Reopen **Privacy permissions** from the tray, revoke each permission, and confirm the capability stops immediately.
11. Simulate termination during local transcription, restart Clicky, and confirm the abandoned `%LOCALAPPDATA%\Clicky\audio-temp\clicky-audio-*.wav` is removed without touching unrelated files.

### Unfinished action feature gates

Launch the baseline build with fresh preferences and confirm Global Dictation,
Screen-Aware Compose, Task Agent, connector reads, connector writes, workspace
coding, and desktop automation are not exposed. Confirm the source manifest
marks every action build flag unavailable. In a test build, make only one
capability available with the current permission schema; verify it still fails
without its independent user permission and matching per-run grant. Change the
run ID, permission version, or capability ID and confirm authorization fails.
Finally, enable a persisted action permission without its current schema and
confirm startup refuses the invalid configuration rather than granting access.

### One-use screen-region selection and Tutor routing

Run the pure contract and wiring tests without screen access:

~~~powershell
python -m unittest -v tests.test_handoff_models tests.test_region_handoff_selection tests.test_region_handoff_image tests.test_region_handoff_routing tests.test_region_handoff_wiring tests.test_region_compose_context tests.test_region_compose_wiring
~~~

The locked Windows suite additionally runs `tests.test_region_handoff_ui` and
`tests.test_region_handoff_tutor`, `tests.test_region_compose_ui`,
`tests.test_compose_preview`, and the existing Compose service/insertion tests.
Confirm a fresh default-build tray menu includes **Select screen region…**.
Without the current screen-capture permission it must fail before capture.
With permission, choose Rectangle and Freehand circle separately on every
monitor, including negative-origin and mixed-DPI arrangements. Confirm the
overlay shows the frozen pre-overlay frame, consumes the drag instead of
clicking the underlying application, and accepts a shape on exactly one
monitor. Move, resize, reconnect, or rescale a display before selection and
again before review; each change must discard the capture. Escape, the
60-second timeout, a replacement push-to-talk turn, an invalid/open/crossing
lasso, capture-exclusion failure, and application shutdown must close every
overlay and wipe the transient frames.

The review must show the exact selected image, require the user to choose
Tutor context, require a purpose, and label the data as selected screen pixels.
Compose preview and New Task Agent run must not appear in the default build
because their build flags remain unavailable. Approve Tutor once and confirm
one new provider request contains only the exact reviewed JPEG and purpose,
with an empty conversation history. Confirm it does not recapture the screen,
start a task, insert text, emit a drawing action, or change desktop state.
Attempt to reuse the same intent and confirm it is rejected before a second
provider call. Revoke screen permission, change the selected bytes, expire the
intent, cancel with Escape, and stop the accepted turn; each path must fail
closed and wipe its transient bytearrays. Inspect the packaged smoke build to
confirm the four lazy region modules are present. These source/UI checks are
not live proof of provider delivery, compositor exclusion, multi-monitor DPI
behavior, cancellation timing, or pixel wiping; record those native
observations separately.

For a controlled source test build only, make Screen-Aware Compose available
with the current permission schema while leaving every other action build flag
off. Confirm Compose preview appears only after its independent user permission
and screen permission are granted. Route a synthetic region to Compose and
confirm the non-activating target picker names only application/control
metadata. It must ignore transient or blocked targets and bind only after three
identical allowed observations. Change focus, identity, policy, integrity,
desktop, provider, model, vision capability, permission, pixels, or expiry
before generation; no provider request may occur.

With a stable disposable editable field, confirm exactly one request contains
the exact reviewed JPEG and purpose, uses empty history and no tools, and
produces a non-activating draft preview naming the target application. The
region draft must disable Regenerate and require a new region selection for
another provider use. Cancel and close must change nothing. Copy may change
only the clipboard after the explicit Copy click. Insert must revalidate the
remembered field and produce at most one truthful insertion result without
sending or submitting the containing application. Exercise Escape before
target binding, while queued, during streaming, and during preview; late
provider output must not appear. Keep the default build flag off until this
passes on the representative Win32, WPF, browser, Electron, and Qt target
matrix.

### Desktop automation target, approval, and one-shot action boundary

The source-only desktop-automation implementation remains build-unavailable.
Run:

~~~powershell
python -m unittest -v tests.test_desktop_automation_policy
python -m unittest -v tests.test_desktop_automation_target_review tests.test_desktop_action_highlight
python -m unittest -v tests.test_desktop_action_broker tests.test_desktop_action_protocol tests.test_desktop_uia_actions
python -m unittest -v tests.test_desktop_automation_task_center
~~~

Confirm the model binds one target to process ID and start time, application
identity, top-level/foreground window, UIA runtime ID, control type, framework,
automation ID, bounds, supported patterns, visibility, desktop, and integrity.
Confirm raw mouse/keyboard actions do not exist, policy eligibility has no
execution method, and credential, two-factor, payment/purchase, security,
administrator, account-change, secure-desktop, destructive deletion,
elevation, protected, hidden, background, unsupported-pattern, and changed
targets fail closed. Labels used for classification must not be read from or
replaced with a control's current `ValuePattern` value. Confirm the broker
consumes one exact Task Agent approval, revalidates the still-visible review,
launches only one bounded worker, binds Escape to its job, and never retries.
The pipe protocol must reject malformed, oversized, duplicate-key,
wrong-nonce, and incorrectly authenticated responses. Every allowlisted
pattern must be invoked at most once and must expose action-specific observed
post-state. A failed postcondition cannot be success, and a post-delivery
transport failure must remain an unknown outcome.

Confirm the Task Center shows the exact reviewed target, semantic action,
desktop capability, approval ID, truthful result code, observed postcondition
when available, and verifier-evidence digest. Approval, rejection, timeout, and
cancellation must consume the live callback exactly once. A task with only
tutor, dictation, compose, pointing, response-provider, or workspace authority
must never substitute that grant for `desktop.uia.action`. Stop an approved but
queued action and confirm the worker is never launched. The integration suite
must also prove that target swapping, focus theft, disappearing controls,
misleading labels, elevation mismatch, and secure-desktop transitions end in
an explicit failure without reaching the worker.

On a disposable native Windows desktop containing only synthetic controls,
start a source test build with desktop automation still build-unavailable and
invoke the components only from the controlled validation harness. Confirm the
exact foreground control receives a named cyan, click-through highlight that
does not take focus; negative-origin and mixed-DPI monitor coordinates route
to the correct logical rectangle. Change name, runtime ID, bounds, pattern,
foreground window, desktop, or integrity and confirm revalidation clears the
highlight. Exercise each semantic pattern against disposable synthetic
controls and confirm the declared postcondition and one-call limit. Force a
post-action read failure, worker timeout, malformed receipt, stop-before-send,
and stop-after-send; confirm no automatic retry and truthful classification.
Press Escape and confirm it invalidates the run, clears the highlight,
terminates the exact worker job, invokes every registered cancellation, and
suppresses all queued callbacks. Confirm removing the one hotkey leaves
unrelated keyboard hooks untouched. Do not use real credentials, payments,
accounts, destructive controls, or personal content.

### Workspace coding threat-model gate

`WORKSPACE_CODING_SECURITY.md` selects a fresh, network-disabled Windows
Sandbox as the only V1 execution boundary. The source implements the reviewed
Git identity, isolated staging copy, typed broker, exact Sandbox configuration,
same-manifest result verification, exact diff review, and transactional
Apply/Discard contracts. It does not expose workspace coding or launch the
Sandbox in a release build.

Confirm both source-level regression suites:

~~~powershell
python -m unittest -v tests.test_workspace_coding_threat_model tests.test_workspace_coding_isolation tests.test_workspace_coding_adoption
~~~

It must prove that workspace read, write, and command remain separate
capabilities; writes and commands require action approval; the baseline build
flag remains unavailable; Codex and Qwen Code response providers receive no
workspace capability; networking and host redirections are disabled; the
original repository is never mapped; command strings and dependency
installation are unavailable; and isolated result production grants no Apply
authority. The isolation suite must additionally prove exact reviewed-Git
identity and hardened read-only inspection, pre/post staging identity checks,
dirty and untracked byte preservation without `.git`, secret/link/hardlink and
overlap rejection, no mutation of a rejected source location, exact two-mapping
Sandbox XML, one-use digest-bound broker calls, immutable command profiles,
minimal environments, no dependency install or shell, and verification
receipts bound to the exact final manifest.

The adoption suite must prove that the Task Center review is host-derived and
shows deterministic changed paths, exact text/binary identities, and
same-manifest verification evidence; `workspace.apply` is distinct and
one-use; stale original or isolated bytes prevent Apply; backups and
replacements verify before mutation; a mid-Apply failure or cancellation
restores the complete baseline and prior file protection; transaction roots
cannot overlap the original or task copy; post-Apply bytes equal the final
manifest; and Discard removes only the isolated task even after tampering.

The interactive gate must use a disposable synthetic Git repository on
a fixed local NTFS drive. It must demonstrate Sandbox-unavailable fail-closed
behavior, exact two-mapping configuration, no host profile/credential/original
repository visibility, denied path/reparse/hardlink/alternate-stream handling,
dirty and untracked baseline preservation, offline tokenized command approval,
process-tree cancellation, bounded untrusted output, and stale-original
rejection. Exercise successful multi-file Apply, forced mid-Apply rollback,
journal-cleanup failure, rollback-failure recovery, and safe Discard. Confirm
the exact reviewed source bytes remain untouched on every preflight failure and
that no repository hooks run. Do not test with real secrets or a repository
containing personal data. This live gate remains pending until the packaged
Sandbox worker and host launcher are connected; source tests and CI are not
runtime containment proof.

### Screen-Aware Compose contract

Use a test build where only Screen-Aware Compose is build-available. Grant its
action permission but not screen capture and invoke it; confirm no capture or
provider call occurs. Grant screen capture, select one to four synthetic
screens, and choose a reviewed model whose cached capabilities explicitly
include image input. Confirm capture starts only after the invocation and
contains exactly those screens. Unknown models and text-only models must fail
closed before capture.

Focus a disposable editable destination and invoke Compose. Before capture and
again before provider generation, switch the focused control, process, window,
desktop, integrity level, or target policy. Confirm the operation stops without
a provider request, destination mutation, or clipboard write. With a stable
target, confirm the provider receives only the spoken instruction, authorized
JPEGs, response language, output bound, destination control type, and selected
style-profile ID. It must receive empty history and no clipboard, documents,
web results, window title, executable identity, or unrelated Clicky state.

Return a synthetic valid draft, an oversized response, action-control syntax,
and a provider failure. Only the valid case may create a typed draft. Confirm
the draft contains text plus content-free provenance and exposes no insertion,
send, submit, click, run, or execute operation. All failure cases must leave the
destination and clipboard unchanged. These checked-in tests are source-level
contract evidence, not proof of real Windows capture or provider behavior; the
baseline build flag remains off until the later capture, preview, and
interactive Windows tasks pass.

In the preview test build, confirm the window is shown without activating or
replacing the remembered destination. It must show the draft, destination
application, writing profile, response provider, and exact character count,
with only **Insert**, **Copy**, **Regenerate**, and **Cancel** controls. Cancel,
window close, and the five-minute expiry must clear the draft and request no
action. Copy and Regenerate emit bounded requests to their separately owned
caller paths; the preview itself must not access the clipboard or provider.

Click Insert with the original disposable destination unchanged and confirm one
typed approval is emitted after a fresh target-policy observation. Attempt a
second click and confirm no second approval. Repeat after changing focus,
control identity, process, executable identity, desktop, policy, or integrity
level; Insert must become unavailable while the draft remains reviewable.

Route the typed approval to the Compose insertion service with the matching
current run grant. Confirm it performs a second target-policy observation and
uses the same insertion broker and ordered adapters as Global Dictation. One
approval may cause at most one mutation attempt, including when it is delivered
to a second service instance. Compose permission without the typed approval,
Global Dictation permission without Compose permission, a stale/revoked grant,
or the baseline hard-off build flag must cause no target query or mutation.
Unsupported Unicode insertion must remain a preview-copy result; the service
must not silently authorize clipboard fallback. Provider, target, or backend
failure must preserve the original disposable text, make no retry, and log no
draft or raw exception.

The checked-in tests prove the preview-to-broker contract with synthetic
targets and backends. They do not prove real Windows insertion, clipboard
behavior, window non-activation across Windows UI frameworks, or the complete
interactive Compose caller path. Keep the feature build-unavailable until the
representative-application matrix passes.

### Global Dictation session ownership

Use a test build where only Global Dictation is build-available, grant only its
permission, and configure a hotkey different from tutor push-to-talk. Hold the
dictation hotkey and confirm the content-free indicator shows **Listening**;
release it and confirm **Finalizing**. While either hotkey owns capture, press
the other and confirm it cannot open a second microphone recording. While
dictation is finalizing, start tutor push-to-talk and confirm the dictation
session becomes cancelled and a late final transcript cannot advance toward
insertion. Repeat with Escape during capture and finalization. Confirm no
screenshot, LLM, style profile, web, connector, read-only response-provider, or
Task Agent call occurs. The baseline flag remains off and end-to-end dictation
is not release-enabled.

### Global Dictation secure target

In a Global Dictation test build, focus an ordinary editable field in one
Win32, WPF, browser, Electron, and Qt application before pressing the dictation
hotkey. Confirm the target is accepted without the indicator or diagnostics
showing the control's contents or window title. Before commit, change focus,
window, process, or control and confirm the indicator shows **Blocked**, the
final transcript is cleared, and no insertion adapter is called.

Repeat with a password or protected field, sign-in and payment surfaces,
Windows Security and administrator tools, a disabled/read-only control, an
elevated target, and the secure desktop. Each must fail closed. Repeat after
making the UI Automation runtime ID, executable identity, foreground window,
focus, editability, or process integrity lookup unavailable; an unknown value
must never become an allowed target. The secure-target gate itself never
attempts input; it hands a lease to the separately tested insertion broker.

### Global Dictation truthful insertion

With a synthetic current commit and ordinary disposable target, confirm one
session can call at most one mutation adapter. For an explicit whole-value
replacement, expose a writable UIA ValuePattern and verify `verified_inserted`
appears only when immediate readback exactly matches the requested value.
Without that explicit intent, confirm the adapter is skipped.

For insertion at the selection, confirm Unicode `SendInput` reports
`attempted_unverified` when it succeeds and never `verified_inserted` without a
readable postcondition. Disable it and confirm clipboard paste is unavailable
until separately approved and supplied a valid Clicky-owned UI window handle.
Before paste, change the clipboard after its snapshot and again after Clicky's
temporary value; confirm Clicky neither pastes stale content nor restores over
a newer clipboard value. Exercise an unsupported control and confirm it stays
unchanged until the user chooses the one-use copy action. Reuse the commit,
race cancellation, and force each adapter to fail; no case may try a second
mutation adapter silently.

### Global Dictation end-to-end test-build matrix

The checked-in integration tests provide source-level evidence for the complete
caller path with synthetic Win32, WPF, browser, Electron, and Qt target
identities. They assert hotkey ownership, one final STT result, an immediate
target recheck, exactly one insertion, content-free telemetry, one-use recovery,
and no response-model, screenshot, or tutor-transcript call. CI passing these
tests is not live Windows compatibility proof.

For interactive proof, use a disposable Windows VM and a test build where only
Global Dictation is build-available. Use a synthetic phrase that contains no
personal or account data. In each row below, focus a disposable ordinary text
control before pressing the dictation hotkey:

| Surface | Disposable target | Required evidence |
| --- | --- | --- |
| Win32 | Notepad document | One insertion; result is `attempted_unverified` unless an exact readable postcondition is available |
| WPF | Local test app text box | One insertion; no focus redirection |
| Browser | Empty local `about:blank` editable field | One insertion; no page or browser metadata in the result |
| Electron | Empty disposable editor | One insertion; no application-specific fallback |
| Qt | Empty local test text control | One insertion; Clicky result windows remain excluded from capture |

For every row, repeat these adversarial transitions before release and before
the final commit: move focus to another field, switch applications, close the
target, elevate the target, and open a password, payment, sign-in, or protected
field. Expected result is **Not inserted** with zero input events in the new
destination. Exercise Escape and immediate dictation/tutor replacement during
capture, STT finalization, and insertion; stale results must not appear over the
new run.

Finally, disable Unicode input in the test harness. Confirm no clipboard write
occurs automatically. Choose **Retry as safe preview**, confirm text becomes
visible only then, dismiss it, and verify it is cleared. Repeat and choose
**Copy**; verify one clipboard write through a Clicky-owned HWND and that a
second click cannot reuse the recovery token. This live matrix, including
screen recordings or content-free logs with run ID, STT provider, application,
status, adapter, and result code, remains required before changing the baseline
build flag.

### Live speech-to-text

Use a test Deepgram account and synthetic spoken phrases. Grant microphone and cloud-STT permissions, then choose **Setup & Diagnostics → Speech input → Deepgram Nova-2 — live streaming**. Verify partial text appears while the hotkey is still held and network capture shows bounded binary audio frames before release, followed by the explicit finalization messages. Release and confirm one final transcript is used for the turn without a batch transcription POST.

Interrupt live finalization with a new push-to-talk turn and verify the first WebSocket closes, its late partial/final messages never appear, and exactly one replacement capture owns the microphone. Exercise provider rejection, disconnect, connection/finalization timeout, and queue saturation; each must show an error without reconnecting or selecting another provider. Finally choose a labeled local-batch mode and confirm it performs no cloud-STT request.

### Approved transcription vocabulary

Open **Setup & Diagnostics → Transcription vocabulary**, enter a distinctive
synthetic term, and save. Confirm the Deepgram live WebSocket and Deepgram batch
request contain the shipped `Clicky` term plus the approved term exactly once.
Confirm the OpenAI batch request contains the same bounded vocabulary in its
`prompt` field. Verify both local STT modes receive no vocabulary input.

Try more than 63 terms, a term longer than 64 characters, and control characters;
confirm saving fails explicitly. Put distinctive synthetic text in a window
title, screenshot, clipboard, attached document, and prior conversation without
adding it in the editor. Confirm none of those values appears in any STT request.

### Push-to-talk cancellation

While Clicky is thinking and again while it is speaking, press and hold the push-to-talk shortcut. Confirm the prior generation and audio stop, exactly one new capture enters Listening, rapid release/repress remains responsive, and no text, drawing, point, error, or Idle state from the cancelled turn appears afterward.

### Login startup

Confirm the classic installer reference leaves its per-user startup task
unchecked and that a freshly installed MSIX reports `ClickyStartup` as disabled.
Use **Windows startup settings…** from the tray and confirm it opens Windows
Startup Apps without changing the setting. Enable and disable Clicky there,
sign out and back in to verify both states, then uninstall and confirm no Clicky
startup entry or shortcut remains.

### Clicky-owned window capture exclusion

In the isolated Windows runtime, show a synthetic Clicky top-level window and overlay containing a distinctive magenta block that is absent from the synthetic desktop. Capture through the LLM screenshot path, OCR fallback, and lesson-recorder frame path; confirm the magenta pixels are absent while ordinary desktop test pixels remain. Force `SetWindowDisplayAffinity` failure and repeat through the hide/capture/restore fallback. Also force capture, compositor-flush, and restoration failures and confirm capture aborts while every previously visible Clicky window regains its placement and visibility.

### Monitor identity and mixed DPI

Use four disposable displays at 100%, 125%, 150%, and 200%, including one
portrait display and at least one negative virtual-desktop origin. Put the
foreground test window on each display in turn. Confirm an unqualified request
selects that window's display, an explicit “screen N” request selects only the
named display, every attached image has the matching screen label, and points,
OCR boxes, figure boxes, and lesson frames remain on that display.

Reorder the displays and restart Clicky. Confirm hardware-backed stable IDs remain
attached to the same physical panels even if `DISPLAYN` numbers change. During a
capture, disconnect or rearrange a display and confirm the operation aborts
explicitly without drawing or clicking on another display.

### Provider keys and preferences

1. Place a dummy marker value in one provider-key environment variable.
2. Launch in a disposable environment and close the app without making a provider request.
3. Inspect `%LOCALAPPDATA%\Clicky\preferences.json` and application logs.
4. Confirm the marker is absent.
5. Place the same marker in `.env` and confirm Clicky does not load it. Remove
   the file afterward.

Never perform this test with a real key.

### Per-provider model restoration

Choose distinct models for two or more providers, restart Clicky, and switch
between them. Confirm each provider restores only its own exact saved ID. Replace
one cached model list with a list that omits its saved ID and includes the
reviewed low-cost fallback; confirm the panel and tray visibly report the
fallback before a request is sent.

Repeat with a model list containing only higher-cost or unknown-cost choices.
Confirm no model is selected automatically and Clicky blocks the request until
the user makes an explicit choice. For Copilot, confirm automatic fallback occurs
only when the selected record reports multiplier zero.

Repeat with Kimi Code, MiniMax Token Plan, DeepSeek, Qwen standard, the Codex
read-only response provider, and the Qwen Code read-only response provider.
Confirm preferences remain separate. Kimi, MiniMax, and DeepSeek may use only
their reviewed safe aliases automatically; Qwen standard and Qwen Code must
visibly require a selection when no saved model is valid. Select a text-only
model and confirm Clicky sends no screenshot bytes while showing the no-vision
label.

### Read-only response-provider CLI boundary

In a disposable Windows account with synthetic prompts:

1. Leave read-only response-provider permission disabled and confirm neither
   provider appears in the menu and no `codex` or `qwen` process starts.
2. Grant the permission without selecting a provider; again confirm no process
   starts.
3. Select **Codex — read-only response provider** and submit a synthetic turn.
   Confirm the command uses an ephemeral run, ignored user config/rules,
   read-only sandbox, a temporary working directory, and stdin for the prompt.
4. Confirm the UI and permission text state that this is not a Task Agent and
   cannot edit files, run tools, or perform external actions through Clicky.
5. Interrupt the turn and confirm the owned provider process exits and no late
   response reaches the UI.
6. Select **Qwen Code — read-only response provider** with a synthetic Coding
   Plan key in a test account. Confirm the child environment contains only the
   fixed international plan endpoint, plan key, and selected allowlisted
   model—not unrelated provider secrets.
7. Confirm temporary screenshot files are absent after success, failure,
   timeout, and interruption.

### Google Calendar availability connector

Use a disposable Google test account and synthetic calendars only. In a test
build with Task Agent and connector-read availability explicitly enabled:

1. Connect only the Google Calendar read capability and confirm consent shows
   the FreeBusy scope, not general Calendar event access.
2. Start a task with the exact Calendar read grant and select one or more
   synthetic calendar IDs plus a bounded UTC range of at most 31 days.
3. Confirm the provider request uses only the fixed Calendar FreeBusy endpoint,
   and the result contains only selected calendar IDs and busy start/end
   intervals. It must not contain titles, descriptions, locations, attendees,
   conferencing data, or unrelated calendars.
4. Remove the run grant, change the run ID, account authorization ID, selected
   calendar list, request digest, or response range in turn. Each change must
   fail before a provider request or token lease.
5. Expire the memory-only access token and confirm the account broker refreshes
   it from the DPAPI-protected refresh token without exposing either token in a
   task result, diagnostic record, prompt, or UI.
6. Revoke or disconnect the account and confirm subsequent reads produce the
   explicit connector error without a provider retry.
7. Exercise a 401, 403, 429, timeout, oversized body, non-JSON body, calendar
   error, unselected-calendar response, and event-body-shaped response. Confirm
   every case fails closed and provider response content is not recorded.
8. Confirm successful Task Center evidence retains only the output digest,
   provider response digest and size, and a bounded provider request ID.

The checked-in tests use synthetic transports and accounts. They do not prove
live Google consent, network behavior, or the interactive Windows caller path.
Keep connector reads build-unavailable in the baseline until those checks pass.

### Gmail selected-thread read and verified draft

Use a disposable Google test account containing only synthetic mail. In a test
build with Task Agent plus the relevant connector feature explicitly enabled:

1. Connect `gmail.message.read` alone and confirm consent requests only
   `gmail.readonly`. Supply one exact synthetic thread ID; confirm Clicky calls
   only `users.me.threads.get` with `format=full`, returns that thread's bounded
   headers and text bodies, and omits attachments, unselected headers, mailbox
   search results, and every other thread.
2. Change the thread ID, run ID, account authorization ID, capability, or
   argument digest. Confirm each mismatch fails before a token lease or request.
3. Connect `gmail.draft.write` and confirm consent requests `gmail.compose`,
   not `gmail.send`. Review the complete To/Cc/Bcc, subject, and plain-text body
   preview, then approve exactly once.
4. Confirm Clicky calls only `users.me.drafts.create`, never a message or draft
   send endpoint, then performs one `users.me.drafts.get?format=raw` read-back.
   The task succeeds only when the provider IDs and exact approved recipients,
   subject, and body match.
5. Reject or expire approval and confirm no draft is created. Change any
   approved field or reuse the call ID and confirm the write is rejected before
   provider access.
6. Simulate an ambiguous create timeout and confirm Clicky reports
   `connector_write_outcome_unknown` without retrying. Simulate a mismatched or
   unavailable read-back and confirm it reports `connector_write_unverified`;
   do not claim the draft was absent or retry automatically.
7. Exercise 401, 403, 404, 429, timeout, oversized body, non-JSON body, malformed
   MIME, attachment-only content, and provider identity mismatches. Confirm all
   fail closed without tokens or message bodies in diagnostics.
8. Confirm Task Center retains only bounded result/provider digests, byte
   counts, provider request ID, and verified draft identifiers. The approved
   body must not be persisted as task evidence.

The checked-in tests use synthetic transports and accounts. They do not prove
live Google consent, Gmail API behavior, or the interactive Windows caller
path. Keep Gmail read/write build-unavailable in the baseline until those
checks pass. Gmail sending intentionally remains outside the capability
registry and first release.

### Notion selected-page read and local draft

Notion public OAuth requires a confidential client secret for token exchange
and refresh. Do not place that secret in the desktop application, package,
environment, or preferences. Live account connection remains unavailable until
a reviewed confidential authorization broker and user-controlled Notion
registration exist.

After that external gate is available, use a disposable workspace containing
only synthetic pages. In a test build with Task Agent and connector reads
explicitly enabled:

1. Use the Notion authorization page picker to share only the synthetic parent
   page. Confirm the consent capability is read content only for the read test.
2. Supply one exact canonical page ID. Confirm Clicky calls only the fixed
   `api.notion.com/v1/pages/{page_id}` and
   `api.notion.com/v1/blocks/{block_id}/children` endpoints with
   `Notion-Version: 2026-03-11`.
3. Confirm recursion consumes at most 16 provider requests, treats cursors as
   opaque, and sets `content_truncated=true` whenever pagination, nested
   children, block count, depth, or text cannot be completed within the bound.
4. Confirm the result contains only the selected page ID/title plus bounded
   plain block text and structure. It must omit search results, comments,
   people/email properties, unrelated database properties, file/media URLs,
   signed URLs, and unselected pages.
5. Change the selected page ID, run ID, authorization ID, capability, or
   argument digest. Confirm each mismatch fails before a token lease or
   provider request. A task with fewer than 16 remaining network requests must
   also fail before provider access.
6. Exercise 401, 403, 404, 409, 429, timeout, redirect, oversized body,
   non-JSON body, duplicate block ID, malformed cursor, and provider identity
   mismatch. Confirm each case fails closed with content-free diagnostics.
7. Render a local draft from bounded title and block JSON. Confirm the artifact
   says `state=local_unpublished` and `publication_authorized=false`, contains
   no token or endpoint, and performs no connector call.
8. Confirm there is no Notion create/append/update/archive/publish endpoint or
   brokered `notion.page.write` route in this release. Saving the inert JSON
   artifact may use the existing local-artifact approval; publishing requires a
   future, separate exact-target approval and provider read-back.

The checked-in tests use synthetic transports and accounts. They prove source,
quota, parsing, packaging, and broker boundaries, not a live Notion consent
flow or interactive Windows behavior. Keep Notion connector reads
build-unavailable until the confidential broker and this matrix pass.

### Google Sheets verified-table export

Use a disposable Google account and a previously adopted synthetic research
CSV. In a test build with Task Agent and connector writes explicitly enabled:

1. Connect only `google_sheets.values.write`. Confirm consent requests the
   per-file `drive.file` scope, not full Drive or broad spreadsheet access.
2. Select the adopted CSV by opaque artifact ID. Confirm the broker reopens
   the protected artifact, matches its recorded size and SHA-256, requires
   adoption/verifier evidence, and independently reparses a non-empty,
   rectangular UTF-8 table before offering approval.
3. Confirm the approval shows the destination account authorization, exact
   title, data-row count, every column name, source size, and source SHA-256.
   The raw idempotency key and table cells must not be exposed in task evidence.
4. Approve once. Confirm the Drive lookup is limited to the app-private
   `clickyExportId` property, spreadsheet MIME type, non-trashed files, and the
   `drive.file` visibility boundary. Creation must set
   `ignoreDefaultVisibility=true` and no sharing permission.
5. Confirm values are written only to the derived `A1` range with
   `valueInputOption=RAW`; leading `=`, `+`, `-`, and `@` strings must remain
   literal data rather than formulas.
6. Confirm success requires a bounded metadata read-back with the exact
   spreadsheet ID, title, HTTPS Google Sheets URL, one grid sheet, sufficient
   row/column capacity, and an exact value read-back of the approved table.
7. Repeat the same operation key. An exact existing export must be returned
   without a second write. An empty file left by an ambiguous create may be
   completed once. A different request digest, title, source digest, duplicate
   match, pre-existing different values, or altered metadata must fail as an
   idempotency conflict without overwriting content.
8. Reject or expire approval, alter the artifact bytes, change the account,
   run, capability, source digest, title, or operation key, or provide fewer
   than six remaining network calls. Confirm every case fails before the
   connector mutation.
9. Exercise 401, 403, 429, timeout, redirect, oversized/non-JSON response,
   ambiguous create/update, malformed metadata, invalid URL, wrong row/column
   counts, and mismatched values. Confirm no automatic create retry and no
   success claim without exact read-back.

The checked-in tests use synthetic accounts, adopted files, and transports.
They prove source, approval, quota, idempotency, fixed-endpoint, parsing,
packaging, and read-back contracts. They do not prove live Google OAuth,
Drive/Sheets behavior, the interactive Task Center flow, or a real Windows
package. Keep Sheets export build-unavailable in the baseline until those
interactive checks pass.

### Google Slides verified-presentation export

Use a disposable Google account and a previously adopted synthetic JSON
presentation specification. In a test build with Task Agent and connector
writes explicitly enabled:

1. Connect only `google_slides.presentation.write`. Confirm consent requests
   the per-file `drive.file` scope, not full Drive access.
2. Select the adopted JSON by opaque artifact ID. Confirm the broker reopens
   the protected artifact, matches its recorded size and SHA-256, requires
   adoption/verifier evidence, and independently reparses the strict schema:
   version 1, one presentation title, and 1–10 title/body text slides.
3. Confirm approval shows the selected account authorization, exact
   presentation title, every slide title and complete body text, slide count,
   source size, and source SHA-256. The raw idempotency key must not appear.
4. Approve once. Confirm Drive lookup is limited to the app-private
   `clickySlidesExportId` property, Google presentation MIME type, non-trashed
   files, and the `drive.file` visibility boundary. Creation must set
   `ignoreDefaultVisibility=true` and must not create a sharing permission.
5. Confirm the single Slides batch uses only deterministic blank slides,
   text-box shapes, title/body text insertion, and at most deletion of the one
   initial blank slide. Images, videos, charts, links, notes, comments,
   publishing, sharing, and arbitrary presentation IDs must remain unavailable.
6. Confirm success requires bounded Drive metadata and Slides presentation
   reads with the exact file ID, title, HTTPS Google presentation URL,
   app-property binding, slide IDs, text-box IDs, slide order, and complete
   approved title/body text.
7. Repeat the same operation key. An exact existing presentation must return
   without another batch update. A completely empty file left by an ambiguous
   create may be populated once. A different request/source digest, title,
   duplicate match, pre-existing slide content, altered metadata, or invalid URL
   must fail as a conflict or unverified result without overwriting content.
8. Reject or expire approval, alter the source artifact, change the account,
   run, capability, source digest, or operation key, or provide fewer than six
   remaining network calls. Confirm every case fails before mutation.
9. Exercise 401, 403, 429, timeout, redirect, oversized/non-JSON response,
   ambiguous create/batch update, malformed Drive metadata, invalid URL,
   malformed batch replies, and mismatched final text. Confirm no automatic
   mutation retry and no completion claim without exact read-back.

The checked-in tests use synthetic accounts, adopted files, and transports.
They prove source, approval, quota, idempotency, fixed-endpoint, text-only,
packaging, and read-back contracts. They do not prove live Google OAuth,
Drive/Slides behavior, the interactive Task Center flow, or a packaged Windows
application. Keep Slides export build-unavailable in the baseline until those
interactive checks pass.

### GitHub Copilot token storage

Use a disposable GitHub test account if an end-to-end check is required. Confirm:

- the device code appears only in the transient UI or console
- the login log does not contain the device code or token
- `github_token.dpapi` does not contain the plaintext token
- a legacy `github_token.json` is removed only after verified migration
- another Windows user cannot decrypt the DPAPI file
- logout removes encrypted token state

The automated suite exercises DPAPI with a generated non-secret value.

The reusable DPAPI tests also enforce plaintext, ciphertext, entropy, and file
deletion limits; reject non-Windows use before a native call; and verify that a
wrong application context or damaged ciphertext raises a content-free
corrupt-or-foreign-user error. In a disposable second Windows account, copy a
synthetic protected blob created by the first account and confirm
`decrypt_current_user` raises that same explicit error. This cross-account
check remains interactive because CI has only one Windows user context.

### Writing-style profile storage

With a fresh `%LOCALAPPDATA%`, listing or exporting writing-style profiles must
return an empty collection without creating `style_profiles.db`. Create one
synthetic Work profile and one synthetic Personal profile manually. Inspect the
database and confirm that only IDs, timestamps, enabled state, payload version,
and ciphertext are present; names, rules, examples, and executable identities
must not appear as plaintext bytes.

Confirm create, inspect, update, disable, re-enable, delete, single
export/import, and complete export/import preserve stable IDs and timestamps.
Disabled or deleted profiles must not appear in the prompt-facing lookup. A
profile scoped to the Work executable identity must not appear for the
Personal identity, and vice versa; an explicitly unscoped profile may appear
for both. Corrupt ciphertext, unknown schema versions, symlinked databases,
oversized values, duplicate records, and DPAPI failures must fail closed
without partial rows or content-bearing diagnostics. Export returns plaintext
only to its explicit caller and never writes a file on its own.

### Region-handoff contracts

Run `python -m unittest -v tests.test_handoff_models`. The contract suite uses
synthetic mixed-DPI monitors with negative origins and proves that zero-area,
oversized, off-monitor, expired, cross-generation, changed-topology, changed-
DPI, and invalid-mask selections fail closed. It also proves that screenshot
bytes and OCR text are not contract fields, focus cannot infer a destination,
and Compose or new-Task destinations expose only their existing required
capability identifiers.

This is source-only evidence. Do not report a selection UI, capture, provider
handoff, or Task Agent handoff as available until the later overlay and routing
tasks are wired and validated on native Windows.

### Web search

Keep web search disabled for the baseline. After explicit activation with synthetic queries, confirm that ordinary public HTTPS results can be processed. Do not weaken a rejection to make an HTTP, private-address, redirect, unexpected-content-type, missing-peer, or oversized-response case pass. Those cases belong in the offline tests.

Environment proxy variables are intentionally ignored. Corporate proxy or split-DNS failure is expected unless a separately reviewed design changes that boundary.

### User skills

1. Create a harmless test skill in a temporary `~/.clicky/skills` directory.
2. Confirm it does not execute without `allowlist.json`.
3. Add an incorrect digest and confirm it remains disabled.
4. Calculate its SHA-256, add the exact filename and digest, and confirm it loads.
5. Change one byte and confirm it becomes disabled again.
6. Confirm bundled skills still load.

Do not test with code that launches a process, changes system state, or accesses user data.

### Local speech model identity

Use small generated fixture files for unit tests. For an approved real-model smoke test:

1. Provision the model separately.
2. For whisper.cpp, hash the selected file. For faster-whisper, compute the whole-directory digest with `python -m audio.stt.local_models <directory>`.
3. Confirm the configured model loads only with the matching digest.
4. Change each required faster-whisper file in turn, then add an extra file, and confirm every change invalidates the digest.
5. Change the expected digest and confirm loading fails.
6. Remove or duplicate the cached candidate and confirm resolution fails closed.
7. Monitor network activity and confirm Clicky does not download a replacement.

### Ollama identity and process behavior

Use an already-installed local Ollama service and non-sensitive prompts.

1. Confirm Clicky does not install or start Ollama.
2. Confirm Clicky does not pull a model.
3. Run the read-only status command and record the exact local tag and digest.
4. Configure both text and vision digests.
5. Confirm the matching models are accepted.
6. Change either digest and confirm the provider refuses the model.
7. Stop Ollama and confirm Clicky reports the unavailable service without starting it.

### Unsupported features

Confirm the locked environment contains neither `pynput` nor `langdetect`. Workflow capture should report that it is unavailable. Non-Latin Unicode script detection may work, but Latin-language auto-detection must not be reported as supported.

## Local packaging smoke test

~~~bat
build.bat
~~~

Confirm:

- the script refuses the wrong Python or uv version
- existing `build\` or `dist\` directories stop the build
- the output includes `SHA256SUMS.txt`, `sbom.cdx.json`, `uv.lock`, the MIT license, and `UNSIGNED-LOCAL-TEST-ONLY.txt`
- the temporary build environment is removed
- `build.bat installer` fails immediately and no `Setup-Clicky.exe` is created
- no model, token, journal, recording, or local preference is bundled

The output is unsigned and must remain local.

## Future signed-release checks

There are no releases yet. Before a future artifact is distributed:

- verify Authenticode signatures and timestamps on `Clicky.exe` and the installer
- compare final SHA-256 values through an independent channel
- inspect the final SBOM and source commit
- scan the exact final bytes with current security tools
- install in a disposable Windows VM with no secrets
- test install, launch, data paths, uninstall, and cleanup

Do not bypass SmartScreen or antivirus during testing. A warning or detection is a failed release gate until investigated.

## Completion criteria

A change is ready for review when all applicable automated checks pass, manual results identify their environment and inputs, no secret or generated artifact is present, and remaining limitations are documented. This does not mean the application is completely safe.
