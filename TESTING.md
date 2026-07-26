# Testing Clicky for Windows — Hardened

Testing establishes behavior under stated conditions. It does not prove the absence of malicious code, unknown vulnerabilities, provider-side failures, or unsafe model behavior.

Use Windows x86-64, Python `3.12.10`, uv `0.11.19`, and the checked-in lock. Tests must not install packages, contact public services, access real secrets, or run the desktop application unless the manual test explicitly requires it.

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

## Manual security checks

Use synthetic screen content, test accounts, and temporary process-scoped keys. Do not expose a real password manager, private document, production account, or personal conversation during testing.

### Privacy defaults

1. Start with no existing `%LOCALAPPDATA%\Clicky\preferences.json`.
2. Launch Clicky and confirm the privacy dialog appears before microphone or hotkey capture starts.
3. Close the dialog and confirm the microphone is unopened, speech is silent, and no screenshot is taken. Restart and confirm the dialog returns.
4. Choose **Keep all disabled** and confirm all three denials persist.
5. Grant only microphone permission. Confirm microphone capture works while cloud TTS remains silent and screen capture remains blocked.
6. Grant cloud TTS using synthetic text and verify only the selected provider destination.
7. Grant screen capture while displaying synthetic content on every monitor; verify local providers keep images local and the selected cloud provider receives them only after permission.
8. Confirm **Web Search** and **Journal Logging** are off in the tray and no `journal.db` or search request appears.
9. Reopen **Privacy permissions** from the tray, revoke each permission, and confirm the capability stops immediately.
10. Simulate termination during local transcription, restart Clicky, and confirm the abandoned `%LOCALAPPDATA%\Clicky\audio-temp\clicky-audio-*.wav` is removed without touching unrelated files.

### Provider keys and preferences

1. Place a dummy marker value in one provider-key environment variable.
2. Launch in a disposable environment and close the app without making a provider request.
3. Inspect `%LOCALAPPDATA%\Clicky\preferences.json` and application logs.
4. Confirm the marker is absent.
5. Place the same marker in `.env` and confirm Clicky does not load it. Remove the file afterward.

Never perform this test with a real key.

### GitHub Copilot token storage

Use a disposable GitHub test account if an end-to-end check is required. Confirm:

- the device code appears only in the transient UI or console
- the login log does not contain the device code or token
- `github_token.dpapi` does not contain the plaintext token
- a legacy `github_token.json` is removed only after verified migration
- another Windows user cannot decrypt the DPAPI file
- logout removes encrypted token state

The automated suite exercises DPAPI with a generated non-secret value.

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
