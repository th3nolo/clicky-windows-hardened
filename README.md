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
- Screen capture, multi-monitor coordinate mapping, and a click-through PyQt overlay.
- Pointing and drawing instructions produced by supported vision models.
- Cloud LLM support for Anthropic, OpenAI, Gemini, and GitHub Copilot.
- Local LLM support through an already-installed Ollama or LM Studio server.
- Local or cloud speech-to-text and text-to-speech providers.
- Optional document context, OCR, lesson recording, per-app conversation history, and quiz mode.
- Optional web search and a local learning journal. Both are off by default.

The application does not provide a fully offline guarantee. Cloud AI providers receive the data needed for the selected request. Edge TTS and web search also require network access. Microphone, cloud text-to-speech, and screen capture each remain disabled until the first-run privacy dialog records an explicit choice.

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
- GitHub Copilot OAuth tokens are encrypted for the current Windows user with DPAPI.
- Non-secret preferences are allowlisted and stored in `%LOCALAPPDATA%\Clicky\preferences.json`.
- Microphone access, cloud text-to-speech, and screen capture require independent persisted permission.
- Journal logging and web search are disabled until the user enables them in the tray.

### Network requests

Web search accepts HTTPS destinations only. It rejects local, private, link-local, reserved, multicast, and unspecified IP addresses before connecting, repeats the check for every redirect, and verifies the actual connected socket peer. Response types, redirects, and decoded byte counts are bounded. Environment proxies are not used.

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
$env:DEEPGRAM_API_KEY = "..."
$env:ELEVENLABS_API_KEY = "..."
$env:TAVILY_API_KEY = "..."
~~~

Do not place keys in this repository or in a sidecar configuration file. GitHub Copilot uses the tray device-login flow and stores its resulting token with DPAPI.

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

`build.bat` creates an unsigned local smoke-test artifact from the frozen lock. It also records the executable SHA-256 and exports a CycloneDX SBOM.

Unsigned executables and installers must not be distributed. Authenticode signing and verification are release gates, and no release artifacts exist yet. Never instruct a recipient to bypass SmartScreen or add an antivirus exclusion. See [BUILD.md](BUILD.md).

## Documentation

- [SETUP.md](SETUP.md): reviewed local setup and model provisioning
- [BUILD.md](BUILD.md): frozen build and signing gates
- [TESTING.md](TESTING.md): automated and manual verification
- [SECURITY.md](SECURITY.md): reporting and security boundaries
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution requirements

## Credits and license

The original Windows implementation is [Bitshank-2338/clicky-windows](https://github.com/Bitshank-2338/clicky-windows), based on the Clicky concept by [farzaa/clicky](https://github.com/farzaa/clicky).

Licensed under MIT. The preserved upstream notice is in [LICENSE](LICENSE).
