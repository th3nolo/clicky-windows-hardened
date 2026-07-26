# Clicky for Windows — Hardened setup

This guide prepares the reviewed Windows environment. It does not install or run dependencies automatically.

## Requirements

Use only:

- Windows 10 or 11, x86-64
- CPython `3.12.10`
- uv `0.11.19`
- Git for Windows

Obtain the exact Python and uv releases from their official projects. Verify the downloaded installer or archive before running it. Do not substitute a newer version.

## Clone the independent derivative

~~~powershell
git clone https://github.com/th3nolo/clicky-windows-hardened.git
Set-Location clicky-windows-hardened
~~~

This repository derives from [Bitshank-2338/clicky-windows](https://github.com/Bitshank-2338/clicky-windows) source commit `09208d88740db7ba593eb6b95085b63e92a59772`. It is independent and is not an upstream or official release.

## Verify the toolchain

~~~powershell
python --version
uv --version
~~~

The output must be `Python 3.12.10` and `uv 0.11.19`. Stop if either version differs.

## Verify and create the frozen environment

First verify that the checked-in lock matches the project without contacting a package index:

~~~powershell
uv lock --check --offline --no-build --no-sources --no-python-downloads --python "3.12.10"
~~~

Then create the environment from the frozen lock:

~~~powershell
uv sync --frozen --group build --no-build --no-managed-python --no-python-downloads --python "3.12.10" --default-index "https://pypi.org/simple" --index-strategy first-index --keyring-provider disabled --link-mode copy --no-cache
~~~

Registry-only dependency sourcing is enforced by the checked-in `tool.uv.no-sources = true` setting. With uv 0.11.19, do not repeat `--no-sources` on a frozen sync because that flag combination is invalid.

This command refuses source builds and unmanaged Python downloads. Do not use pip, requirement files, editable installs, Git dependencies, or upgrade flags.

## Provider keys

Clicky does not read `.env` or `.env.local`. The example file is informational and is not loaded. Set provider keys only in the PowerShell process that launches Clicky:

~~~powershell
$env:ANTHROPIC_API_KEY = "..."
$env:OPENAI_API_KEY = "..."
$env:GOOGLE_API_KEY = "..."
$env:DEEPGRAM_API_KEY = "..."
$env:ELEVENLABS_API_KEY = "..."
$env:TAVILY_API_KEY = "..."
~~~

Set only the keys you use. Closing that PowerShell session removes these process-scoped values. Do not commit keys or place them in project files.

Non-secret choices are saved in `%LOCALAPPDATA%\Clicky\preferences.json`. The application accepts only its allowlisted preference keys.

## GitHub Copilot

Use **Tray → Model → Sign in to GitHub Copilot**. The device code is shown transiently and is not written to the login log. The resulting OAuth token is stored at:

~~~text
%LOCALAPPDATA%\Clicky\github_token.dpapi
~~~

The token is encrypted with Windows DPAPI for the current user. A legacy plaintext `github_token.json` is migrated only after the encrypted value is verified, then removal is attempted. DPAPI-protected files do not work under another Windows user.

## Local Ollama models

Clicky never downloads, installs, starts, or pulls Ollama or a model. If local Ollama is required:

1. Obtain Ollama separately from its official Windows distribution. Verify its Authenticode signature before installation.
2. Start Ollama yourself.
3. Provision the chosen text and vision models yourself. A manual `ollama pull <model>` is outside Clicky.
4. Inspect the installed tags and full digests:

~~~powershell
uv run --frozen --no-sync --python "3.12.10" python -m ai.ollama_bootstrap status
~~~

5. Select the exact installed model tags in the tray.
6. Set both expected 64-hex digests in the launch process:

~~~powershell
$env:OLLAMA_TEXT_MODEL_DIGEST = "<64 hexadecimal characters>"
$env:OLLAMA_VISION_MODEL_DIGEST = "<64 hexadecimal characters>"
~~~

The Ollama provider refuses a mutable tag whose current digest does not match. Re-check and review a model before accepting a changed digest.

## Local speech models

Speech models must be provisioned separately. Clicky does not contact a model hub to acquire them.

For whisper.cpp, point to one reviewed GGML or GGUF file and configure its hash:

~~~powershell
$env:WHISPERCPP_MODEL = "C:\Models\whisper\ggml-base.bin"
$env:WHISPERCPP_MODEL_SHA256 = (Get-FileHash -Algorithm SHA256 $env:WHISPERCPP_MODEL).Hash.ToLowerInvariant()
~~~

For faster-whisper, the configured directory must contain `config.json`, `model.bin`, and `tokenizer.json`. Clicky hashes every regular file, its relative path, and its size into one deterministic directory digest. Review the directory first, ensure it contains no symlinks, then compute the exact value with the pinned interpreter:

~~~powershell
$modelDir = "C:\Models\faster-whisper-base"
$env:WHISPER_MODEL_SHA256 = (& uv run --frozen --no-sync --python "3.12.10" python -m audio.stt.local_models $modelDir).Trim()
~~~

The complete model directory or reviewed cache snapshot must match the selected `whisper_model` preference. Adding, removing, renaming, or changing any file invalidates the digest.

Wake-word recognition is optional. Push-to-talk still works when it is unavailable. To enable it, provide and hash a separate complete faster-whisper directory:

~~~powershell
$env:CLICKY_WAKE_MODEL = "C:\Models\faster-whisper-tiny-en"
$env:CLICKY_WAKE_MODEL_SHA256 = (& uv run --frozen --no-sync --python "3.12.10" python -m audio.stt.local_models $env:CLICKY_WAKE_MODEL).Trim()
~~~

A missing or mismatched digest disables that local model instead of downloading a replacement.

## Privacy defaults

On first launch, microphone access, cloud text-to-speech, and screen capture are independent unchecked permissions. Closing the dialog grants nothing. Choosing **Keep all disabled** records an intentional denial; reopen it through **Tray → Setup & Diagnostics → Privacy permissions**.

- Microphone permission allows the continuous local wake-word stream and push-to-talk capture.
- Cloud TTS permission sends assistant response text to Microsoft Edge TTS, OpenAI, or ElevenLabs, depending on the selected provider.
- Screen permission captures every monitor. Images stay local with Ollama or LM Studio and are sent to the selected cloud AI provider otherwise. The window-title Privacy Guard is heuristic only.
- Temporary WAV files use a private per-user directory and are removed after use; a startup sweep removes crash leftovers from terminated processes.

Web search and journal logging also start off. Enable either feature explicitly from the tray only after reviewing its data flow.

- Web search sends the search text to DuckDuckGo or Tavily and fetches public result pages.
- Journal logging stores question, answer, active application, and window-title context in `%LOCALAPPDATA%\Clicky\journal.db`.

Cloud providers receive the request data described above. Use synthetic test content until provider behavior and account settings have been reviewed.

## Run from source

~~~powershell
uv run --frozen --no-sync --python "3.12.10" python main.py
~~~

Clicky does not start Ollama or download a missing model. A failed model-integrity check is a setup error, not a prompt to disable verification.

## Unsupported optional features

The locked environment excludes `pynput` and `langdetect` because their dependency chains do not meet the wheel-only policy. Workflow capture is unavailable. Non-Latin Unicode script detection remains, but Latin-language auto-detection is unavailable.

Do not add these packages manually. Any addition requires a reviewed exact pin, a new lock, wheel evidence, and the project’s 72-hour publication-age rule.
