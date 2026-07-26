# Building Clicky for Windows — Hardened

The build is reviewed for Windows x86-64 with Python `3.12.10` and uv `0.11.19` only. It produces unsigned local test artifacts. There are no releases yet.

Unsigned executables and installers must not be distributed. A release requires Authenticode signing and verification of both the installed application executable and the outer installer.

## Build inputs

- a clean checkout of this repository
- Python `3.12.10` on `PATH`
- uv `0.11.19` on `PATH`
- checked-in `pyproject.toml` and `uv.lock`
- no existing `build\` or `dist\` directory

The supported build entry point is `build.bat`. Do not run PyInstaller directly for a release candidate and do not use pip.

## Frozen wheel-only build

Run from a normal, non-administrator PowerShell or Command Prompt:

~~~bat
build.bat
~~~

The script performs these operations:

1. Requires uv `0.11.19` and Python `3.12.10`.
2. Clears inherited package-index and installer overrides.
3. Verifies the lock offline with:

~~~bat
uv lock --check --offline --no-build --no-sources --no-python-downloads --python "3.12.10"
~~~

4. Creates a new temporary environment with:

~~~bat
uv sync --frozen --group build --no-build --no-managed-python --no-python-downloads --python "3.12.10" --default-index "https://pypi.org/simple" --index-strategy first-index --keyring-provider disabled --link-mode copy --no-cache
~~~

Registry-only dependency sourcing is enforced by the checked-in `tool.uv.no-sources = true` setting. With uv 0.11.19, do not repeat `--no-sources` on a frozen sync because that flag combination is invalid.

5. Generates the icon and runs PyInstaller from that frozen environment.
6. Copies the MIT notice and dependency evidence.
7. Exports a CycloneDX 1.5 SBOM.
8. Records the SHA-256 of `Clicky.exe`.
9. Deletes the temporary build environment on exit.

The output is:

~~~text
dist\Clicky\Clicky.exe
dist\Clicky\SHA256SUMS.txt
dist\Clicky\sbom.cdx.json
dist\Clicky\UNSIGNED-LOCAL-TEST-ONLY.txt
~~~

The marker file states that the portable output is unsigned, local-test-only, and not distributable. Keep the entire artifact local.

## Why the build is wheel-only

`pyproject.toml` uses exact dependency versions, a single PyPI index, `no-build = true`, `no-sources = true`, and a 64-bit Windows required environment. The lock contains SHA-256 artifact hashes. The dependency-policy test rejects dependencies without locked wheels and rejects Git, path, editable, and unreviewed index sources.

`langdetect` and `pynput` are intentionally absent because their resolved dependency chains do not satisfy this policy. Do not add them to a local build environment.

## Installer generation is disabled

Installer generation is intentionally unavailable. `build.bat installer` exits with an error before dependency or build work begins. `installer.iss` also contains an unconditional preprocessor error, so invoking Inno Setup directly fails closed.

Do not remove or bypass either guard. No `Setup-Clicky.exe` should be produced by the current repository. Installer support can return only after a reviewed release pipeline can:

- sign and verify `Clicky.exe` before packaging
- package only that verified executable and its reviewed support files
- sign and verify the completed installer
- generate final hashes and an SBOM for the exact distributed bytes

Setting an Inno Setup path or compiler digest does not enable installer generation.

## Mandatory release signing gate

Before any distribution, a controlled release process must:

1. Build from the reviewed commit and frozen lock.
2. Sign `Clicky.exe` with an organization-controlled Authenticode certificate.
3. Verify the embedded signature and timestamp.
4. Package the already-signed application directory.
5. Sign the completed installer.
6. Verify the installer signature and timestamp.
7. Regenerate release hashes and the SBOM after the final bytes are produced.
8. Publish the source commit, hashes, SBOM, signer identity, and verification instructions together.

Example verification commands for a future signed artifact are:

~~~powershell
Get-AuthenticodeSignature .\dist\Clicky\Clicky.exe | Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
signtool verify /pa /all /v .\dist\Clicky\Clicky.exe
signtool verify /pa /all /v .\dist\Setup-Clicky.exe
Get-FileHash -Algorithm SHA256 .\dist\Clicky\Clicky.exe
Get-FileHash -Algorithm SHA256 .\dist\Setup-Clicky.exe
~~~

A valid signature does not replace source review or malware scanning. It establishes publisher identity and detects changes after signing.

## SmartScreen and antivirus

Never tell a user to choose **Run anyway**, disable SmartScreen, disable antivirus, or add an exclusion for Clicky. Stop when Windows cannot verify the publisher or security software reports the artifact. Confirm the expected signer and published SHA-256 through an independent channel before investigating further.

PyInstaller false positives are possible, but that label is not evidence that a detection is harmless.

## Release status

No signed release artifacts have been published. Until the signing pipeline above exists and is independently reviewed, this repository supports source review and local smoke builds only.
