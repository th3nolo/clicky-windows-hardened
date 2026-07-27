# Building Clicky for Windows — Hardened

The build is reviewed for Windows x86-64 with Python `3.12.10` and uv `0.11.19` only. It can produce an unsigned local test artifact or the single immutable onedir input for a future Microsoft Store submission. There are no releases yet.

Unsigned executables, onedir trees, and MSIX files must not be distributed or sideloaded. The Store path is not complete until Microsoft certifies and signs the package and the exact Store-delivered bytes pass the post-certification gates below.

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

That command is local-test-only. `store-rc` is the clean-tree, commit-bound
manual construction entry point:

~~~bat
build.bat store-rc
~~~

`store-rc` refuses dirty tracked files, staged changes, and untracked source. It
records the exact 40-character commit in `SOURCE-COMMIT.txt` and writes
`UNSIGNED-STORE-SUBMISSION-INPUT.txt`. Preserve that complete `dist\Clicky`
directory. Do not rebuild it between runtime validation, static scanning,
adjudication, MSIX packaging, and Store submission.

The actual release-bound candidate must be built once inside the reviewed
Windows Sandbox flow using `prepare-windows-sandbox.ps1
-StoreReleaseCandidate`. That path builds from the authenticated commit archive,
applies the same exact Store marker and commit binding before packaged execution,
validates the resulting tree, and exports it once. Do not run `build.bat
store-rc` again after that exported candidate exists.

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

The local marker states that the portable output is unsigned, local-test-only,
and not distributable. Store mode uses a distinct marker and source-commit
binding so a local smoke build cannot be mistaken for submission input.

## Why the build is wheel-only

`pyproject.toml` uses exact dependency versions, a single PyPI index, `no-build = true`, `no-sources = true`, and a 64-bit Windows required environment. The lock contains SHA-256 artifact hashes. The dependency-policy test rejects dependencies without locked wheels and rejects Git, path, editable, and unreviewed index sources. CI additionally matches every locked artifact to bounded live PyPI metadata and enforces the 72-hour age, yank state, filename, size, URL, and SHA-256 requirements.

`langdetect` and `pynput` are intentionally absent because their resolved dependency chains do not satisfy this policy. Do not add them to a local build environment.

## Inno Setup generation is disabled

Installer generation is intentionally unavailable. `build.bat installer` exits with an error before dependency or build work begins. `installer.iss` also contains an unconditional preprocessor error, so invoking Inno Setup directly fails closed.

Do not remove or bypass either guard. No `Setup-Clicky.exe` should be produced.
The supported distribution design is Microsoft Store MSIX.

## MSIX packaging

`tools\build_msix.py` consumes an existing onedir; it never rebuilds, signs,
installs, submits, or uploads anything. It:

- requires the exact `SOURCE-COMMIT.txt` and Store-input marker
- requires a caller-supplied Windows SDK `MakeAppx.exe` path and reviewed SHA-256
- requires the exact Package Identity Name, Publisher DN, and
  PublisherDisplayName copied from Partner Center
- copies the complete onedir to a new preserved staging directory
- generates deterministic package assets and a desktop full-trust manifest
- produces an unsigned MSIX with SHA-256 block mapping
- unpacks it again and proves that the Clicky subtree and manifest are unchanged
- records the onedir, executable, staging, MSIX, tool, and commit identities

The legal publisher is Manuel Parra. The product/developer brand is th3nolo.
Those decisions do not substitute for the exact Store-assigned identity values.

The generated manifest declares the full-trust `ClickyStartup` startup task with
`Enabled="false"`. Installing the package therefore does not opt the user into
login startup. Windows Startup Apps remains the user-controlled place to enable
or disable it.

For a non-Store structural validation only, use `--validation-only`. That mode
uses a fixed conspicuous local identity, embeds an unsigned validation marker,
and refuses Store identity arguments. Its output must never be submitted or
distributed.

For a Store input, copy all three values from **Partner Center → Product
management → Product identity**, pass them verbatim, and include
`--partner-center-confirmed`. Example placeholders are intentionally not
provided because guessing any of those values creates the wrong package family.
Run `python tools\build_msix.py --help` for the complete invocation.

## Mandatory Store release gate

Before any distribution, a controlled Store release process must:

1. Build from the reviewed commit and frozen lock.
2. Preserve and hash the exact complete unsigned onedir and inner `Clicky.exe`.
3. Run the isolated Windows runtime gate against that onedir.
4. Complete the approved static scans against those exact bytes. Uploading an
   unknown hash to VirusTotal requires explicit approval for those exact bytes.
5. Obtain the exact Store identity values through Partner Center and package
   that same onedir once.
6. Submit the exact unsigned MSIX through Partner Center and pass certification.
7. Obtain the exact Store-delivered signed MSIX, verify its Store signature, and
   hash/scan both that package and its exact inner `Clicky.exe`.
8. Publish the source commit, hashes, SBOM, Store signer identity, certification
   status, and verification instructions together.

Microsoft re-signs Store MSIX packages after certification. That package
signature does not imply that the inner PyInstaller `Clicky.exe` has an
Authenticode signature. Verify and report both objects separately.

Example verification commands for a future Store-delivered package are:

~~~powershell
Get-AuthenticodeSignature .\Clicky-from-Store.msix | Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
signtool verify /pa /all /v .\Clicky-from-Store.msix
Get-AuthenticodeSignature .\unpacked\Clicky\Clicky.exe | Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
Get-FileHash -Algorithm SHA256 .\Clicky-from-Store.msix
Get-FileHash -Algorithm SHA256 .\unpacked\Clicky\Clicky.exe
~~~

A valid signature does not replace source review or malware scanning. It establishes publisher identity and detects changes after signing.

## SmartScreen and antivirus

Never tell a user to choose **Run anyway**, disable SmartScreen, disable antivirus, or add an exclusion for Clicky. Stop when Windows cannot verify the publisher or security software reports the artifact. Confirm the expected signer and published SHA-256 through an independent channel before investigating further.

PyInstaller false positives are possible, but that label is not evidence that a detection is harmless.

## Release status

No signed release artifacts have been published. The MSIX construction path is
reviewable and testable, but Partner Center identity, submission, certification,
Store signing, exact-byte post-certification retrieval, and scanning remain
mandatory user-interactive release gates.
