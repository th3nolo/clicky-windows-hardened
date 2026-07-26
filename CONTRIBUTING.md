# Contributing to Clicky for Windows — Hardened

This repository is an independent MIT-licensed derivative of [Bitshank-2338/clicky-windows](https://github.com/Bitshank-2338/clicky-windows) source commit `09208d88740db7ba593eb6b95085b63e92a59772`. It is not an official upstream repository. Preserve the original notice in [LICENSE](LICENSE).

## Before starting

Use Windows x86-64, Python `3.12.10`, and uv `0.11.19`. Other toolchain versions are outside the reviewed build.

Read:

- [SETUP.md](SETUP.md) for the frozen environment
- [SECURITY.md](SECURITY.md) for trust boundaries and private reporting
- [TESTING.md](TESTING.md) for required checks

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/th3nolo/clicky-windows-hardened/security/advisories/new), not a public issue.

## Create a change

~~~powershell
git clone https://github.com/<your-user>/clicky-windows-hardened.git
Set-Location clicky-windows-hardened
git switch -c fix/short-description
~~~

Verify and install the lock without changing it:

~~~powershell
uv lock --check --offline --no-build --no-sources --no-python-downloads --python "3.12.10"
uv sync --frozen --group build --no-build --no-sources --no-managed-python --no-python-downloads --python "3.12.10" --default-index "https://pypi.org/simple" --index-strategy first-index --keyring-provider disabled --link-mode copy --no-cache
~~~

Do not use pip, editable installs, alternate indexes, Git dependencies, path dependencies, source builds, or upgrade flags.

## Scope changes narrowly

Prefer one issue per commit. Keep unrelated formatting or refactoring out of a security fix. Preserve existing user changes in a dirty worktree.

For code changes:

- keep network and filesystem operations bounded
- fail closed when identity, digest, destination, or platform state is ambiguous
- never log API keys, OAuth tokens, device codes, document contents, or screenshots
- do not add automatic installers, model downloads, service startup, package installation, or shell execution
- keep provider endpoints fixed unless a security review defines a safe configuration boundary
- keep journal and web search opt-in
- route UI updates across threads with Qt signals
- add standard-library offline tests for every security boundary changed

## Dependency changes

Treat every dependency change as a security change. A proposal must:

1. Explain why existing code or the standard library is insufficient.
2. Pin an exact version that has been public for at least 72 hours.
3. Use a stable, widely adopted release.
4. Resolve from the official PyPI index only.
5. Provide compatible Windows x86-64 wheels for the complete dependency chain.
6. Update `pyproject.toml`, `uv.lock`, and `sbom.cdx.json` together.
7. Pass `tools/check_dependency_policy.py`.
8. Avoid unnecessary transitive packages.

Do not restore live requirements to `requirements.txt` or `requirements-student.txt`. They are intentionally non-installable legacy files.

`langdetect` and `pynput` are currently excluded because their resolved chains do not meet the wheel-only rule. A feature that depends on either package remains unsupported until the complete policy is satisfied.

## Model and executable changes

Do not commit models, installers, opaque executables, or generated build output.

Changes to local model loading must preserve exact digest enforcement:

- speech files use configured SHA-256 values
- Ollama models use both the exact tag and the immutable local digest
- missing or changed artifacts fail closed
- Clicky does not download, install, start, or pull them

A hash proves identity, not safety. Document the source and review method for any new expected artifact.

## Run the required checks

~~~powershell
uv run --frozen --no-sync --python "3.12.10" python tools/check_dependency_policy.py
uv run --frozen --no-sync --python "3.12.10" python -m unittest discover -s tests -p "test_*.py" -v
~~~

Also parse every Python source and review the diff as described in [TESTING.md](TESTING.md). Tests must not contact the network, access real secrets, run the desktop app, or install dependencies.

For a local packaging check, use `build.bat`. Do not attach its unsigned output to a pull request or distribute it.

## Pull request content

A pull request should state:

- the problem and affected trust boundary
- the exact behavior changed
- tests run and their results
- files intentionally not tested and why
- dependency or model implications
- remaining limitations
- whether the change affects privacy, network access, secrets, build artifacts, or signing

Do not claim that a change makes the application completely safe. State the verified conditions.

## Documentation

Update documentation when commands, defaults, data flow, model requirements, supported features, or security behavior changes. Do not document an unsigned local build as a release. Do not tell users to bypass SmartScreen or antivirus.

## License and attribution

Contributions are made under the repository’s MIT license. Do not remove the preserved upstream copyright and permission notice.
