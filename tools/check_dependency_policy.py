"""Fail-closed checks for the locked dependency and CI policy.

This script uses only the Python standard library. It never imports or executes
Clicky, installs packages, downloads artifacts, or mutates files. The optional
``--verify-pypi`` mode reads bounded version metadata from PyPI so CI can prove
that exact locked artifacts are neither mismatched, yanked, nor under 72 hours old.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CUTOFF = "2026-07-22T00:00:00Z"
EXPECTED_INDEX = "https://pypi.org/simple"
PYPI_JSON_BASE = "https://pypi.org/pypi"
EXPECTED_PYTHON = "3.12.10"
EXPECTED_UV = "0.11.19"
MINIMUM_RELEASE_AGE = timedelta(hours=72)
PYPI_METADATA_TIMEOUT_SECONDS = 15.0
MAX_PYPI_METADATA_BYTES = 4 * 1024 * 1024
PYPI_VALIDATION_WORKERS = 8
BANNED_PACKAGES = {"evdev", "langdetect", "pynput"}
UNUSED_DIRECT_PACKAGES = {
    "aiohttp",
    "ddgs",
    "elevenlabs",
    "ollama",
    "soundfile",
    "tavily-python",
}
UNSUPPORTED_SPEC_PACKAGES = {
    "ddgs",
    "elevenlabs",
    "langdetect",
    "ollama",
    "pynput",
    "tavily",
}
EXACT_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)$"
)
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
CONSERVATIVE_PINS = {
    "anthropic": "0.112.0",
    "av": "17.1.0",
    "imageio": "2.37.3",
    "openai": "2.44.0",
    "opencv-python": "4.13.0.92",
    "pillow": "12.3.0",
}
EXPECTED_ACTIONS = {
    "actions/checkout": "08c6903cd8c0fde910a37f88322edcfb5dd907a8",
    "actions/setup-python": "e797f83bcb11b83ae66e0230d6156d7c80228e7c",
    "astral-sh/setup-uv": "08807647e7069bb48b6ef5acd8ec9567f424441b",
}


@dataclass(frozen=True)
class LockedArtifact:
    url: str
    sha256: str
    size: int


@dataclass(frozen=True)
class LockedRelease:
    name: str
    version: str
    artifacts: tuple[LockedArtifact, ...]


def fail(message: str) -> NoReturn:
    raise AssertionError(message)


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_requirements(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        match = EXACT_REQUIREMENT.fullmatch(value)
        if not match:
            fail(f"{label} dependency is not an exact registry pin: {value!r}")
        name = canonical_name(match.group("name"))
        if name in result:
            fail(f"{label} dependency is duplicated: {name}")
        result[name] = match.group("version")
    return result


def check_pyproject() -> tuple[dict[str, str], dict[str, str]]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    if project["requires-python"] != ">=3.11,<3.13":
        fail("requires-python must remain bounded to the reviewed 3.11/3.12 range")
    if project["license"] != "MIT" or project.get("license-files") != ["LICENSE"]:
        fail("MIT attribution metadata must remain present")

    runtime = exact_requirements(project["dependencies"], "runtime")
    build = exact_requirements(data["dependency-groups"]["build"], "build")
    if build != {"pyinstaller": "6.15.0"}:
        fail("the build group must contain only PyInstaller 6.15.0")
    if BANNED_PACKAGES & runtime.keys():
        fail("sdist-only optional packages must not enter the wheel-only build")
    if UNUSED_DIRECT_PACKAGES & runtime.keys():
        fail("unused SDKs must not re-enter the direct dependency set")
    for name, expected_version in CONSERVATIVE_PINS.items():
        if runtime.get(name) != expected_version:
            fail(f"{name} must remain on reviewed stable pin {expected_version}")

    uv = data["tool"]["uv"]
    required_uv_settings = {
        "exclude-newer": EXPECTED_CUTOFF,
        "required-version": f"=={EXPECTED_UV}",
        "prerelease": "disallow",
        "resolution": "highest",
        "no-build": True,
        "no-sources": True,
        "index-strategy": "first-index",
    }
    for key, expected in required_uv_settings.items():
        if uv.get(key) != expected:
            fail(f"tool.uv.{key} must be {expected!r}")
    expected_environment = [
        "sys_platform == 'win32' and platform_machine == 'AMD64'"
    ]
    if uv.get("environments") != expected_environment:
        fail("uv resolution must be restricted to 64-bit Windows")
    if uv.get("required-environments") != expected_environment:
        fail("uv must require wheels for 64-bit Windows")

    indexes = uv.get("index", [])
    if indexes != [{"name": "pypi", "url": EXPECTED_INDEX, "default": True}]:
        fail("PyPI must be the sole configured default index")
    return runtime, build


def check_lock(expected: dict[str, str]) -> tuple[LockedRelease, ...]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    if lock.get("requires-python") != ">=3.11, <3.13":
        fail("uv.lock Python range does not match the reviewed range")
    packages = lock.get("package", [])
    locked_versions: dict[str, set[str]] = {}
    locked_releases: list[LockedRelease] = []
    release_keys: set[tuple[str, str]] = set()
    for package in packages:
        name = canonical_name(package["name"])
        source = package.get("source", {})
        if "virtual" in source:
            continue
        if source != {"registry": EXPECTED_INDEX}:
            fail(f"{name} is not locked to the sole PyPI registry: {source!r}")
        version = package.get("version")
        if not version:
            fail(f"{name} has no locked version")
        locked_versions.setdefault(name, set()).add(version)
        release_key = (name, version)
        if release_key in release_keys:
            fail(f"{name} {version} is duplicated in uv.lock")
        release_keys.add(release_key)

        wheels = package.get("wheels", [])
        if not wheels:
            fail(f"{name} has no wheel in uv.lock")
        artifacts = list(wheels)
        if "sdist" in package:
            artifacts.append(package["sdist"])
        locked_artifacts: list[LockedArtifact] = []
        artifact_urls: set[str] = set()
        for artifact in artifacts:
            url = artifact.get("url", "")
            digest = artifact.get("hash", "")
            size = artifact.get("size")
            if not url.startswith("https://files.pythonhosted.org/"):
                fail(f"{name} has an unexpected artifact URL: {url!r}")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                fail(f"{name} has a missing or non-SHA256 artifact digest")
            if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                fail(f"{name} has a missing or invalid artifact size")
            if url in artifact_urls:
                fail(f"{name} {version} repeats a locked artifact URL: {url}")
            artifact_urls.add(url)
            locked_artifacts.append(
                LockedArtifact(url=url, sha256=digest.removeprefix("sha256:"), size=size)
            )
        locked_releases.append(
            LockedRelease(
                name=name,
                version=version,
                artifacts=tuple(locked_artifacts),
            )
        )

    for name, version in expected.items():
        if locked_versions.get(name) != {version}:
            fail(
                f"{name} expected exactly {version}, found "
                f"{sorted(locked_versions.get(name, set()))}"
            )
    if BANNED_PACKAGES & locked_versions.keys():
        fail("an excluded sdist-only package entered uv.lock")
    return tuple(sorted(locked_releases, key=lambda release: release.name))


def _parse_pypi_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(f"{label} has no authoritative PyPI upload timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} has a malformed PyPI upload timestamp: {value!r}")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{label} has a timezone-naive PyPI upload timestamp")
    return parsed.astimezone(timezone.utc)


def _check_locked_release_metadata(
    release: LockedRelease,
    metadata: object,
    *,
    now: datetime,
) -> int:
    """Match every locked artifact to authoritative PyPI version metadata."""
    if not isinstance(metadata, dict):
        fail(f"PyPI metadata for {release.name} {release.version} is not an object")
    info = metadata.get("info")
    if not isinstance(info, dict):
        fail(f"PyPI metadata for {release.name} {release.version} has no info object")
    metadata_name = info.get("name")
    metadata_version = info.get("version")
    if not isinstance(metadata_name, str) or canonical_name(metadata_name) != release.name:
        fail(
            f"PyPI identity mismatch for {release.name} {release.version}: "
            f"name is {metadata_name!r}"
        )
    if metadata_version != release.version:
        fail(
            f"PyPI identity mismatch for {release.name} {release.version}: "
            f"version is {metadata_version!r}"
        )
    if info.get("yanked") is not False:
        fail(f"PyPI release {release.name} {release.version} is yanked or ambiguous")

    files = metadata.get("urls")
    if not isinstance(files, list) or not files:
        fail(f"PyPI release {release.name} {release.version} has no artifacts")
    by_url: dict[str, dict[str, Any]] = {}
    for file_metadata in files:
        if not isinstance(file_metadata, dict):
            fail(f"PyPI release {release.name} {release.version} has malformed artifacts")
        artifact_url = file_metadata.get("url")
        if not isinstance(artifact_url, str) or not artifact_url:
            fail(f"PyPI release {release.name} {release.version} has an artifact without a URL")
        if artifact_url in by_url:
            fail(
                f"PyPI release {release.name} {release.version} repeats artifact "
                f"{artifact_url}"
            )
        by_url[artifact_url] = file_metadata

    checked = 0
    checked_at = now.astimezone(timezone.utc)
    minimum_upload_time = checked_at - MINIMUM_RELEASE_AGE
    for artifact in release.artifacts:
        file_metadata = by_url.get(artifact.url)
        if file_metadata is None:
            fail(
                f"locked artifact is missing from PyPI for "
                f"{release.name} {release.version}: {artifact.url}"
            )
        if file_metadata.get("yanked") is not False:
            fail(
                f"locked artifact is yanked or ambiguous for "
                f"{release.name} {release.version}: {artifact.url}"
            )
        digests = file_metadata.get("digests")
        if not isinstance(digests, dict) or digests.get("sha256") != artifact.sha256:
            fail(
                f"locked artifact SHA-256 does not match PyPI for "
                f"{release.name} {release.version}: {artifact.url}"
            )
        if file_metadata.get("size") != artifact.size:
            fail(
                f"locked artifact size does not match PyPI for "
                f"{release.name} {release.version}: {artifact.url}"
            )
        expected_filename = unquote(Path(urlparse(artifact.url).path).name)
        if file_metadata.get("filename") != expected_filename:
            fail(
                f"locked artifact filename does not match PyPI for "
                f"{release.name} {release.version}: {artifact.url}"
            )
        uploaded = _parse_pypi_timestamp(
            file_metadata.get("upload_time_iso_8601"),
            label=f"{release.name} {release.version} artifact",
        )
        if uploaded > checked_at:
            fail(
                f"PyPI upload timestamp is in the future for "
                f"{release.name} {release.version}: {artifact.url}"
            )
        if uploaded > minimum_upload_time:
            age = checked_at - uploaded
            fail(
                f"locked artifact for {release.name} {release.version} is only "
                f"{age.total_seconds() / 3600:.1f} hours old; 72 hours are required"
            )
        checked += 1
    return checked


def _fetch_pypi_release(
    release: LockedRelease,
    *,
    opener: Any = urlopen,
) -> dict[str, Any]:
    name = quote(release.name, safe="")
    version = quote(release.version, safe="")
    url = f"{PYPI_JSON_BASE}/{name}/{version}/json"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "clicky-windows-dependency-policy/1",
        },
        method="GET",
    )
    try:
        with opener(request, timeout=PYPI_METADATA_TIMEOUT_SECONDS) as response:
            if getattr(response, "status", None) != 200:
                fail(
                    f"PyPI metadata request failed for {release.name} "
                    f"{release.version}: HTTP {getattr(response, 'status', None)!r}"
                )
            final_url = response.geturl()
            parsed_final_url = urlparse(final_url)
            if (
                parsed_final_url.scheme != "https"
                or parsed_final_url.hostname != "pypi.org"
            ):
                fail(
                    f"PyPI metadata request redirected outside pypi.org for "
                    f"{release.name} {release.version}: {final_url}"
                )
            payload = response.read(MAX_PYPI_METADATA_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        fail(
            f"could not retrieve authoritative PyPI metadata for "
            f"{release.name} {release.version}: {error}"
        )
    if len(payload) > MAX_PYPI_METADATA_BYTES:
        fail(f"PyPI metadata is too large for {release.name} {release.version}")
    try:
        metadata = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"PyPI returned invalid JSON for {release.name} {release.version}: {error}")
    if not isinstance(metadata, dict):
        fail(f"PyPI metadata for {release.name} {release.version} is not an object")
    return metadata


def check_pypi_releases(
    releases: tuple[LockedRelease, ...],
    *,
    now: datetime | None = None,
) -> int:
    """Validate lock provenance against live, fail-closed PyPI metadata."""
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        fail("the PyPI validation clock must be timezone-aware")

    def validate(release: LockedRelease) -> int:
        metadata = _fetch_pypi_release(release)
        return _check_locked_release_metadata(release, metadata, now=checked_at)

    with ThreadPoolExecutor(max_workers=PYPI_VALIDATION_WORKERS) as executor:
        return sum(executor.map(validate, releases))


def check_sbom(expected: dict[str, str]) -> None:
    data = json.loads((ROOT / "sbom.cdx.json").read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX" or data.get("specVersion") != "1.5":
        fail("sbom.cdx.json must be CycloneDX 1.5")
    components: dict[str, set[str]] = {}
    for component in data.get("components", []):
        name = canonical_name(component["name"])
        version = component.get("version")
        if version:
            components.setdefault(name, set()).add(version)
        purl = component.get("purl", "")
        if not purl.startswith("pkg:pypi/"):
            fail(f"SBOM component {name} is not a PyPI package")
    for name, version in expected.items():
        if components.get(name) != {version}:
            fail(f"SBOM is stale for {name}: expected {version}")
    if BANNED_PACKAGES & components.keys():
        fail("an excluded sdist-only package entered the SBOM")



def check_bundled_skills() -> None:
    """Require an exact hash manifest for every dynamically executed skill."""
    directory = ROOT / "skills"
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 64 * 1024:
        fail("bundled skill manifest is missing, linked, or oversized")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        fail("bundled skill manifest must use version 1")
    manifest = payload.get("files")
    if not isinstance(manifest, dict) or not manifest:
        fail("bundled skill manifest must contain a non-empty files object")
    bundled = {
        path.name: path
        for path in directory.glob("*.py")
        if not path.name.startswith("_")
    }
    if set(manifest) != set(bundled):
        fail("bundled skill manifest must cover exactly every bundled skill")
    for filename, path in bundled.items():
        expected = manifest.get(filename)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            fail(f"bundled skill {filename} has no valid SHA-256 manifest entry")
        if path.is_symlink():
            fail(f"bundled skill {filename} cannot be a symlink")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(f"bundled skill {filename} does not match its manifest digest")


def check_legacy_manifests() -> None:
    for filename in ("requirements.txt", "requirements-student.txt"):
        lines = (ROOT / filename).read_text(encoding="utf-8").splitlines()
        live = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
        if live:
            fail(f"{filename} must not contain installable requirements")


def _batch_commands(text: str) -> tuple[str, ...]:
    """Return executable logical batch lines, excluding full-line comments."""
    commands: list[str] = []
    pending = ""
    for physical_line in text.splitlines():
        stripped = physical_line.strip()
        if not stripped:
            continue
        uncommented = stripped.removeprefix("@").lstrip()
        if uncommented.startswith("::") or re.match(r"(?i)^rem(?:\s|$)", uncommented):
            continue
        continued = stripped.endswith("^")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment}".strip()
        if continued:
            continue
        commands.append(" ".join(pending.split()))
        pending = ""
    if pending:
        fail("build.bat ends with an unterminated caret continuation")
    return tuple(commands)


def _strip_unquoted_comment(value: str, marker: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if character in {"'", '"'}:
            quote = None if quote == character else character if quote is None else quote
            continue
        if character == marker and quote is None and (
            index == 0 or value[index - 1].isspace()
        ):
            return value[:index].rstrip()
    return value.rstrip()


def _workflow_run_commands(text: str) -> tuple[str, ...]:
    """Extract effective GitHub Actions run bodies from this repository's YAML."""
    lines = text.splitlines()
    commands: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(?P<indent>\s*)run:\s*(?P<value>.*)$", line)
        if match is None or line.lstrip().startswith("#"):
            index += 1
            continue
        value = _strip_unquoted_comment(match.group("value").strip(), "#")
        if value and value not in {"|", "|-", ">", ">-"}:
            commands.append(" ".join(value.split()))
            index += 1
            continue
        base_indent = len(match.group("indent"))
        block: list[str] = []
        index += 1
        while index < len(lines):
            block_line = lines[index]
            if block_line.strip() and len(block_line) - len(block_line.lstrip()) <= base_indent:
                break
            stripped = _strip_unquoted_comment(block_line.strip(), "#")
            if stripped:
                block.append(stripped)
            index += 1
        commands.append(" ".join(block))
    return tuple(commands)


def _require_batch_command(
    commands: tuple[str, ...],
    prefix: str,
    required_arguments: tuple[str, ...],
) -> None:
    prefix_parts = prefix.split()
    executable = re.escape(prefix_parts[0]) + r"(?:\.exe)?"
    subcommands = "".join(rf"\s+{re.escape(part)}" for part in prefix_parts[1:])
    prefix_pattern = rf"(?i)^@?{executable}{subcommands}(?:\s|$)"
    candidates = [
        command.lower()
        for command in commands
        if re.match(prefix_pattern, command)
    ]
    if not candidates or not any(
        all(argument.lower() in candidate for argument in required_arguments)
        for candidate in candidates
    ):
        fail(
            f"build.bat is missing hardened {prefix} command arguments: "
            f"{list(required_arguments)}"
        )


def check_build_script(
    *,
    build_text: str | None = None,
    workflow_text: str | None = None,
) -> None:
    text = build_text
    if text is None:
        text = (ROOT / "build.bat").read_text(encoding="utf-8")
    commands = _batch_commands(text)
    lowered_commands = tuple(command.lower() for command in commands)
    required_exact = {
        f'set "expected_uv_version={EXPECTED_UV.lower()}"',
        f'set "expected_python_version={EXPECTED_PYTHON.lower()}"',
    }
    missing_exact = required_exact - set(lowered_commands)
    if missing_exact:
        fail(f"build.bat is missing required pinned settings: {sorted(missing_exact)}")

    _require_batch_command(
        commands,
        "uv lock",
        ("--check", "--offline", "--no-build", "--no-sources", "--no-python-downloads"),
    )
    _require_batch_command(
        commands,
        "uv sync",
        (
            "--frozen",
            "--group build",
            "--no-build",
            "--no-managed-python",
            "--no-python-downloads",
            "--keyring-provider disabled",
            "--link-mode copy",
            "--no-cache",
        ),
    )
    _require_batch_command(
        commands,
        "uv export",
        ("--frozen", "--no-dev", "--no-emit-project", "--format cyclonedx1.5"),
    )
    if not any(
        command.lower().startswith("echo ")
        and "installer builds are disabled." in command.lower()
        for command in commands
    ):
        fail("build.bat must actively report that installer builds are disabled")
    if not any(
        re.match(
            r'(?i)^>\s*"dist\\clicky\\unsigned-local-test-only\.txt"\s*\($',
            command,
        )
        for command in commands
    ):
        fail("build.bat must create the unsigned-local-test marker")
    if not any(
        command.lower().startswith("echo ")
        and "local test only - unsigned - do not distribute" in command.lower()
        for command in commands
    ):
        fail("build.bat must actively print the unsigned-build warning")

    for command in commands:
        lowered = command.lower()
        if "uv_no_sources" in lowered:
            fail("build.bat must rely on checked-in tool.uv.no-sources during sync")
        if re.match(r"(?i)^@?uv(?:\.exe)?\s+sync(?:\s|$)", command):
            if "--frozen" in lowered and "--no-sources" in lowered:
                fail("uv 0.11.19 rejects sync --frozen combined with --no-sources")
        if re.search(
            r"(?i)(?<![a-z0-9_.-])pip(?:3(?:\.\d+)*)?(?:\.exe)?(?=$|[\s\"'])",
            command,
        ):
            fail(f"build.bat invokes or references a pip executable: {command}")
        if re.search(r"(?i)(?<![a-z0-9_.-])uv(?:\.exe)?\s+pip(?:\s|$)", command):
            fail(f"build.bat invokes uv pip: {command}")
        for option in ("--upgrade", "--allow-insecure-host", "--no-verify-hashes"):
            if re.search(rf"(?i)(?<!\S){re.escape(option)}(?=$|\s)", command):
                fail(f"build.bat contains forbidden dependency option {option}: {command}")
        if "clicky_iscc" in lowered or re.search(
            r"(?i)(?<![a-z0-9_.-])iscc(?:\.exe)?(?=$|[\s\"'])",
            command,
        ):
            fail(f"build.bat invokes or references Inno Setup: {command}")
    if any(re.match(r"(?i)^:build_installer(?:\s|$)", command) for command in commands):
        fail("build.bat contains a disabled installer-build label")

    workflow = workflow_text
    if workflow is None:
        workflow = (
            ROOT / ".github" / "workflows" / "dependency-policy.yml"
        ).read_text(encoding="utf-8")
    workflow_commands = _workflow_run_commands(workflow)
    if not any(
        re.search(
            r"(?i)(?:^|\s)python(?:\.exe)?\s+tools/check_dependency_policy\.py\s+--verify-pypi(?:\s|$)",
            command,
        )
        for command in workflow_commands
    ):
        fail("CI must validate the lock against authoritative PyPI metadata")
    for command in workflow_commands:
        lowered = command.lower()
        if "uv_no_sources" in lowered:
            fail("CI sync must rely on checked-in tool.uv.no-sources")
        sync = re.search(r"(?i)(?:^|\s)uv(?:\.exe)?\s+sync(?:\s|$)", command)
        if sync and "--frozen" in lowered and "--no-sources" in lowered:
            fail("CI uses the invalid sync --frozen plus --no-sources combination")


def _call_named(tree: ast.AST, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    ]


def _literal_keyword(call: ast.Call, name: str) -> object:
    matches = [keyword.value for keyword in call.keywords if keyword.arg == name]
    if len(matches) != 1:
        fail(f"clicky.spec call {getattr(call.func, 'id', '<unknown>')} needs keyword {name}")
    try:
        return ast.literal_eval(matches[0])
    except (ValueError, TypeError):
        fail(f"clicky.spec keyword {name} must be a static literal")


def check_packaging_policy() -> None:
    installer_text = (ROOT / "installer.iss").read_text(encoding="utf-8-sig")
    installer_lines = [
        line.strip()
        for line in installer_text.splitlines()
        if line.strip() and not line.lstrip().startswith(";")
    ]
    guard = '#error "Installer build disabled: Authenticode signing pipeline is not implemented"'
    try:
        guard_position = installer_lines.index(guard)
        setup_position = installer_lines.index("[Setup]")
    except ValueError:
        fail("installer.iss must contain an active signing-pipeline guard and Setup section")
    if guard_position > setup_position:
        fail("installer.iss must fail unconditionally before its Setup section")
    if ".env.example inside the install folder for the template" in installer_text:
        fail("installer.iss contains stale dotenv-loading guidance")

    spec_path = ROOT / "clicky.spec"
    spec = spec_path.read_text(encoding="utf-8")
    spec_tree = ast.parse(spec, filename=str(spec_path))
    packaged_names: set[str] = set()
    for node in ast.walk(spec_tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "hidden"
            for target in node.targets
        ):
            try:
                values = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                fail("clicky.spec hidden imports must be a static string list")
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                fail("clicky.spec hidden imports must be a static string list")
            packaged_names.update(values)
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == "pkg":
            try:
                values = ast.literal_eval(node.iter)
            except (ValueError, TypeError):
                fail("clicky.spec collected packages must be a static string collection")
            if not isinstance(values, (list, tuple)) or not all(
                isinstance(value, str) for value in values
            ):
                fail("clicky.spec collected packages must be a static string collection")
            packaged_names.update(values)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "collect_submodules"
            and node.args
        ):
            try:
                value = ast.literal_eval(node.args[0])
            except (ValueError, TypeError):
                fail("clicky.spec collect_submodules target must be a static string")
            if not isinstance(value, str):
                fail("clicky.spec collect_submodules target must be a static string")
            packaged_names.add(value)
    packaged_data: set[tuple[str, str]] = set()
    for node in ast.walk(spec_tree):
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "datas"
            and isinstance(node.op, ast.Add)
        ):
            if not isinstance(node.value, (ast.List, ast.Tuple)):
                continue
            try:
                values = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                fail("clicky.spec added data files must be static string pairs")
            if not isinstance(values, list):
                fail("clicky.spec added data files must be a static list")
            for value in values:
                if (
                    not isinstance(value, (list, tuple))
                    or len(value) != 2
                    or not all(isinstance(item, str) for item in value)
                ):
                    fail("clicky.spec added data files must be string pairs")
                packaged_data.add((value[0], value[1]))
    required_skill_data = {
        ("skills/example_self_mode.py", "skills"),
        ("skills/manifest.json", "skills"),
    }
    if not required_skill_data.issubset(packaged_data):
        fail("clicky.spec must package bundled skill source and integrity manifest")

    unsupported = UNSUPPORTED_SPEC_PACKAGES & {
        canonical_name(name.split(".", 1)[0]) for name in packaged_names
    }
    if unsupported:
        fail(f"clicky.spec collects unsupported packages: {sorted(unsupported)}")

    module_doc = ast.get_docstring(spec_tree, clean=False) or ""
    for fragment in (
        "LOCAL TEST ONLY — UNSIGNED — DO NOT DISTRIBUTE.",
        "Installer packaging is disabled until an Authenticode signing",
    ):
        if fragment not in module_doc:
            fail(f"clicky.spec module documentation is missing: {fragment}")

    analysis_calls = _call_named(spec_tree, "Analysis")
    exe_calls = _call_named(spec_tree, "EXE")
    collect_calls = _call_named(spec_tree, "COLLECT")
    if len(analysis_calls) != 1 or len(exe_calls) != 1 or len(collect_calls) != 1:
        fail("clicky.spec must contain exactly one Analysis, EXE, and COLLECT call")
    if _literal_keyword(analysis_calls[0], "hookspath") != []:
        fail("clicky.spec must not load build-time PyInstaller hooks")
    if _literal_keyword(analysis_calls[0], "runtime_hooks") != []:
        fail("clicky.spec must not install runtime hooks")
    if _literal_keyword(exe_calls[0], "exclude_binaries") is not True:
        fail("clicky.spec must remain an inspectable one-directory build")
    if _literal_keyword(exe_calls[0], "upx") is not False:
        fail("clicky.spec EXE must keep UPX compression disabled")
    if _literal_keyword(collect_calls[0], "upx") is not False:
        fail("clicky.spec COLLECT must keep UPX compression disabled")

    for forbidden in (
        "antivirus-triggering",
        "Windows Defender",
        "distribute this whole folder",
        "released builds",
    ):
        if forbidden in spec:
            fail(f"clicky.spec contains stale release/antivirus wording: {forbidden}")

def check_editor_automation() -> None:
    candidates: set[Path] = set(ROOT.glob("*.code-workspace"))
    for directory in (".vscode", ".devcontainer", ".idea", ".run", ".fleet", ".zed"):
        base = ROOT / directory
        if base.is_dir():
            candidates.update(path for path in base.rglob("*") if path.is_file())

    for path in sorted(candidates):
        text = path.read_text(encoding="utf-8-sig")
        relative = path.relative_to(ROOT)
        if re.search(r'"[^"]*(?<!use)envFile"\s*:', text, re.IGNORECASE):
            fail(f"{relative} configures an envFile")
        for match in re.finditer(
            r'"[^"]*useEnvFile"\s*:\s*(?P<value>[^,}\r\n]+)',
            text,
            re.IGNORECASE,
        ):
            if match.group("value").strip().lower() != "false":
                fail(f"{relative} enables or ambiguously configures useEnvFile")
        if re.search(r"(?<![A-Za-z0-9])\.env(?:\b|[._-])", text, re.IGNORECASE):
            fail(f"{relative} references a dotenv file")
        if re.search(
            r'"runOn"\s*:\s*"folderOpen"',
            text,
            re.IGNORECASE,
        ):
            fail(f"{relative} enables an automatic folder-open task")
        for match in re.finditer(
            r'"task\.allowAutomaticTasks"\s*:\s*(?P<value>[^,}\r\n]+)',
            text,
            re.IGNORECASE,
        ):
            if match.group("value").strip().lower() not in {"false", '"off"'}:
                fail(f"{relative} enables or ambiguously permits automatic tasks")

def check_actions() -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    found: set[str] = set()
    for workflow in sorted(workflow_dir.glob("*.y*ml")):
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = re.search(r"^\s*uses:\s*([^#\s]+)", line)
            if not match:
                continue
            value = match.group(1)
            if value.startswith("./"):
                continue
            action, separator, revision = value.rpartition("@")
            if not separator or not FULL_COMMIT.fullmatch(revision):
                fail(
                    f"{workflow.relative_to(ROOT)}:{line_number} uses an "
                    "unpinned third-party action"
                )
            expected = EXPECTED_ACTIONS.get(action)
            if expected is None:
                fail(
                    f"{workflow.relative_to(ROOT)}:{line_number} uses an "
                    f"unreviewed third-party action: {action}"
                )
            if revision != expected:
                fail(
                    f"{workflow.relative_to(ROOT)}:{line_number} uses the "
                    f"wrong reviewed commit for {action}"
                )
            found.add(action)
    missing = EXPECTED_ACTIONS.keys() - found
    if missing:
        fail(f"required pinned actions are missing: {sorted(missing)}")

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify-pypi",
        action="store_true",
        help=(
            "fail closed unless every locked artifact matches live PyPI metadata "
            "and has been public for at least 72 hours"
        ),
    )
    args = parser.parse_args(argv)

    runtime, build = check_pyproject()
    locked_releases = check_lock(runtime | build)
    check_sbom(runtime)
    check_bundled_skills()
    check_legacy_manifests()
    check_build_script()
    check_packaging_policy()
    check_editor_automation()
    check_actions()
    provenance = ""
    if args.verify_pypi:
        checked_artifacts = check_pypi_releases(locked_releases)
        provenance = f", {checked_artifacts} artifacts verified against PyPI"
    print(
        "Dependency policy OK: "
        f"{len(runtime)} runtime pins, {len(build)} build pin, wheel-only lock"
        f"{provenance}."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        AssertionError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"Dependency policy FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
