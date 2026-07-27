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
import ssl
import stat
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
REVIEWED_CERTIFI_VERSION = "2026.6.17"
REVIEWED_CERTIFI_WHEEL_SHA256 = "2227dcbaafe0d2f59279d1762ddddc37783ed4354594f194ffc31d20f41fc3db"
REVIEWED_CERTIFI_WHEEL_SIZE = 133289
REVIEWED_CA_BUNDLE_SHA256 = "bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0"
REVIEWED_CERTIFI_LICENSE_SHA256 = "e93716da6b9c0d5a4a1df60fe695b370f0695603d21f6f83f053e42cfc10caf7"
MAX_CA_BUNDLE_BYTES = 1024 * 1024
MAX_CERTIFI_LICENSE_BYTES = 64 * 1024
BANNED_PACKAGES = {"evdev", "langdetect", "pynput"}
UNUSED_DIRECT_PACKAGES = {
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
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/setup-python": "e797f83bcb11b83ae66e0230d6156d7c80228e7c",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
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

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_reviewed_file(
    path: Path, *, expected_sha256: str, maximum_bytes: int, label: str
) -> None:
    try:
        details = path.lstat()
    except OSError:
        fail(f"{label} is missing, linked, or not a regular file")
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(details, "st_file_attributes", 0)
    if path.is_symlink() or bool(attributes & reparse_flag) or not path.is_file():
        fail(f"{label} is missing, linked, or not a regular file")
    if details.st_size > maximum_bytes:
        fail(f"{label} exceeds its reviewed size limit")
    if _sha256_file(path) != expected_sha256:
        fail(f"{label} SHA-256 does not match the reviewed digest")


def check_trust_bundle() -> Path:
    """Bind live PyPI validation to the reviewed, commit-tracked CA bundle."""
    trust_directory = ROOT / "tools" / "trust"
    bundle = trust_directory / f"certifi-{REVIEWED_CERTIFI_VERSION}.pem"
    license_path = trust_directory / f"LICENSE.certifi-{REVIEWED_CERTIFI_VERSION}"
    _require_reviewed_file(
        bundle,
        expected_sha256=REVIEWED_CA_BUNDLE_SHA256,
        maximum_bytes=MAX_CA_BUNDLE_BYTES,
        label="reviewed CA bundle",
    )
    _require_reviewed_file(
        license_path,
        expected_sha256=REVIEWED_CERTIFI_LICENSE_SHA256,
        maximum_bytes=MAX_CERTIFI_LICENSE_BYTES,
        label="certifi license",
    )
    return bundle

def check_trust_bundle_lock(releases: tuple[LockedRelease, ...]) -> None:
    """Prove the vendored trust assets came from the exact locked wheel."""
    matches = [release for release in releases if canonical_name(release.name) == "certifi"]
    if len(matches) != 1 or matches[0].version != REVIEWED_CERTIFI_VERSION:
        fail("uv.lock does not contain the reviewed certifi release exactly once")
    release = matches[0]
    expected_filename = f"certifi-{REVIEWED_CERTIFI_VERSION}-py3-none-any.whl"
    wheels = [
        artifact
        for artifact in release.artifacts
        if unquote(urlparse(artifact.url).path).rsplit("/", 1)[-1] == expected_filename
    ]
    if len(wheels) != 1:
        fail("uv.lock does not contain the reviewed certifi wheel exactly once")
    wheel = wheels[0]
    if (
        wheel.sha256 != REVIEWED_CERTIFI_WHEEL_SHA256
        or wheel.size != REVIEWED_CERTIFI_WHEEL_SIZE
    ):
        fail("uv.lock certifi wheel identity differs from the reviewed trust source")



def _reviewed_ca_context(ca_bundle: Path) -> ssl.SSLContext:
    reviewed_bundle = check_trust_bundle()
    if ca_bundle.resolve() != reviewed_bundle.resolve():
        fail("live PyPI validation must use the reviewed CA bundle")
    try:
        context = ssl.create_default_context(cafile=str(reviewed_bundle))
    except (OSError, ValueError) as error:
        fail(f"could not load the reviewed CA bundle: {error}")
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        fail("reviewed CA context does not enforce certificate and hostname checks")
    if context.cert_store_stats().get("x509_ca", 0) < 100:
        fail("reviewed CA bundle contains too few trusted CA certificates")
    return context



def _fetch_pypi_release(
    release: LockedRelease,
    *,
    opener: Any = urlopen,
    ssl_context: ssl.SSLContext,
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
        with opener(
            request, timeout=PYPI_METADATA_TIMEOUT_SECONDS, context=ssl_context
        ) as response:
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
    ssl_context: ssl.SSLContext,
) -> int:
    """Validate lock provenance against live, fail-closed PyPI metadata."""
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        fail("the PyPI validation clock must be timezone-aware")

    def validate(release: LockedRelease) -> int:
        metadata = _fetch_pypi_release(release, ssl_context=ssl_context)
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

    loader_path = directory / "__init__.py"
    loader_tree = ast.parse(loader_path.read_text(encoding="utf-8"), filename=str(loader_path))
    anchors = [
        node.value
        for node in loader_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_BUNDLED_SKILL_DIGESTS"
            for target in node.targets
        )
    ]
    if len(anchors) != 1:
        fail("bundled skills need exactly one embedded digest trust anchor")
    anchor_call = anchors[0]
    if not (
        isinstance(anchor_call, ast.Call)
        and isinstance(anchor_call.func, ast.Name)
        and anchor_call.func.id == "MappingProxyType"
        and len(anchor_call.args) == 1
        and not anchor_call.keywords
    ):
        fail("bundled skill trust anchor must be an immutable static mapping")
    try:
        embedded = ast.literal_eval(anchor_call.args[0])
    except (ValueError, TypeError):
        fail("bundled skill trust anchor must contain only static digests")
    if embedded != manifest:
        fail("external bundled-skill manifest differs from the embedded trust anchor")

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


@dataclass(frozen=True)
class BatchCommand:
    text: str
    depth: int


# Intentional whole-file seal: every legitimate build.bat change requires a
# security review of the complete diff. Update this digest in the same reviewed
# commit; never change it only to make CI pass.
EXPECTED_BUILD_SCRIPT_SHA256 = (
    "6c28f0292aa98487a853e201c38d0556466f804c237d7e0dacf51528afbcb5f7"
)
EXPECTED_STORE_MARKER_SHA256 = (
    "313db1ba95e3dd039f63f7e786c3de6e1090499f53051515893781d36652191d"
)


_EXPECTED_PRE_EXPORT_GUARDS = (
    'if /i "%~1"=="installer" (',
    'if not "%~1"=="" (',
    'if /i "%~1"=="store-rc" (',
    "if errorlevel 1 (",
    'if not "!found_uv_version!"=="%expected_uv_version%" (',
    'if not exist "pyproject.toml" (',
    'if not exist "uv.lock" (',
    'if not exist "clicky.spec" (',
    'if exist "build" (',
    'if exist "dist" (',
    "if errorlevel 1 (",
    'if exist "!uv_project_environment!" (',
    "if errorlevel 1 (",
    "if errorlevel 1 (",
    "if errorlevel 1 (",
    'if not exist "dist\\clicky\\clicky.exe" (',
)


def _batch_parenthesis_delta(command: str) -> int:
    delta = 0
    quoted = False
    escaped = False
    for character in command:
        if escaped:
            escaped = False
            continue
        if character == "^":
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            continue
        if not quoted and character == "(":
            delta += 1
        elif not quoted and character == ")":
            delta -= 1
    if quoted or escaped:
        fail(f"build.bat contains malformed quoting or escaping: {command!r}")
    return delta


def _batch_command_records(text: str) -> tuple[BatchCommand, ...]:
    """Return logical batch commands with their surrounding block depth."""
    records: list[BatchCommand] = []
    pending = ""
    pending_depth = 0
    depth = 0
    for physical_line in text.splitlines():
        stripped = physical_line.strip()
        if not stripped:
            continue
        uncommented = stripped.removeprefix("@").lstrip()
        if uncommented.startswith("::") or re.match(
            r"(?i)^rem(?:\s|$)", uncommented
        ):
            continue
        if not pending:
            pending_depth = depth
        continued = stripped.endswith("^")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment}".strip()
        if continued:
            continue
        command = " ".join(pending.split())
        records.append(BatchCommand(command, pending_depth))
        depth += _batch_parenthesis_delta(command)
        if depth < 0:
            fail("build.bat closes a command block that was not open")
        pending = ""
    if pending:
        fail("build.bat ends with an unterminated caret continuation")
    if depth != 0:
        fail("build.bat contains an unterminated command block")
    return tuple(records)



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


def _require_authoritative_pypi_step(text: str) -> None:
    """Require one unconditional, unmasked PyPI policy step in validate."""
    lines = text.splitlines()
    effective = [
        line.rstrip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
    try:
        jobs_index = effective.index("jobs:")
    except ValueError:
        fail("CI must retain the exact reviewed workflow envelope")
    if effective[: jobs_index + 1] != [
        "name: Dependency policy",
        "on:",
        "  push:",
        "  pull_request:",
        "permissions:",
        "  contents: read",
        "jobs:",
    ]:
        fail("CI must retain the exact reviewed workflow envelope")

    try:
        trigger_index = effective.index("on:")
        permissions_index = effective.index("permissions:", trigger_index + 1)
    except ValueError:
        fail("CI must retain unconditional push and pull_request triggers")
    if effective[trigger_index:permissions_index] != [
        "on:",
        "  push:",
        "  pull_request:",
    ]:
        fail("CI dependency policy triggers must be exactly push and pull_request")

    job_markers = [
        index for index, line in enumerate(lines) if line.rstrip() == "  validate:"
    ]
    if len(job_markers) != 1:
        fail("CI must contain exactly one validate job")
    job_start = job_markers[0]
    job_end = len(lines)
    for index in range(job_start + 1, len(lines)):
        line = lines[index]
        if line.strip() and re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            job_end = index
            break
    job_lines = lines[job_start:job_end]
    job_envelope = []
    for line in job_lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        key_match = re.match(
            r"""^\s*(?P<key>"[^"]*"|'[^']*'|[A-Za-z0-9_-]+)\s*:\s*(?P<value>.*)$""",
            line,
        )
        if key_match is None:
            if indent == 4:
                fail("CI validate job contains an unreviewed job-level entry")
            continue
        key = key_match.group("key").strip("\"'").casefold()
        value = _strip_unquoted_comment(key_match.group("value").strip(), "#")
        if key in {"if", "continue-on-error"}:
            fail("CI validate job and policy step must be unconditional and unmasked")
        if indent == 4:
            job_envelope.append((key, value))

    if job_envelope != [
        ("runs-on", "windows-2022"),
        ("timeout-minutes", "5"),
        ("steps", ""),
    ]:
        fail(
            "CI validate job must use the exact reviewed Windows runner, timeout, "
            "and direct steps envelope"
        )

    step_marker = "      - name: Validate dependency policy"
    step_indexes = [
        index
        for index in range(job_start, job_end)
        if lines[index].rstrip() == step_marker
    ]
    if len(step_indexes) != 1:
        fail("CI validate job must contain exactly one named dependency-policy step")
    step_start = step_indexes[0]
    step_end = job_end
    for index in range(step_start + 1, job_end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= 6:
            step_end = index
            break
    actual_step = [
        line.strip()
        for line in lines[step_start:step_end]
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected_step = [
        "- name: Validate dependency policy",
        "shell: pwsh",
        "run: python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem",
    ]
    if actual_step != expected_step:
        fail(
            "CI dependency-policy step must be the exact unconditional, "
            "unmasked reviewed command"
        )

    steps_indexes = [
        index
        for index in range(job_start, step_start)
        if lines[index].rstrip() == "    steps:"
    ]
    if len(steps_indexes) != 1:
        fail("CI validate job must retain one direct steps list")
    actual_prefix = [
        _strip_unquoted_comment(line.strip(), "#")
        for line in lines[steps_indexes[0] + 1 : step_end]
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected_prefix = [
        "- name: Check out the reviewed revision",
        f"uses: actions/checkout@{EXPECTED_ACTIONS['actions/checkout']}",
        "with:",
        "persist-credentials: false",
        "- name: Set up the pinned Python runtime",
        f"uses: actions/setup-python@{EXPECTED_ACTIONS['actions/setup-python']}",
        "with:",
        f'python-version: "{EXPECTED_PYTHON}"',
        'cache: ""',
        "check-latest: false",
        "- name: Validate dependency policy",
        "shell: pwsh",
        "run: python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem",
    ]
    if actual_prefix != expected_prefix:
        fail(
            "CI validate job must begin with the exact reviewed checkout, "
            "Python setup, and dependency-policy steps"
        )


def _batch_command_tokens(command: str) -> tuple[str, ...]:
    """Tokenize the constrained batch commands checked by this policy."""
    tokens: list[str] = []
    current: list[str] = []
    quoted = False
    for character in command:
        if character == '"':
            quoted = not quoted
            continue
        if character.isspace() and not quoted:
            if current:
                tokens.append("".join(current).casefold())
                current = []
            continue
        current.append(character)
    if quoted:
        fail(f"build.bat contains an unterminated quoted argument: {command!r}")
    if current:
        tokens.append("".join(current).casefold())
    if tokens and tokens[0].startswith("@"):
        tokens[0] = tokens[0][1:]
    return tuple(tokens)


def _require_batch_command(
    records: tuple[BatchCommand, ...],
    prefix: str,
    expected_arguments: tuple[str, ...],
) -> int:
    prefix_tokens = _batch_command_tokens(prefix)
    expected_tail = tuple(
        token
        for argument in expected_arguments
        for token in _batch_command_tokens(argument)
    )
    candidates: list[tuple[int, tuple[str, ...]]] = []
    for index, record in enumerate(records):
        if record.depth != 0:
            continue
        tokens = _batch_command_tokens(record.text)
        if len(tokens) < len(prefix_tokens):
            continue
        executable_matches = tokens[0] in {
            prefix_tokens[0],
            f"{prefix_tokens[0]}.exe",
        }
        subcommands_match = (
            tokens[1 : len(prefix_tokens)] == prefix_tokens[1:]
        )
        if executable_matches and subcommands_match:
            candidates.append((index, tokens[len(prefix_tokens) :]))

    if len(candidates) != 1 or candidates[0][1] != expected_tail:
        fail(
            f"build.bat must contain one top-level {prefix} command with "
            f"the exact reviewed argument vector: {list(expected_arguments)}"
        )
    return candidates[0][0]


def _require_immediate_batch_failure_check(
    records: tuple[BatchCommand, ...],
    command_index: int,
    prefix: str,
    expected_error: str,
) -> None:
    check_index = command_index + 1
    if (
        check_index >= len(records)
        or records[check_index].depth != 0
        or records[check_index].text.casefold() != "if errorlevel 1 ("
    ):
        fail(f"{prefix} must be followed immediately by 'if errorlevel 1 ('")

    block_index = check_index + 1
    block: list[str] = []
    while block_index < len(records) and records[block_index].depth > 0:
        record = records[block_index]
        if record.depth == 1:
            block.append(record.text.casefold())
        block_index += 1
    expected = (expected_error.casefold(), "goto :cleanup", ")")
    if tuple(block) != expected:
        fail(f"{prefix} failure block must match the exact reviewed fail-closed body")


def _reject_early_top_level_transfers(
    records: tuple[BatchCommand, ...], last_required_index: int
) -> None:
    for record in records[:last_required_index]:
        if record.depth != 0:
            continue
        lowered = record.text.removeprefix("@").casefold()
        if re.match(r"^(?:goto|call|exit)(?:\s|$)", lowered):
            fail(
                "build.bat contains a top-level transfer before dependency "
                f"validation completes: {record.text}"
            )
        if lowered.startswith("if ") and not lowered.endswith("("):
            fail(
                "build.bat contains non-block conditional control flow before "
                f"dependency validation completes: {record.text}"
            )


def _require_reviewed_build_script(text: str) -> None:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if digest != EXPECTED_BUILD_SCRIPT_SHA256:
        fail("build.bat must retain the exact reviewed build script content")


def _require_reviewed_pre_export_guards(
    records: tuple[BatchCommand, ...], export_index: int
) -> None:
    actual = tuple(
        record.text.removeprefix("@").casefold()
        for record in records[:export_index]
        if record.depth == 0
        and record.text.removeprefix("@").casefold().startswith("if ")
    )
    if actual != _EXPECTED_PRE_EXPORT_GUARDS:
        fail(
            "build.bat pre-export guards must match the exact reviewed "
            "conditions and order"
        )


def _reject_unreviewed_batch_escaping(
    records: tuple[BatchCommand, ...], last_required_index: int
) -> None:
    approved = (
        'for /f "tokens=2" %%v in (\'uv --version 2^>nul\') '
        'do set "found_uv_version=%%v"'
    )
    for record in records[:last_required_index]:
        if "^" in record.text and record.text.casefold() != approved:
            fail(
                "build.bat contains unreviewed caret escaping before dependency "
                f"validation completes: {record.text}"
            )


def _reject_indirect_batch_assignments(
    records: tuple[BatchCommand, ...], last_required_index: int
) -> None:
    assignment = re.compile(
        r'(?i)(?:^|[\s&|()])@?set(?:\s+/(?:a|p))?\s+"?(?P<name>[^=\s"]+)='
    )
    for record in records[:last_required_index]:
        for match in assignment.finditer(record.text):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", match.group("name")) is None:
                fail(
                    "build.bat assignments before dependency validation must use "
                    f"static variable names: {record.text}"
                )


def _require_single_batch_assignment(
    records: tuple[BatchCommand, ...], name: str, value: str
) -> None:
    assignment = re.compile(
        rf'(?i)(?:^|[\s&|()])@?set(?:\s+/(?:a|p))?\s+"?{re.escape(name)}='
    )
    matches = [
        (index, record)
        for index, record in enumerate(records)
        if assignment.search(record.text)
    ]
    first_guard_index = next(
        (
            index
            for index, record in enumerate(records)
            if record.depth == 0
            and record.text.removeprefix("@").casefold().startswith("if ")
        ),
        len(records),
    )
    expected = f'set "{name}={value}"'.casefold()
    if (
        len(matches) != 1
        or matches[0][0] >= first_guard_index
        or matches[0][1].depth != 0
        or matches[0][1].text.removeprefix("@").casefold() != expected
    ):
        fail(
            "build.bat pinned settings must each have exactly one reviewed assignment "
            f"in the top-level preamble: {name}"
        )


def check_build_script(
    *,
    build_text: str | None = None,
    workflow_text: str | None = None,
) -> None:
    text = build_text
    if text is None:
        text = (ROOT / "build.bat").read_text(encoding="utf-8")
    records = _batch_command_records(text)
    commands = tuple(record.text for record in records)
    for name, value in (
        ("EXPECTED_UV_VERSION", EXPECTED_UV),
        ("EXPECTED_PYTHON_VERSION", EXPECTED_PYTHON),
        ("PYPI_INDEX", EXPECTED_INDEX),
    ):
        _require_single_batch_assignment(records, name, value)

    lock_index = _require_batch_command(
        records,
        "uv lock",
        (
            "--check",
            "--offline",
            "--no-build",
            "--no-sources",
            "--no-python-downloads",
            '--python "%EXPECTED_PYTHON_VERSION%"',
        ),
    )
    sync_index = _require_batch_command(
        records,
        "uv sync",
        (
            "--frozen",
            "--group build",
            "--no-build",
            "--no-managed-python",
            "--no-python-downloads",
            '--python "%EXPECTED_PYTHON_VERSION%"',
            '--default-index "%PYPI_INDEX%"',
            "--index-strategy first-index",
            "--keyring-provider disabled",
            "--link-mode copy",
            "--no-cache",
        ),
    )
    export_index = _require_batch_command(
        records,
        "uv export",
        (
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--format cyclonedx1.5",
            '--output-file "dist\\Clicky\\sbom.cdx.json"',
        ),
    )
    if not lock_index < sync_index < export_index:
        fail("build.bat dependency commands are not in the reviewed order")
    _reject_unreviewed_batch_escaping(records, export_index)
    _reject_indirect_batch_assignments(records, export_index)
    for command_index, prefix, expected_error in (
        (
            lock_index,
            "uv lock",
            "echo [ERROR] uv.lock does not match pyproject.toml.",
        ),
        (
            sync_index,
            "uv sync",
            "echo [ERROR] Frozen wheel-only dependency sync failed.",
        ),
        (
            export_index,
            "uv export",
            "echo [ERROR] CycloneDX SBOM generation failed.",
        ),
    ):
        _require_immediate_batch_failure_check(
            records, command_index, prefix, expected_error
        )
    _require_reviewed_pre_export_guards(records, export_index)
    _reject_early_top_level_transfers(records, export_index)
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
    _require_reviewed_build_script(text)

    workflow = workflow_text
    if workflow is None:
        workflow = (
            ROOT / ".github" / "workflows" / "dependency-policy.yml"
        ).read_text(encoding="utf-8")
    _require_authoritative_pypi_step(workflow)
    workflow_commands = _workflow_run_commands(workflow)
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
    parents = {child: parent for parent in ast.walk(spec_tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(spec_tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "collect_all"
        ):
            continue
        ancestor = parents.get(node)
        while ancestor is not None:
            if isinstance(ancestor, ast.Try):
                fail("clicky.spec must not suppress required-package collection failures")
            ancestor = parents.get(ancestor)

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
        "Inno Setup packaging is disabled.",
        "commit-bound onedir",
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
    if _literal_keyword(analysis_calls[0], "noarchive") is not True:
        fail("clicky.spec must keep Python bytecode external and inspectable")
    if _literal_keyword(exe_calls[0], "exclude_binaries") is not True:
        fail("clicky.spec must remain an inspectable one-directory build")
    if _literal_keyword(exe_calls[0], "upx") is not False:
        fail("clicky.spec EXE must keep UPX compression disabled")
    if _literal_keyword(exe_calls[0], "manifest") != "clicky.manifest":
        fail("clicky.spec must embed the reviewed per-monitor-v2 manifest")
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

    build_text = (ROOT / "build.bat").read_text(encoding="utf-8-sig")
    for fragment in (
        'if /I "%~1"=="store-rc"',
        "UNSIGNED-STORE-SUBMISSION-INPUT.txt",
        "SOURCE-COMMIT.txt",
        "git diff --quiet -- .",
        "git diff --cached --quiet -- .",
        "git ls-files --others --exclude-standard",
    ):
        if fragment not in build_text:
            fail(f"build.bat is missing Store input gate: {fragment}")

    manifest_template = ROOT / "packaging" / "AppxManifest.xml.in"
    store_marker_template = (
        ROOT / "packaging" / "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
    )
    msix_tool = ROOT / "tools" / "build_msix.py"
    if (
        not manifest_template.is_file()
        or not store_marker_template.is_file()
        or not msix_tool.is_file()
    ):
        fail("reviewed MSIX templates and packaging tool are required")
    if (
        hashlib.sha256(store_marker_template.read_bytes()).hexdigest()
        != EXPECTED_STORE_MARKER_SHA256
    ):
        fail("Store input marker must retain its exact reviewed text")
    manifest_text = manifest_template.read_text(encoding="utf-8")
    for fragment in (
        "{{IDENTITY_NAME}}",
        "{{PUBLISHER}}",
        "{{PUBLISHER_DISPLAY_NAME}}",
        'Name="Windows.Desktop"',
        'uap10:RuntimeBehavior="packagedClassicApp"',
        'uap10:TrustLevel="mediumIL"',
        '<rescap:Capability Name="runFullTrust"',
        'Executable="Clicky\\Clicky.exe"',
        "developed by th3nolo",
    ):
        if fragment not in manifest_text:
            fail(f"MSIX manifest template is missing: {fragment}")
    msix_source = msix_tool.read_text(encoding="utf-8")
    ast.parse(msix_source, filename=str(msix_tool))
    for fragment in (
        "--makeappx-sha256",
        "--partner-center-confirmed",
        "UNSIGNED-STORE-SUBMISSION-INPUT.txt",
        "UNSIGNED-VALIDATION-ONLY.txt",
        "AppxSignature.p7x",
        "tree_identity(unpacked / \"Clicky\")",
        '"legal_publisher": "Manuel Parra"',
        '"brand": "th3nolo"',
        '"store_certification_complete": False',
    ):
        if fragment not in msix_source:
            fail(f"MSIX packaging tool is missing release gate: {fragment}")
    for forbidden in (
        "signtool",
        "Add-AppxPackage",
        "Invoke-WebRequest",
        "urllib.request",
        "requests.",
    ):
        if forbidden.casefold() in msix_source.casefold():
            fail(f"MSIX packaging tool contains forbidden capability: {forbidden}")

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
    parser.add_argument(
        "--ca-bundle",
        type=Path,
        help="reviewed CA bundle required for fail-closed live PyPI TLS",
    )
    args = parser.parse_args(argv)
    reviewed_bundle = check_trust_bundle()

    runtime, build = check_pyproject()
    locked_releases = check_lock(runtime | build)
    check_trust_bundle_lock(locked_releases)
    check_sbom(runtime)
    check_bundled_skills()
    check_legacy_manifests()
    check_build_script()
    check_packaging_policy()
    check_editor_automation()
    check_actions()
    provenance = ""
    if args.ca_bundle is not None and not args.verify_pypi:
        fail("--ca-bundle may be used only with --verify-pypi")
    if args.verify_pypi:
        if args.ca_bundle is None:
            fail("--verify-pypi requires --ca-bundle")
        if args.ca_bundle.resolve() != reviewed_bundle.resolve():
            fail("--verify-pypi must use the reviewed CA bundle")
        ssl_context = _reviewed_ca_context(reviewed_bundle)
        checked_artifacts = check_pypi_releases(
            locked_releases, ssl_context=ssl_context
        )
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
