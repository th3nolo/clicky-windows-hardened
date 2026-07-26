"""Fail-closed static checks for the locked dependency and CI policy.

This script intentionally uses only the Python standard library. It does not
import or execute Clicky, install packages, contact indexes, or mutate files.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CUTOFF = "2026-07-22T00:00:00Z"
EXPECTED_INDEX = "https://pypi.org/simple"
EXPECTED_PYTHON = "3.12.10"
EXPECTED_UV = "0.11.19"
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
    "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "astral-sh/setup-uv": "08807647e7069bb48b6ef5acd8ec9567f424441b",
}


def fail(message: str) -> None:
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


def check_lock(expected: dict[str, str]) -> None:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    if lock.get("requires-python") != ">=3.11, <3.13":
        fail("uv.lock Python range does not match the reviewed range")
    packages = lock.get("package", [])
    locked_versions: dict[str, set[str]] = {}
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

        wheels = package.get("wheels", [])
        if not wheels:
            fail(f"{name} has no wheel in uv.lock")
        artifacts = list(wheels)
        if "sdist" in package:
            artifacts.append(package["sdist"])
        for artifact in artifacts:
            url = artifact.get("url", "")
            digest = artifact.get("hash", "")
            if not url.startswith("https://files.pythonhosted.org/"):
                fail(f"{name} has an unexpected artifact URL: {url!r}")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                fail(f"{name} has a missing or non-SHA256 artifact digest")

    for name, version in expected.items():
        if locked_versions.get(name) != {version}:
            fail(
                f"{name} expected exactly {version}, found "
                f"{sorted(locked_versions.get(name, set()))}"
            )
    if BANNED_PACKAGES & locked_versions.keys():
        fail("an excluded sdist-only package entered uv.lock")



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

def check_legacy_manifests() -> None:
    for filename in ("requirements.txt", "requirements-student.txt"):
        lines = (ROOT / filename).read_text(encoding="utf-8").splitlines()
        live = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
        if live:
            fail(f"{filename} must not contain installable requirements")


def check_build_script() -> None:
    text = (ROOT / "build.bat").read_text(encoding="utf-8")
    required_fragments = (
        f'set "EXPECTED_UV_VERSION={EXPECTED_UV}"',
        f'set "EXPECTED_PYTHON_VERSION={EXPECTED_PYTHON}"',
        "uv lock --check --offline --no-build --no-sources --no-python-downloads",
        "uv sync --frozen --group build --no-build --no-sources",
        "--no-managed-python --no-python-downloads",
        "--keyring-provider disabled --link-mode copy --no-cache",
        "uv export --frozen --no-dev --no-emit-project "
        "--format cyclonedx1.5",
        "Installer builds are disabled.",
        '"dist\\Clicky\\UNSIGNED-LOCAL-TEST-ONLY.txt"',
        "LOCAL TEST ONLY - UNSIGNED - DO NOT DISTRIBUTE",
    )
    for fragment in required_fragments:
        if fragment not in text:
            fail(f"build.bat is missing required hardening: {fragment}")
    forbidden = (
        " pip ",
        "pip install",
        "uv pip",
        "--upgrade",
        "--allow-insecure-host",
        "--no-verify-hashes",
        ":build_installer",
        "clicky_iscc",
        "iscc.exe",
    )
    lowered = f" {text.lower()} "
    for fragment in forbidden:
        if fragment in lowered:
            fail(f"build.bat contains forbidden dependency behavior: {fragment}")


def check_packaging_policy() -> None:
    installer = (ROOT / "installer.iss").read_text(encoding="utf-8-sig")
    guard = '#error "Installer build disabled: Authenticode signing pipeline is not implemented"'
    guard_position = installer.find(guard)
    setup_position = installer.find("[Setup]")
    if guard_position < 0 or setup_position < 0 or guard_position > setup_position:
        fail("installer.iss must fail unconditionally before its Setup section")
    if ".env.example inside the install folder for the template" in installer:
        fail("installer.iss contains stale dotenv-loading guidance")

    spec = (ROOT / "clicky.spec").read_text(encoding="utf-8")
    spec_lines = set(spec.splitlines())
    for package in UNSUPPORTED_SPEC_PACKAGES:
        if f'    "{package}",' in spec_lines:
            fail(f"clicky.spec must not collect unsupported package: {package}")
    required = (
        "LOCAL TEST ONLY — UNSIGNED — DO NOT DISTRIBUTE.",
        "Installer packaging is disabled until an Authenticode signing",
        "keep binaries uncompressed and inspectable",
    )
    for fragment in required:
        if fragment not in spec:
            fail(f"clicky.spec is missing unsigned-build guidance: {fragment}")
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

def main() -> int:
    runtime, build = check_pyproject()
    check_lock(runtime | build)
    check_sbom(runtime)
    check_legacy_manifests()
    check_build_script()
    check_packaging_policy()
    check_editor_automation()
    check_actions()
    print(
        "Dependency policy OK: "
        f"{len(runtime)} runtime pins, {len(build)} build pin, wheel-only lock."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, tomllib.TOMLDecodeError) as error:
        print(f"Dependency policy FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
