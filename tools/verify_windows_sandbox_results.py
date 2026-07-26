"""Verify a Windows Sandbox run from the trusted host side."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_EXPECTED_UV_SHA256 = "cd628b46729d01ad110146a647a633a6e5de0e091d73db46afaeee6fcb4ba648"
_EXPECTED_PYTHON_RUNTIME_SHA256 = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
_EXPECTED_GIT_SHA256 = "22fead8244ef3a7225fb800099a4e43eca8bcec0466774917669599c2f19a05a"
_EXPECTED_INPUTS = {
    "clicky-source.zip",
    "python-runtime-sha256.txt",
    "python-runtime.zip",
    "source-archive-sha256.txt",
    "source-commit.txt",
    "uv-sha256.txt",
    "uv.exe",
    "windows-sandbox-validate.cmd",
}
_RESULT_LIMITS = {
    "PASS.txt": 32,
    "clicky-exe-sha256.txt": 4096,
    "runtime-validation.json": 2 * 1024 * 1024,
    "sandbox-validation.log": 8 * 1024 * 1024,
    "source-archive-sha256.txt": 256,
    "source-commit.txt": 256,
}
_INPUT_LIMITS = {
    "clicky-source.zip": 32 * 1024 * 1024,
    "python-runtime-sha256.txt": 256,
    "python-runtime.zip": 16 * 1024 * 1024,
    "source-archive-sha256.txt": 256,
    "source-commit.txt": 256,
    "uv-sha256.txt": 256,
    "uv.exe": 80 * 1024 * 1024,
    "windows-sandbox-validate.cmd": 1024 * 1024,
}
_EDGE_TTS_HOST = "speech.platform.bing.com"
_EXPECTED_LOGON_COMMAND = (
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
    r'-NoLogo -NoProfile -NonInteractive -Command "'
    r"& 'C:\ClickyInput\windows-sandbox-validate.cmd'; "
    r"$validationExit = $LASTEXITCODE; "
    r"$shutdown = [IO.Path]::Combine($env:SystemRoot, 'System32', 'shutdown.exe'); "
    r"& $shutdown /s /t 5 *> $null; "
    r"if ($LASTEXITCODE -ne 0) { exit 90 }; "
    r"if ($validationExit -ne 0) { exit $validationExit }; "
    r"Move-Item -LiteralPath 'C:\ValidationOutput\PASS.pending' "
    r"-Destination 'C:\ValidationOutput\PASS.txt' -Force -ErrorAction Stop; "
    r'exit 0"'
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _require_regular_file(path: Path, maximum_bytes: int) -> None:
    _require(path.exists(), f"required file is missing: {path.name}")
    _require(not _is_reparse(path), f"reparse-point evidence is forbidden: {path.name}")
    _require(path.is_file(), f"evidence is not a regular file: {path.name}")
    _require(path.stat().st_size <= maximum_bytes, f"evidence exceeds size limit: {path.name}")


def _require_plain_directory(path: Path, label: str) -> None:
    _require(path.exists() and path.is_dir(), f"{label} directory is missing")
    _require(not _is_reparse(path), f"{label} directory is a reparse point")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_single_line(path: Path, pattern: re.Pattern[str]) -> str:
    value = path.read_text(encoding="ascii").strip().lower()
    _require(pattern.fullmatch(value) is not None, f"invalid value in {path.name}")
    return value


def _certutil_sha256(path: Path) -> str:
    matches = [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if _SHA256_RE.fullmatch(line.strip().lower())
    ]
    _require(len(matches) == 1, "executable hash evidence is ambiguous")
    return matches[0]


def _paths_overlap(left: Path, right: Path) -> bool:
    left = left.resolve()
    right = right.resolve()
    return left == right or left in right.parents or right in left.parents


def _validate_wsb(run_root: Path, input_directory: Path, results: Path) -> None:
    launchers = tuple(run_root.glob("*.wsb"))
    _require(len(launchers) == 1, "run directory must contain exactly one WSB launcher")
    _require_regular_file(launchers[0], 1024 * 1024)
    root = ET.parse(launchers[0]).getroot()
    expected_settings = {
        "VGpu": "Disable",
        "Networking": "Default",
        "AudioInput": "Disable",
        "VideoInput": "Disable",
        "PrinterRedirection": "Disable",
        "ClipboardRedirection": "Disable",
        "ProtectedClient": "Enable",
    }
    for name, expected in expected_settings.items():
        _require(root.findtext(name) == expected, f"unexpected WSB {name} setting")
    _require(
        root.findtext("./LogonCommand/Command") == _EXPECTED_LOGON_COMMAND,
        "unexpected WSB logon command",
    )

    mappings: dict[str, tuple[Path, bool]] = {}
    for mapping in root.findall("./MappedFolders/MappedFolder"):
        host_text = mapping.findtext("HostFolder")
        sandbox_text = mapping.findtext("SandboxFolder")
        read_only_text = (mapping.findtext("ReadOnly") or "").strip().lower()
        _require(host_text is not None, "mapped folder is missing its host path")
        _require(sandbox_text is not None, "mapped folder is missing its sandbox path")
        _require(read_only_text in {"true", "false"}, "mapped folder has invalid access")
        key = sandbox_text.strip().lower()
        _require(key not in mappings, f"duplicate SandboxFolder mapping: {sandbox_text}")
        mappings[key] = (Path(host_text).resolve(), read_only_text == "true")
    expected = {r"c:\clickyinput", r"c:\validationoutput"}
    _require(set(mappings) == expected, "unexpected WSB mapped folders")
    _require(
        mappings[r"c:\clickyinput"] == (input_directory.resolve(), True),
        "sandbox input mapping is not the narrow read-only input directory",
    )
    _require(
        mappings[r"c:\validationoutput"] == (results.resolve(), False),
        "results must be the only writable host mapping",
    )
    _require(
        not _paths_overlap(input_directory, results),
        "input and writable results mappings overlap",
    )


def _validate_zip_paths(archive: zipfile.ZipFile, *, maximum_total: int) -> None:
    seen: set[str] = set()
    total = 0
    for item in archive.infolist():
        name = item.filename
        normalized = name.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part]
        _require(name not in seen, f"duplicate ZIP member: {name}")
        seen.add(name)
        _require(
            not name.startswith(("/", "\\"))
            and ":" not in name
            and ".." not in parts,
            f"unsafe ZIP member: {name}",
        )
        unix_type = (item.external_attr >> 16) & 0xF000
        _require(unix_type != 0xA000, f"symbolic-link ZIP member: {name}")
        total += item.file_size
        _require(total <= maximum_total, "ZIP expands beyond its size limit")


def _validate_prepared_inputs(
    input_directory: Path, expected_commit: str, expected_archive_sha256: str
) -> dict[str, str]:
    actual = {path.name for path in input_directory.iterdir()}
    _require(actual == _EXPECTED_INPUTS, f"unexpected sandbox inputs: {sorted(actual ^ _EXPECTED_INPUTS)}")
    for name, maximum in _INPUT_LIMITS.items():
        _require_regular_file(input_directory / name, maximum)

    uv_hash = _read_single_line(input_directory / "uv-sha256.txt", _SHA256_RE)
    _require(uv_hash == _EXPECTED_UV_SHA256, "uv evidence is not the reviewed digest")
    _require(_sha256(input_directory / "uv.exe") == uv_hash, "staged uv hash differs")
    python_hash = _read_single_line(
        input_directory / "python-runtime-sha256.txt", _SHA256_RE
    )
    _require(
        python_hash == _EXPECTED_PYTHON_RUNTIME_SHA256,
        "Python runtime evidence is not the reviewed digest",
    )
    _require(
        _sha256(input_directory / "python-runtime.zip") == python_hash,
        "staged Python runtime hash differs",
    )
    with zipfile.ZipFile(input_directory / "python-runtime.zip") as archive:
        _validate_zip_paths(archive, maximum_total=64 * 1024 * 1024)
        names = set(archive.namelist())
        _require(
            {"python.exe", "python312.dll", "python312.zip", "python312._pth"} <= names,
            "Python runtime archive is incomplete",
        )

    commit = _read_single_line(input_directory / "source-commit.txt", _COMMIT_RE)
    _require(commit == expected_commit, "staged source commit does not match HEAD")
    archive_path = input_directory / "clicky-source.zip"
    archive_hash = _sha256(archive_path)
    stated_hash = _read_single_line(
        input_directory / "source-archive-sha256.txt", _SHA256_RE
    )
    _require(archive_hash == stated_hash, "source archive hash evidence differs")
    _require(
        archive_hash == expected_archive_sha256,
        "source archive is not the independently regenerated commit archive",
    )
    with zipfile.ZipFile(archive_path) as archive:
        _validate_zip_paths(archive, maximum_total=64 * 1024 * 1024)
        try:
            archived_validator = archive.read("tools/windows-sandbox-validate.cmd")
        except KeyError as exc:
            raise AssertionError("source archive lacks sandbox validator") from exc
    _require(
        archived_validator == (input_directory / "windows-sandbox-validate.cmd").read_bytes(),
        "staged validator differs from the commit archive",
    )
    return {"commit": commit, "source_archive_sha256": archive_hash}


def verify_prepared(
    run_root: Path,
    expected_commit: str,
    expected_archive_sha256: str,
    *,
    require_empty_results: bool = True,
) -> dict[str, str]:
    run_root = run_root.resolve()
    _require_plain_directory(run_root, "run")
    input_directory = run_root / "input"
    results = run_root / "results"
    _require_plain_directory(input_directory, "sandbox input")
    _require_plain_directory(results, "sandbox results")
    _validate_wsb(run_root, input_directory, results)
    if require_empty_results:
        _require(not any(results.iterdir()), "prepared results directory must be empty")
    return _validate_prepared_inputs(
        input_directory, expected_commit, expected_archive_sha256
    )


def _normalized_hosts(values: list[object]) -> set[str]:
    normalized: set[str] = set()
    for value in values:
        _require(isinstance(value, str), "cloud TTS hostname is not text")
        normalized.add(value.rstrip(".").encode("idna").decode("ascii").lower())
    return normalized


def _validate_cloud_tts(cloud: dict[str, object], label: str) -> None:
    _require(cloud["synthetic_text_only"] is True, f"{label} used non-synthetic text")
    _require(
        _normalized_hosts(cloud["resolved_hosts"]) == {_EDGE_TTS_HOST},
        f"{label} contacted an unexpected hostname",
    )
    public: set[str] = set()
    for value in cloud["resolved_public_addresses"]:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
        _require(address.is_global, f"{label} recorded a non-public DNS answer")
        public.add(str(address))
    _require(bool(public), f"{label} public destination is missing")
    correlated = {str(value).split("%", 1)[0] for value in cloud["correlated_tcp_addresses"]}
    _require(bool(correlated), f"{label} captured no correlated TCP peer")
    _require(correlated <= public, f"{label} TCP peer does not match DNS answers")
    _require(int(cloud["audio_bytes"]) > 0, f"{label} returned no audio")


def _validate_scan(scan: dict[str, object], expected_digest: str, label: str) -> None:
    _require(scan["disable_remediation"] is True, f"{label} remediation was enabled")
    _require(scan["scan_exit_code"] == 0, f"{label} did not return clean")
    _require(
        scan["distribution_sha256_before"] == expected_digest
        and scan["distribution_sha256_after"] == expected_digest,
        f"distribution changed during {label}",
    )


def verify(
    run_root: Path, expected_commit: str, expected_archive_sha256: str
) -> dict[str, object]:
    prepared = verify_prepared(
        run_root,
        expected_commit,
        expected_archive_sha256,
        require_empty_results=False,
    )
    run_root = run_root.resolve()
    input_directory = run_root / "input"
    results = run_root / "results"
    actual_results = {path.name for path in results.iterdir()}
    expected_results = set(_RESULT_LIMITS)
    _require(
        actual_results == expected_results,
        f"unexpected sandbox result files: {sorted(actual_results ^ expected_results)}",
    )
    for name, maximum in _RESULT_LIMITS.items():
        _require_regular_file(results / name, maximum)
    _require(
        (results / "PASS.txt").read_text(encoding="ascii").strip() == "PASS",
        "sandbox did not emit its exact PASS marker",
    )
    source_commit = _read_single_line(results / "source-commit.txt", _COMMIT_RE)
    _require(source_commit == expected_commit, "sandbox source commit does not match HEAD")
    result_archive_hash = _read_single_line(
        results / "source-archive-sha256.txt", _SHA256_RE
    )
    _require(
        result_archive_hash == prepared["source_archive_sha256"],
        "sandbox source identity differs from prepared input",
    )

    log = (results / "sandbox-validation.log").read_text(
        encoding="utf-8-sig", errors="strict"
    )
    _require("[PASS] Windows Sandbox validation completed." in log, "PASS log line missing")
    _require("[FAIL]" not in log, "sandbox log contains a failed gate")
    _require("ERROR: Hidden import" not in log, "PyInstaller reported a missing hidden import")
    _require("Traceback (most recent call last)" not in log, "sandbox log contains a traceback")

    report = json.loads((results / "runtime-validation.json").read_text(encoding="utf-8"))
    crash = report["audio_crash_cleanup"]
    _require(crash["leftover_removed"] is True, "crash-leftover audio was not removed")
    privacy = report["privacy_controls"]
    for key in (
        "microphone_denied_before_consent",
        "recording_denied_before_consent",
        "microphone_started_after_consent",
        "recording_started_after_consent",
        "microphone_stopped_after_revocation",
        "microphone_recording_cancelled_after_revocation",
        "microphone_standby_after_regrant",
        "cloud_tts_denied_before_consent",
        "screen_denied_before_consent",
        "synthetic_screen_content_observed",
    ):
        _require(privacy[key] is True, f"privacy runtime gate failed: {key}")
    _validate_cloud_tts(privacy["cloud_tts_after_consent"], "source cloud TTS")

    dpapi = report["dpapi"]
    _require(dpapi["round_trip"] is True, "source DPAPI round trip failed")
    _require(dpapi["plaintext_absent"] is True, "source DPAPI retained plaintext")

    application = report["unsigned_application"]
    _require(
        application["external_destinations_before_consent"] == [],
        "packaged app made a pre-consent external connection",
    )
    _require(
        application["authenticode"]["Status"] == "NotSigned",
        "pre-release artifact has an unexpected Authenticode state",
    )
    packaged = application["packaged_security_self_test"]
    _require(packaged["runtime_boundary"]["frozen"] is True, "self-test was not packaged")
    _require(
        str(packaged["runtime_boundary"]["executable"]).lower().endswith("clicky.exe"),
        "packaged self-test executable identity is wrong",
    )
    for key in ("magic_present", "plaintext_absent", "same_process_read", "second_process_read"):
        _require(packaged["dpapi_token_persistence"][key] is True, f"packaged DPAPI failed: {key}")
    _require(packaged["secure_audio"]["normal_cleanup"] is True, "packaged audio cleanup failed")
    _require(bool(packaged["bundled_skills"]["verified_files"]), "packaged skills unverified")
    _require(packaged["privacy_defaults"]["microphone_allowed"] is False, "packaged mic defaulted on")
    _require(
        packaged["screen_capture"]["synthetic_content_observed"] is True,
        "packaged screen capture did not observe synthetic content",
    )
    _require(
        packaged["microphone_state"]["cancelled_after_revocation"] is True
        and packaged["microphone_state"]["standby_after_regrant"] is True,
        "packaged microphone revocation state failed",
    )
    _validate_cloud_tts(packaged["cloud_tts"], "packaged cloud TTS")

    defender = report["defender"]
    pristine = defender["pristine_distribution_sha256"]
    _require(_SHA256_RE.fullmatch(pristine) is not None, "invalid pristine tree digest")
    _validate_scan(defender["pre_execution"], pristine, "pre-execution Defender scan")
    _require(
        defender["post_execution_tree_sha256"] == pristine,
        "packaged execution changed the distribution",
    )
    _validate_scan(defender["post_execution"], pristine, "post-execution Defender scan")

    executable_hash = _certutil_sha256(results / "clicky-exe-sha256.txt")
    _require(
        executable_hash == application["sha256"],
        "executable identity differs between runtime and host evidence",
    )
    return {
        "commit": source_commit,
        "source_archive_sha256": prepared["source_archive_sha256"],
        "clicky_exe_sha256": executable_hash,
        "cloud_tts_hosts": packaged["cloud_tts"]["resolved_hosts"],
        "cloud_tts_public_addresses": packaged["cloud_tts"]["resolved_public_addresses"],
        "defender_signature_version": defender["pre_execution"]["status"]["AntivirusSignatureVersion"],
    }


def _independent_archive_hash(repo_root: Path, git_exe: Path, commit: str) -> str:
    _require_regular_file(git_exe, 16 * 1024 * 1024)
    _require(_sha256(git_exe) == _EXPECTED_GIT_SHA256, "Git is not the reviewed executable")
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "NUL",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    with tempfile.TemporaryDirectory(prefix="clicky-archive-verify-") as tmp:
        archive = Path(tmp) / "source.zip"
        command = [
            str(git_exe),
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=NUL",
            "-c",
            "core.attributesFile=NUL",
            "-C",
            str(repo_root),
            "archive",
            "--format=zip",
            f"--output={archive}",
            commit,
        ]
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, env=environment, timeout=120
        )
        _require(completed.returncode == 0, f"independent Git archive failed: {completed.stderr}")
        return _sha256(archive)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_root", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--git-exe", type=Path, required=True)
    parser.add_argument("--prepared-only", action="store_true")
    args = parser.parse_args()
    expected_commit = args.expected_commit.strip().lower()
    _require(_COMMIT_RE.fullmatch(expected_commit) is not None, "invalid expected commit")
    archive_hash = _independent_archive_hash(
        args.repo_root.resolve(), args.git_exe.resolve(), expected_commit
    )
    if args.prepared_only:
        summary = verify_prepared(args.run_root, expected_commit, archive_hash)
    else:
        summary = verify(args.run_root, expected_commit, archive_hash)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
