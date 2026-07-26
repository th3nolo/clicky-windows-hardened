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
import struct
import tempfile
import xml.etree.ElementTree as ET
import unicodedata
import zipfile
from functools import lru_cache
from pathlib import Path, PurePosixPath


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_RUNTIME_BOUNDARIES = frozenset({"windows-sandbox", "github-hosted-windows"})
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
    "Clicky-unsigned.exe": 128 * 1024 * 1024,
    "clicky-unsigned-onedir.zip": 650_000_000,
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
_DIST_MAX_FILES = 20_000
_DIST_MAX_MEMBER_BYTES = 1024 * 1024 * 1024
_DIST_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
_DIST_MAX_COMPRESSION_RATIO = 1000
_DIST_MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
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


@lru_cache(maxsize=1)
def _windows_stream_api() -> tuple[object, object, object, object, object]:
    import ctypes
    from ctypes import wintypes

    class Win32FindStreamData(ctypes.Structure):
        _fields_ = [
            ("stream_size", ctypes.c_longlong),
            ("stream_name", ctypes.c_wchar * 296),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(Win32FindStreamData),
        wintypes.DWORD,
    ]
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(Win32FindStreamData),
    ]
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = [wintypes.HANDLE]
    find_close.restype = wintypes.BOOL

    return ctypes, Win32FindStreamData, find_first, find_next, find_close


def _alternate_stream_names(path: Path) -> tuple[str, ...]:
    if os.name != "nt":
        return ()
    from ctypes import wintypes

    ctypes, data_type, find_first, find_next, find_close = _windows_stream_api()
    details = data_type()
    handle = find_first(str(path), 0, ctypes.byref(details), 0)
    invalid_handle = wintypes.HANDLE(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        _require(error == 38, f"alternate-stream enumeration failed for {path}: {error}")
        return ()

    names: list[str] = []
    try:
        names.append(details.stream_name)
        while find_next(handle, ctypes.byref(details)):
            names.append(details.stream_name)
        error = ctypes.get_last_error()
        _require(error == 38, f"alternate-stream enumeration failed for {path}: {error}")
    finally:
        _require(bool(find_close(handle)), f"alternate-stream handle close failed: {path}")
    return tuple(names)


def _require_no_alternate_streams(path: Path) -> None:
    unexpected = [
        name for name in _alternate_stream_names(path) if name.casefold() != "::$data"
    ]
    _require(
        not unexpected,
        f"alternate data stream is forbidden: {path.name}",
    )


def _require_regular_file(
    path: Path,
    maximum_bytes: int,
    *,
    reject_hardlinks: bool = True,
) -> None:
    _require(path.exists(), f"required file is missing: {path.name}")
    _require(not _is_reparse(path), f"reparse-point evidence is forbidden: {path.name}")
    _require(path.is_file(), f"evidence is not a regular file: {path.name}")
    details = path.stat()
    if reject_hardlinks:
        _require(details.st_nlink == 1, f"hard-linked evidence is forbidden: {path.name}")
    _require_no_alternate_streams(path)
    _require(details.st_size <= maximum_bytes, f"evidence exceeds size limit: {path.name}")


def _require_plain_directory(path: Path, label: str) -> None:
    _require(path.exists() and path.is_dir(), f"{label} directory is missing")
    _require(not _is_reparse(path), f"{label} directory is a reparse point")
    _require_no_alternate_streams(path)


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


def _require_safe_archive_name(name: str) -> None:
    _require(bool(name), "distribution archive contains an empty path")
    _require("\\" not in name, f"distribution archive contains a backslash path: {name}")
    _require(":" not in name, f"distribution archive contains an ADS or drive path: {name}")
    _require(
        not any(ord(character) < 32 or ord(character) == 127 for character in name),
        f"distribution archive contains a control character: {name!r}",
    )
    raw_parts = name.split("/")
    _require(
        all(part not in {"", ".", ".."} for part in raw_parts),
        f"distribution archive path is unsafe: {name}",
    )
    parsed = PurePosixPath(name)
    _require(not parsed.is_absolute(), f"distribution archive path is absolute: {name}")
    _require(
        unicodedata.normalize("NFC", name) == name,
        f"distribution archive path is not Unicode-normalized: {name}",
    )
    reserved = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
    for part in parsed.parts:
        _require(
            not part.endswith((" ", ".")),
            f"distribution archive path has a trailing dot or space: {name}",
        )
        stem = part.split(".", 1)[0].casefold()
        _require(stem not in reserved, f"distribution archive uses a reserved name: {name}")


def _preflight_distribution_archive(path: Path) -> None:
    file_size = path.stat().st_size
    _require(file_size >= 22, "distribution archive is shorter than its end record")
    with path.open("rb") as handle:
        handle.seek(-22, os.SEEK_END)
        end_record = handle.read(22)
    (
        signature,
        disk_number,
        central_directory_disk,
        disk_entries,
        total_entries,
        central_directory_size,
        central_directory_offset,
        comment_length,
    ) = struct.unpack("<4s4H2LH", end_record)
    _require(signature == b"PK\x05\x06", "distribution archive end record is missing")
    _require(comment_length == 0, "distribution archive comment is forbidden")
    _require(
        disk_number == 0
        and central_directory_disk == 0
        and disk_entries == total_entries,
        "multidisk distribution archives are forbidden",
    )
    _require(total_entries > 0, "distribution archive is empty")
    _require(
        total_entries <= _DIST_MAX_FILES,
        "distribution archive exceeds the file-count limit",
    )
    _require(
        central_directory_size <= _DIST_MAX_CENTRAL_DIRECTORY_BYTES,
        "distribution archive central directory exceeds its size limit",
    )
    _require(
        central_directory_offset + central_directory_size == file_size - 22,
        "distribution archive central-directory bounds are invalid",
    )
    actual_entries = 0
    remaining = central_directory_size
    with path.open("rb") as handle:
        handle.seek(central_directory_offset)
        while remaining:
            _require(
                remaining >= 46,
                "distribution archive central-directory header is truncated",
            )
            fixed_header = handle.read(46)
            _require(
                len(fixed_header) == 46
                and fixed_header[:4] == b"PK\x01\x02",
                "distribution archive central-directory header is invalid",
            )
            fields = struct.unpack("<4s6H3L5H2L", fixed_header)
            variable_size = fields[10] + fields[11] + fields[12]
            _require(
                variable_size <= remaining - 46,
                "distribution archive central-directory entry exceeds its bounds",
            )
            handle.seek(variable_size, os.SEEK_CUR)
            remaining -= 46 + variable_size
            actual_entries += 1
            _require(
                actual_entries <= _DIST_MAX_FILES,
                "distribution archive exceeds the file-count limit",
            )
    _require(
        actual_entries == total_entries,
        "distribution archive entry count differs from its end record",
    )


def _validate_distribution_archive(path: Path) -> dict[str, object]:
    tree = hashlib.sha256()
    tree.update(b"clicky-dist-tree-v1\0")
    total_bytes = 0
    executable_hash = hashlib.sha256()
    executable_seen = False
    _preflight_distribution_archive(path)
    with zipfile.ZipFile(path) as archive:
        _require(not archive.comment, "distribution archive comment is forbidden")
        entries = archive.infolist()
        _require(bool(entries), "distribution archive is empty")
        _require(
            len(entries) <= _DIST_MAX_FILES,
            "distribution archive exceeds the file-count limit",
        )
        names = [entry.filename for entry in entries]
        _require(names == sorted(names), "distribution archive entries are not sorted")
        normalized: set[str] = set()
        for entry in entries:
            _require_safe_archive_name(entry.filename)
            folded = unicodedata.normalize("NFC", entry.filename).casefold()
            _require(
                folded not in normalized,
                f"distribution archive contains a case-insensitive duplicate: {entry.filename}",
            )
            normalized.add(folded)
            _require(not entry.is_dir(), "distribution archive directory entries are forbidden")
            _require(
                entry.date_time == (1980, 1, 1, 0, 0, 0),
                "distribution member timestamp is not deterministic",
            )
            _require(
                entry.flag_bits & ~0x800 == 0,
                "distribution member uses unexpected ZIP flags",
            )
            _require(entry.internal_attr == 0, "distribution member has internal attributes")
            _require(not (entry.flag_bits & 0x1), "encrypted distribution members are forbidden")
            _require(not entry.comment, "distribution member comments are forbidden")
            _require(not entry.extra, "distribution member extra metadata is forbidden")
            _require(
                entry.compress_type == zipfile.ZIP_DEFLATED,
                "distribution member uses an unexpected compression method",
            )
            mode = entry.external_attr >> 16
            _require(
                entry.create_system == 3 and mode == (stat.S_IFREG | 0o644),
                f"distribution member is not a regular Unix-mode file: {entry.filename}",
            )
            _require(
                entry.file_size <= _DIST_MAX_MEMBER_BYTES,
                f"distribution member exceeds its size limit: {entry.filename}",
            )
            if entry.file_size:
                _require(
                    entry.compress_size > 0
                    and entry.file_size / entry.compress_size <= _DIST_MAX_COMPRESSION_RATIO,
                    f"distribution member exceeds compression-ratio limit: {entry.filename}",
                )
            total_bytes += entry.file_size
            _require(
                total_bytes <= _DIST_MAX_TOTAL_BYTES,
                "distribution archive exceeds the total expansion limit",
            )
            relative = entry.filename.encode("utf-8")
            tree.update(b"F")
            tree.update(len(relative).to_bytes(8, "big"))
            tree.update(relative)
            tree.update(entry.file_size.to_bytes(8, "big"))
            copied = 0
            with archive.open(entry, "r") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    copied += len(chunk)
                    tree.update(chunk)
                    if entry.filename == "Clicky.exe":
                        executable_hash.update(chunk)
            _require(copied == entry.file_size, "distribution member size changed while reading")
            if entry.filename == "Clicky.exe":
                _require(not executable_seen, "distribution contains duplicate Clicky.exe")
                executable_seen = True
    _require(executable_seen, "distribution archive is missing Clicky.exe")
    return {
        "scheme": "clicky-dist-tree-v1",
        "tree_sha256": tree.hexdigest(),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "clicky_exe_sha256": executable_hash.hexdigest(),
    }


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


def verify_runtime_results(
    results: Path,
    expected_commit: str,
    expected_source_archive_sha256: str,
    *,
    result_limits: dict[str, int],
    log_name: str,
    pass_line: str,
    expected_boundary: str,
    expected_workflow_commit: str | None = None,
) -> dict[str, object]:
    """Verify bounded runtime evidence shared by either disposable Windows gate."""
    _require(
        expected_boundary in _ALLOWED_RUNTIME_BOUNDARIES,
        f"unsupported runtime boundary: {expected_boundary}",
    )
    _require(_COMMIT_RE.fullmatch(expected_commit) is not None, "invalid expected commit")
    if expected_boundary == "github-hosted-windows":
        _require(
            expected_workflow_commit is not None
            and _COMMIT_RE.fullmatch(expected_workflow_commit) is not None,
            "invalid expected trusted workflow commit",
        )
    else:
        _require(
            expected_workflow_commit is None,
            "trusted workflow commit is forbidden for Windows Sandbox evidence",
        )
    _require_plain_directory(results, "validation results")
    results = results.resolve()
    actual_results = {path.name for path in results.iterdir()}
    expected_results = set(result_limits)
    _require(
        actual_results == expected_results,
        f"unexpected validation result files: {sorted(actual_results ^ expected_results)}",
    )
    for name, maximum in result_limits.items():
        _require_regular_file(results / name, maximum)
    _require(
        (results / "PASS.txt").read_text(encoding="ascii").strip() == "PASS",
        "validation did not emit its exact PASS marker",
    )
    source_commit = _read_single_line(results / "source-commit.txt", _COMMIT_RE)
    _require(source_commit == expected_commit, "validation source commit does not match the target")
    result_archive_hash = _read_single_line(
        results / "source-archive-sha256.txt", _SHA256_RE
    )
    _require(
        result_archive_hash == expected_source_archive_sha256,
        "validation source identity differs from the reviewed archive",
    )

    log = (results / log_name).read_text(
        encoding="utf-8-sig", errors="strict"
    )
    _require(pass_line in log, "PASS log line missing")
    _require("[FAIL]" not in log, "sandbox log contains a failed gate")
    _require("ERROR: Hidden import" not in log, "PyInstaller reported a missing hidden import")
    _require("Traceback (most recent call last)" not in log, "sandbox log contains a traceback")

    report = json.loads((results / "runtime-validation.json").read_text(encoding="utf-8"))
    boundary = report["runtime_boundary"]
    _require(boundary["kind"] == expected_boundary, "source runtime boundary differs")
    if expected_boundary == "github-hosted-windows":
        _require(boundary["commit"] == expected_commit, "source runtime commit differs")
        _require(
            expected_workflow_commit is not None
            and boundary["workflow_commit"] == expected_workflow_commit,
            "source trusted workflow commit differs",
        )
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
    _require(
        packaged["runtime_boundary"]["kind"] == expected_boundary,
        "packaged runtime boundary differs",
    )
    if expected_boundary == "github-hosted-windows":
        _require(
            packaged["runtime_boundary"]["commit"] == expected_commit,
            "packaged runtime commit differs",
        )
        _require(
            expected_workflow_commit is not None
            and packaged["runtime_boundary"]["workflow_commit"]
            == expected_workflow_commit,
            "packaged trusted workflow commit differs",
        )
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

    integrity = report["distribution_integrity"]
    _require(
        integrity["scheme"] == "clicky-dist-tree-v1",
        "unexpected distribution tree scheme",
    )
    pristine = integrity["pristine_tree_sha256"]
    _require(_SHA256_RE.fullmatch(pristine) is not None, "invalid pristine tree digest")
    _require(
        integrity["unchanged"] is True
        and integrity["post_execution_tree_sha256"] == pristine,
        "packaged execution changed the distribution",
    )

    distribution_archive = results / "clicky-unsigned-onedir.zip"
    archive_hash = _sha256(distribution_archive)
    _require(
        archive_hash == integrity["archive_sha256"],
        "distribution archive hash differs from runtime evidence",
    )
    _require(
        distribution_archive.stat().st_size == integrity["archive_bytes"],
        "distribution archive size differs from runtime evidence",
    )
    archive_identity = _validate_distribution_archive(distribution_archive)
    _require(
        archive_identity["tree_sha256"] == pristine,
        "exported distribution tree differs from runtime evidence",
    )
    _require(
        archive_identity["file_count"] == integrity["file_count"]
        and archive_identity["total_bytes"] == integrity["total_bytes"],
        "exported distribution size/count differs from runtime evidence",
    )
    executable_hash = _certutil_sha256(results / "clicky-exe-sha256.txt")
    _require(
        executable_hash == _sha256(results / "Clicky-unsigned.exe"),
        "executable hash record differs from the exported executable",
    )
    _require(
        executable_hash == application["sha256"]
        and executable_hash == integrity["clicky_exe_sha256"]
        and executable_hash == archive_identity["clicky_exe_sha256"],
        "executable identity differs between runtime and host evidence",
    )
    return {
        "commit": source_commit,
        "source_archive_sha256": expected_source_archive_sha256,
        "clicky_exe_sha256": executable_hash,
        "distribution_archive_sha256": archive_hash,
        "distribution_tree_sha256": pristine,
        "distribution_file_count": archive_identity["file_count"],
        "distribution_total_bytes": archive_identity["total_bytes"],
        "cloud_tts_hosts": packaged["cloud_tts"]["resolved_hosts"],
        "cloud_tts_public_addresses": packaged["cloud_tts"]["resolved_public_addresses"],
    }


def verify(
    run_root: Path, expected_commit: str, expected_archive_sha256: str
) -> dict[str, object]:
    prepared = verify_prepared(
        run_root,
        expected_commit,
        expected_archive_sha256,
        require_empty_results=False,
    )
    return verify_runtime_results(
        run_root.resolve() / "results",
        expected_commit,
        prepared["source_archive_sha256"],
        result_limits=_RESULT_LIMITS,
        log_name="sandbox-validation.log",
        pass_line="[PASS] Windows Sandbox validation completed.",
        expected_boundary="windows-sandbox",
    )

def _independent_archive_hash(repo_root: Path, git_exe: Path, commit: str) -> str:
    # Git for Windows may install identical binaries as hardlinks. Its exact
    # digest, version, and Authenticode signer are authenticated separately.
    _require_regular_file(git_exe, 16 * 1024 * 1024, reject_hardlinks=False)
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
