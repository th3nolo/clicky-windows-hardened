"""Trusted, standard-library helpers for the ephemeral Windows quarantine workflow.

The build job is intentionally treated as untrusted after it starts executing the
target revision.  A fresh verifier job checks the encrypted evidence again using
this file from the trusted workflow revision before any bytes are sent to
VirusTotal.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import http.client
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


REPOSITORY = "th3nolo/clicky-windows-hardened"
WORKFLOW_PATH = ".github/workflows/ephemeral-windows-security.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
AGE_VERSION = "1.3.1"
AGE_URL = (
    "https://github.com/FiloSottile/age/releases/download/v1.3.1/"
    "age-v1.3.1-windows-amd64.zip"
)
AGE_ARCHIVE_SHA256 = (
    "c56e8ce22f7e80cb85ad946cc82d198767b056366201d3e1a2b93d865be38154"
)
AGE_ARCHIVE_MAX_BYTES = 16 * 1024 * 1024
ARTIFACT_MAX_BYTES = 480_000_000
CIPHERTEXT_PAYLOAD_MAX_BYTES = 479_000_000
SOURCE_MAX_BYTES = 32 * 1024 * 1024
RUNTIME_REPORT_MAX_BYTES = 2 * 1024 * 1024
DIST_ARCHIVE_MAX_BYTES = 470 * 1024 * 1024
DIST_MAX_FILES = 20_000
DIST_MAX_MEMBER_BYTES = 1024 * 1024 * 1024
DIST_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
DIST_MAX_COMPRESSION_RATIO = 1000
DIST_MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
EXECUTABLE_MAX_BYTES = 128 * 1024 * 1024
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_LARGE_UPLOAD_URL = "https://www.virustotal.com/api/v3/files/upload_url"
VT_MAX_UPLOAD_BYTES = 650_000_000
VT_DIRECT_UPLOAD_BYTES = 32 * 1024 * 1024
VT_POLL_SECONDS = 15
VT_ANALYSIS_TIMEOUT_SECONDS = 30 * 60
VT_REQUEST_MIN_INTERVAL_SECONDS = 16.0
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SSH_PUBLIC_RE = re.compile(
    r"^(ssh-ed25519|ssh-rsa) ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]{1,1024})?$"
)
EVIDENCE_MEMBERS = ("PASS.txt", "manifest.json", "runtime/runtime-validation.json")
CIPHERTEXT_MEMBERS = (
    "clicky-executable.exe.age",
    "clicky-full-dist.zip.age",
    "clicky-runtime-evidence.zip.age",
    "clicky-source.zip.age",
)


class HarnessError(RuntimeError):
    """A fail-closed validation error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HarnessError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_hash(value: str, label: str) -> str:
    normalized = value.strip()
    require(SHA256_RE.fullmatch(normalized) is not None, f"{label} is not lowercase SHA-256")
    return normalized


def require_commit(value: str, label: str) -> str:
    normalized = value.strip()
    require(COMMIT_RE.fullmatch(normalized) is not None, f"{label} is not a lowercase commit SHA")
    return normalized


def require_plain_file(
    path: Path, maximum_bytes: int, label: str, *, reject_hardlinks: bool = True
) -> None:
    require(path.exists(), f"{label} is missing")
    require(not path.is_symlink(), f"{label} must not be a symlink")
    require(path.is_file(), f"{label} is not a regular file")
    details = path.stat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(details, "st_file_attributes", 0)
    require(not (attributes & reparse_flag), f"{label} must not be a reparse point")
    if reject_hardlinks:
        require(details.st_nlink == 1, f"{label} must not be hard-linked")
    require(details.st_size > 0, f"{label} is empty")
    require(details.st_size <= maximum_bytes, f"{label} exceeds its size limit")


def validate_ssh_recipient(value: str) -> str:
    require(len(value.encode("utf-8")) <= 16 * 1024, "age SSH recipient is too long")
    require("\r" not in value and "\n" not in value, "age SSH recipient must be one line")
    match = SSH_PUBLIC_RE.fullmatch(value.strip())
    require(match is not None, "age recipient must be one ssh-ed25519 or ssh-rsa public key")
    try:
        decoded = base64.b64decode(match.group(2), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HarnessError("age SSH recipient contains invalid base64") from exc
    require(len(decoded) >= 32, "age SSH recipient key blob is too short")
    return value.strip()


def _json_loads_strict(data: bytes, label: str) -> object:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            require(key not in result, f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"{label} is not valid UTF-8 JSON") from exc


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_context_from_environment(*, require_recipient: bool) -> dict[str, str]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    github_ref = os.environ.get("GITHUB_REF", "")
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    github_sha = require_commit(os.environ.get("GITHUB_SHA", ""), "GITHUB_SHA")
    workflow_sha = require_commit(
        os.environ.get("GITHUB_WORKFLOW_SHA", ""), "GITHUB_WORKFLOW_SHA"
    )
    target_sha = require_commit(os.environ.get("INPUT_TARGET_SHA", ""), "target_sha")
    require(repository == REPOSITORY, "workflow is running in an unexpected repository")
    require(github_ref == "refs/heads/main", "workflow must be dispatched from main")
    require(workflow_ref == WORKFLOW_REF, "workflow reference is not trusted main")
    require(github_sha == workflow_sha, "workflow SHA and dispatch SHA differ")
    require(target_sha != workflow_sha, "target SHA must be distinct from the workflow SHA")
    result = {
        "target_sha": target_sha,
        "workflow_sha": workflow_sha,
    }
    if require_recipient:
        result["recipient"] = validate_ssh_recipient(
            os.environ.get("INPUT_AGE_SSH_PUBLIC_RECIPIENT", "")
        )
    return result


def _hosted_git_executable() -> Path:
    value = os.environ.get("CLICKY_HOSTED_GIT_EXE", "")
    require(value and "\r" not in value and "\n" not in value, "hosted Git path is missing")
    path = Path(value)
    require(path.is_absolute(), "hosted Git path is not absolute")
    require(path.name.casefold() == "git.exe", "hosted Git executable name differs")
    require(path.exists() and path.is_file(), "hosted git.exe is unavailable")
    require(0 < path.stat().st_size <= 16 * 1024 * 1024, "hosted git.exe size is invalid")
    return path


def _run_git(root: Path, arguments: list[str]) -> str:
    git_executable = _hosted_git_executable()
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
        }
    )
    result = subprocess.run(
        [
            str(git_executable),
            "--no-replace-objects",
            "-c",
            "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(root),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=120,
    )
    require(result.returncode == 0, f"hardened Git command failed: {result.stderr.strip()}")
    return result.stdout


def verify_target_checkout(
    root: Path, output: Path, expected_commit: str
) -> dict[str, str]:
    expected_commit = require_commit(expected_commit, "target_sha")
    require(root.is_dir() and not root.is_symlink(), "target checkout is not a plain directory")
    git_dir = root / ".git"
    require(git_dir.is_dir() and not git_dir.is_symlink(), "target .git directory is unexpected")

    hooks = git_dir / "hooks"
    if hooks.exists():
        require(hooks.is_dir() and not hooks.is_symlink(), "target hooks path is unsafe")
        shutil.rmtree(hooks)
    _run_git(root, ["config", "--local", "--replace-all", "core.hooksPath", "NUL"])
    _run_git(root, ["config", "--local", "--replace-all", "core.fsmonitor", "false"])
    _run_git(root, ["config", "--local", "--replace-all", "credential.helper", ""])
    _run_git(root, ["config", "--local", "--replace-all", "protocol.file.allow", "never"])
    _run_git(root, ["config", "--local", "--replace-all", "remote.origin.pushurl", "DISABLED"])

    actual = _run_git(root, ["rev-parse", "--verify", "HEAD^{commit}"]).strip()
    require(actual == expected_commit, "target checkout does not match target_sha")
    tree = _run_git(root, ["rev-parse", "--verify", "HEAD^{tree}"]).strip()
    require(COMMIT_RE.fullmatch(tree) is not None, "target tree identity is invalid")
    require(not _run_git(root, ["status", "--porcelain=v1"]).strip(), "target checkout is dirty")
    require(not hooks.exists(), "target Git hooks directory survived hardening")

    output.parent.mkdir(parents=True, exist_ok=True)
    require(not output.exists(), "source archive output already exists")
    _run_git(root, ["archive", "--format=zip", f"--output={output}", actual])
    require_plain_file(output, SOURCE_MAX_BYTES, "source archive")
    return {
        "commit": actual,
        "tree": tree,
        "source_sha256": sha256_file(output),
    }


def _require_safe_archive_name(name: str) -> None:
    require(bool(name), "archive contains an empty path")
    require("\\" not in name, f"archive contains a backslash path: {name}")
    require(":" not in name, f"archive contains an ADS or drive path: {name}")
    require(
        not any(ord(character) < 32 or ord(character) == 127 for character in name),
        f"archive contains a control character: {name!r}",
    )
    parts = name.split("/")
    require(all(part not in {"", ".", ".."} for part in parts), f"unsafe archive path: {name}")
    parsed = PurePosixPath(name)
    require(not parsed.is_absolute(), f"absolute archive path: {name}")
    require(unicodedata.normalize("NFC", name) == name, f"non-NFC archive path: {name}")
    reserved = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
    for part in parsed.parts:
        require(not part.endswith((" ", ".")), f"archive path has trailing dot/space: {name}")
        require(part.split(".", 1)[0].casefold() not in reserved, f"reserved archive path: {name}")


def _preflight_zip(path: Path, maximum_entries: int, maximum_cd_bytes: int) -> int:
    require_plain_file(path, ARTIFACT_MAX_BYTES, "ZIP archive")
    file_size = path.stat().st_size
    require(file_size >= 22, "ZIP is shorter than its end record")
    with path.open("rb") as handle:
        handle.seek(-22, os.SEEK_END)
        end = handle.read(22)
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack("<4s4H2LH", end)
    require(signature == b"PK\x05\x06", "ZIP end record is missing or ZIP has a comment")
    require(comment_length == 0, "ZIP comments are forbidden")
    require(
        disk_number == 0 and central_disk == 0 and disk_entries == total_entries,
        "multidisk ZIPs are forbidden",
    )
    require(0 < total_entries <= maximum_entries, "ZIP entry count is invalid")
    require(total_entries != 0xFFFF, "ZIP64 entry counts are forbidden")
    require(central_size <= maximum_cd_bytes, "ZIP central directory is too large")
    require(
        central_offset + central_size == file_size - 22,
        "ZIP central-directory bounds are invalid",
    )
    actual_entries = 0
    remaining = central_size
    with path.open("rb") as handle:
        handle.seek(central_offset)
        while remaining:
            require(remaining >= 46, "truncated central-directory header")
            header = handle.read(46)
            require(len(header) == 46 and header[:4] == b"PK\x01\x02", "bad central header")
            name_length, extra_length, member_comment_length = struct.unpack(
                "<3H", header[28:34]
            )
            record_size = 46 + name_length + extra_length + member_comment_length
            require(record_size <= remaining, "central-directory record exceeds bounds")
            handle.seek(record_size - 46, os.SEEK_CUR)
            remaining -= record_size
            actual_entries += 1
    require(actual_entries == total_entries, "ZIP entry count differs from raw directory")
    return total_entries


def _tree_digest_header() -> "hashlib._Hash":
    digest = hashlib.sha256()
    digest.update(b"clicky-dist-tree-v1\0")
    return digest


def verify_distribution_archive(
    path: Path, runtime: dict[str, object], executable_output: Path | None = None
) -> dict[str, object]:
    require_plain_file(path, DIST_ARCHIVE_MAX_BYTES, "distribution archive")
    raw_count = _preflight_zip(path, DIST_MAX_FILES, DIST_MAX_CENTRAL_DIRECTORY_BYTES)
    tree_digest = _tree_digest_header()
    archive_digest = sha256_file(path)
    total_bytes = 0
    executable_digest: str | None = None
    executable_bytes = 0
    seen: set[str] = set()
    folded: set[str] = set()

    if executable_output is not None:
        executable_output.parent.mkdir(parents=True, exist_ok=True)
        require(not executable_output.exists(), "executable output already exists")

    with zipfile.ZipFile(path, "r", allowZip64=False) as archive:
        require(archive.comment == b"", "distribution archive comment is forbidden")
        members = archive.infolist()
        require(len(members) == raw_count, "parsed distribution entry count differs")
        names = [member.filename for member in members]
        require(names == sorted(names), "distribution members are not sorted")
        for member in members:
            name = member.filename
            _require_safe_archive_name(name)
            require(name not in seen, f"duplicate distribution member: {name}")
            folded_name = name.casefold()
            require(folded_name not in folded, f"case-colliding distribution member: {name}")
            seen.add(name)
            folded.add(folded_name)
            require(not member.is_dir(), f"directory member is forbidden: {name}")
            require(member.flag_bits & 0x1 == 0, f"encrypted distribution member: {name}")
            require(member.compress_type == zipfile.ZIP_DEFLATED, f"wrong compression: {name}")
            require(member.date_time == (1980, 1, 1, 0, 0, 0), f"non-deterministic time: {name}")
            require(member.create_system == 3, f"wrong creator system: {name}")
            require(
                member.external_attr == (stat.S_IFREG | 0o644) << 16,
                f"wrong member mode: {name}",
            )
            require(member.extra == b"" and member.comment == b"", f"extra metadata: {name}")
            require(member.file_size <= DIST_MAX_MEMBER_BYTES, f"oversized member: {name}")
            require(member.compress_size > 0 or member.file_size == 0, f"invalid size: {name}")
            if member.compress_size:
                require(
                    member.file_size <= member.compress_size * DIST_MAX_COMPRESSION_RATIO,
                    f"excessive compression ratio: {name}",
                )
            total_bytes += member.file_size
            require(total_bytes <= DIST_MAX_TOTAL_BYTES, "distribution expands past limit")

            encoded = name.encode("utf-8")
            tree_digest.update(b"F")
            tree_digest.update(len(encoded).to_bytes(8, "big"))
            tree_digest.update(encoded)
            tree_digest.update(member.file_size.to_bytes(8, "big"))
            member_digest = hashlib.sha256()
            copied = 0
            output_handle: BinaryIO | None = None
            try:
                if name == "Clicky.exe" and executable_output is not None:
                    output_handle = executable_output.open("xb")
                with archive.open(member, "r") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        copied += len(chunk)
                        tree_digest.update(chunk)
                        member_digest.update(chunk)
                        if output_handle is not None:
                            output_handle.write(chunk)
            finally:
                if output_handle is not None:
                    output_handle.close()
            require(copied == member.file_size, f"short distribution member: {name}")
            if name == "Clicky.exe":
                executable_digest = member_digest.hexdigest()
                executable_bytes = copied

    require(executable_digest is not None, "distribution does not contain Clicky.exe")
    require(executable_bytes <= EXECUTABLE_MAX_BYTES, "Clicky.exe exceeds size limit")
    identity = {
        "archive_sha256": archive_digest,
        "archive_bytes": path.stat().st_size,
        "tree_sha256": tree_digest.hexdigest(),
        "file_count": raw_count,
        "total_bytes": total_bytes,
        "clicky_exe_sha256": executable_digest,
        "clicky_exe_bytes": executable_bytes,
    }
    expected = runtime["distribution_integrity"]
    require(isinstance(expected, dict), "runtime distribution evidence is not an object")
    require(expected.get("scheme") == "clicky-dist-tree-v1", "wrong tree identity scheme")
    require(expected.get("unchanged") is True, "runtime distribution was not unchanged")
    require(
        expected.get("pristine_tree_sha256") == identity["tree_sha256"]
        and expected.get("post_execution_tree_sha256") == identity["tree_sha256"],
        "runtime tree identity differs from archive",
    )
    for key in ("archive_sha256", "archive_bytes", "file_count", "total_bytes", "clicky_exe_sha256"):
        require(expected.get(key) == identity[key], f"runtime {key} differs from archive")
    return identity


def _require_true_fields(value: object, fields: tuple[str, ...], label: str) -> dict[str, object]:
    require(isinstance(value, dict), f"{label} is not an object")
    for field in fields:
        require(value.get(field) is True, f"{label}.{field} did not pass")
    return value


def _validate_cloud_tts_evidence(value: object, label: str) -> None:
    require(isinstance(value, dict), f"{label} is not an object")
    require(value.get("synthetic_text_only") is True, f"{label} used non-synthetic text")
    hosts = value.get("resolved_hosts")
    require(isinstance(hosts, list) and hosts, f"{label} hostname evidence is missing")
    normalized_hosts = {
        str(host).rstrip(".").encode("idna").decode("ascii").lower() for host in hosts
    }
    require(normalized_hosts == {"speech.platform.bing.com"}, f"{label} host differs")
    resolved = value.get("resolved_public_addresses")
    require(isinstance(resolved, list) and resolved, f"{label} public addresses are missing")
    public: set[str] = set()
    for raw in resolved:
        try:
            address = ipaddress.ip_address(str(raw).split("%", 1)[0])
        except ValueError as exc:
            raise HarnessError(f"{label} contains an invalid address") from exc
        require(address.is_global, f"{label} contains a non-public DNS answer")
        public.add(str(address))
    correlated_value = value.get("correlated_tcp_addresses")
    require(isinstance(correlated_value, list) and correlated_value, f"{label} peer is missing")
    correlated = {str(raw).split("%", 1)[0] for raw in correlated_value}
    require(correlated <= public, f"{label} TCP peer differs from DNS answers")
    audio_bytes = value.get("audio_bytes")
    require(isinstance(audio_bytes, int) and audio_bytes > 0, f"{label} returned no audio")


def _require_nonempty_string_list(value: object, label: str) -> list[str]:
    require(isinstance(value, list) and value, f"{label} is empty")
    require(all(isinstance(item, str) and item for item in value), f"{label} is invalid")
    require(len(set(value)) == len(value), f"{label} contains duplicates")
    return value


def validate_runtime_report(
    path: Path, target_sha: str, workflow_sha: str
) -> dict[str, object]:
    require_plain_file(path, RUNTIME_REPORT_MAX_BYTES, "runtime report")
    report = _json_loads_strict(path.read_bytes(), "runtime report")
    require(isinstance(report, dict), "runtime report root is not an object")
    required_top = {
        "audio_crash_cleanup", "distribution_integrity", "dpapi", "executable",
        "privacy_controls", "python", "runtime_boundary", "unsigned_application",
    }
    require(set(report) == required_top, "runtime report top-level schema differs")
    require(isinstance(report["python"], str) and report["python"].startswith("3.12."), "runtime Python differs")
    require(isinstance(report["executable"], str) and report["executable"], "runtime executable is missing")
    target_sha = require_commit(target_sha, "target SHA")
    workflow_sha = require_commit(workflow_sha, "workflow SHA")
    expected_boundary = {
        "kind": "github-hosted-windows",
        "commit": target_sha,
        "workflow_commit": workflow_sha,
    }
    boundary = report["runtime_boundary"]
    require(isinstance(boundary, dict) and boundary == expected_boundary, "runtime boundary identity differs")

    crash = _require_true_fields(report["audio_crash_cleanup"], ("leftover_removed",), "audio_crash_cleanup")
    require(crash.get("crash_exit_code") == 73, "crash child exit evidence differs")
    require(isinstance(crash.get("audio_directory_sddl"), str), "audio directory ACL evidence is missing")
    require(isinstance(crash.get("audio_file_sddl"), str), "audio file ACL evidence is missing")
    dpapi = _require_true_fields(report["dpapi"], ("round_trip", "plaintext_absent"), "dpapi")
    require(isinstance(dpapi.get("protected_bytes"), int) and dpapi["protected_bytes"] > 0, "DPAPI protected-byte evidence is missing")

    privacy = _require_true_fields(
        report["privacy_controls"],
        (
            "microphone_denied_before_consent", "recording_denied_before_consent",
            "microphone_started_after_consent", "recording_started_after_consent",
            "microphone_stopped_after_revocation",
            "microphone_recording_cancelled_after_revocation",
            "microphone_standby_after_regrant", "cloud_tts_denied_before_consent",
            "screen_denied_before_consent", "clicky_owned_window_excluded",
            "owned_window_fallback_restored",
        ),
        "privacy_controls",
    )
    require(
        privacy.get("microphone_device") == "synthetic listener; host audio input disabled",
        "microphone device evidence differs",
    )
    _validate_cloud_tts_evidence(privacy.get("cloud_tts_after_consent"), "source cloud TTS")
    screens = privacy.get("screen_capture_after_consent")
    require(isinstance(screens, list) and screens, "screen capture evidence is empty")
    for screen in screens:
        require(
            isinstance(screen, dict)
            and isinstance(screen.get("width"), int) and screen["width"] > 0
            and isinstance(screen.get("height"), int) and screen["height"] > 0,
            "screen dimension evidence is invalid",
        )

    unsigned = report["unsigned_application"]
    require(isinstance(unsigned, dict), "unsigned application evidence is not an object")
    require(unsigned.get("external_destinations_before_consent") == [], "pre-consent network seen")
    titles = unsigned.get("window_titles")
    require(
        isinstance(titles, list)
        and any(isinstance(title, str) and "privacy permissions" in title.lower() for title in titles),
        "first-run privacy dialog evidence is missing",
    )
    signature = unsigned.get("authenticode")
    require(isinstance(signature, dict) and signature.get("Status") == "NotSigned", "unexpected signature")
    require_hash(str(unsigned.get("sha256", "")), "runtime Clicky.exe SHA-256")

    packaged = unsigned.get("packaged_security_self_test")
    require(isinstance(packaged, dict), "packaged self-test evidence is missing")
    require(
        set(packaged)
        == {
            "runtime_boundary", "dpapi_token_persistence", "secure_audio",
            "bundled_skills", "privacy_defaults", "microphone_state",
            "screen_capture", "cloud_tts",
        },
        "packaged self-test schema differs",
    )
    packaged_boundary = packaged["runtime_boundary"]
    require(isinstance(packaged_boundary, dict), "packaged boundary is not an object")
    require(packaged_boundary.get("kind") == expected_boundary["kind"], "packaged boundary differs")
    require(packaged_boundary.get("commit") == target_sha, "packaged target commit differs")
    require(packaged_boundary.get("workflow_commit") == workflow_sha, "packaged workflow commit differs")
    require(packaged_boundary.get("frozen") is True, "packaged self-test was not frozen")
    packaged_executable = packaged_boundary.get("executable")
    require(
        isinstance(packaged_executable, str) and packaged_executable.lower().endswith("clicky.exe"),
        "packaged executable identity differs",
    )

    packaged_dpapi = _require_true_fields(
        packaged["dpapi_token_persistence"],
        ("magic_present", "plaintext_absent", "same_process_read", "second_process_read"),
        "packaged.dpapi_token_persistence",
    )
    require(
        isinstance(packaged_dpapi.get("encrypted_bytes"), int)
        and packaged_dpapi["encrypted_bytes"] > 0,
        "packaged DPAPI encrypted-byte evidence is missing",
    )
    _require_true_fields(packaged["secure_audio"], ("private_write", "normal_cleanup"), "packaged.secure_audio")
    bundled = packaged["bundled_skills"]
    require(isinstance(bundled, dict), "packaged bundled-skill evidence is missing")
    _require_nonempty_string_list(bundled.get("verified_files"), "packaged verified skills")
    _require_nonempty_string_list(bundled.get("loaded_names"), "packaged loaded skills")

    defaults = packaged["privacy_defaults"]
    require(isinstance(defaults, dict), "packaged privacy defaults are missing")
    for key in ("notice_accepted", "microphone_allowed", "cloud_tts_allowed", "screen_capture_allowed"):
        require(defaults.get(key) is False, f"packaged privacy default is enabled: {key}")
    microphone = _require_true_fields(
        packaged["microphone_state"],
        ("cancelled_after_revocation", "standby_after_regrant"),
        "packaged.microphone_state",
    )
    require(set(microphone) >= {"cancelled_after_revocation", "standby_after_regrant"}, "microphone evidence differs")
    packaged_screen = _require_true_fields(
        packaged["screen_capture"], ("synthetic_content_excluded",), "packaged.screen_capture"
    )
    packaged_screens = packaged_screen.get("screens")
    require(isinstance(packaged_screens, list) and packaged_screens, "packaged screen evidence is empty")
    _validate_cloud_tts_evidence(packaged["cloud_tts"], "packaged cloud TTS")
    return report

def create_evidence_archive(
    source: Path,
    runtime_path: Path,
    distribution: Path,
    executable_copy: Path,
    output: Path,
    target_sha: str,
    expected_source_sha: str,
    workflow_sha: str,
) -> dict[str, object]:
    """Create the small evidence ZIP; candidate binaries remain separate."""
    target_sha = require_commit(target_sha, "target SHA")
    workflow_sha = require_commit(workflow_sha, "workflow SHA")
    expected_source_sha = require_hash(expected_source_sha, "source SHA-256")
    require_plain_file(source, SOURCE_MAX_BYTES, "source archive")
    require(sha256_file(source) == expected_source_sha, "source archive hash differs")
    runtime = validate_runtime_report(runtime_path, target_sha, workflow_sha)
    identity = verify_distribution_archive(distribution, runtime)
    require_plain_file(executable_copy, EXECUTABLE_MAX_BYTES, "runtime executable copy")
    executable_sha = sha256_file(executable_copy)
    require(executable_sha == identity["clicky_exe_sha256"], "runtime EXE differs from dist")
    with executable_copy.open("rb") as handle:
        require(handle.read(2) == b"MZ", "runtime executable is not a PE file")
    require(not output.exists(), "evidence archive output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    direct_files = {
        "clicky-executable.exe": executable_copy,
        "clicky-full-dist.zip": distribution,
        "clicky-source.zip": source,
        "runtime/runtime-validation.json": runtime_path,
    }
    manifest = {
        "schema": 2,
        "repository": REPOSITORY,
        "target_sha": target_sha,
        "trusted_workflow_sha": workflow_sha,
        "expected_source_archive_sha256": expected_source_sha,
        "files": {
            name: {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
            for name, path in sorted(direct_files.items())
        },
    }
    payloads: dict[str, bytes | Path] = {
        "PASS.txt": b"PASS\n",
        "manifest.json": _json_bytes(manifest),
        "runtime/runtime-validation.json": runtime_path,
    }
    with zipfile.ZipFile(
        output,
        "x",
        compression=zipfile.ZIP_STORED,
        allowZip64=False,
        strict_timestamps=True,
    ) as archive:
        for name in EVIDENCE_MEMBERS:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            payload = payloads[name]
            if isinstance(payload, bytes):
                archive.writestr(info, payload)
            else:
                with payload.open("rb") as source_handle, archive.open(info, "w") as target:
                    shutil.copyfileobj(source_handle, target, length=1024 * 1024)
    require_plain_file(output, 3 * 1024 * 1024, "runtime evidence archive")
    return {"manifest": manifest, "evidence_sha256": sha256_file(output)}


def verify_evidence_archive(
    evidence_path: Path,
    source: Path,
    distribution: Path,
    executable: Path,
    output_directory: Path,
    target_sha: str,
    expected_source_sha: str,
    workflow_sha: str,
) -> dict[str, object]:
    """Parse candidate evidence only in the age-only verifier VM."""
    target_sha = require_commit(target_sha, "target SHA")
    expected_source_sha = require_hash(expected_source_sha, "source SHA-256")
    workflow_sha = require_commit(workflow_sha, "workflow SHA")
    require_plain_file(evidence_path, 3 * 1024 * 1024, "decrypted evidence archive")
    require_plain_file(source, SOURCE_MAX_BYTES, "decrypted source archive")
    require_plain_file(distribution, DIST_ARCHIVE_MAX_BYTES, "decrypted distribution archive")
    require_plain_file(executable, EXECUTABLE_MAX_BYTES, "decrypted executable")
    require(sha256_file(source) == expected_source_sha, "source archive expectation differs")
    raw_count = _preflight_zip(evidence_path, len(EVIDENCE_MEMBERS), 1024 * 1024)
    require(raw_count == len(EVIDENCE_MEMBERS), "evidence archive member count differs")
    require(not output_directory.exists(), "verified output directory already exists")
    output_directory.mkdir(parents=True)
    extracted: dict[str, Path] = {}
    with zipfile.ZipFile(evidence_path, "r", allowZip64=False) as archive:
        require(archive.comment == b"", "evidence archive comment is forbidden")
        members = archive.infolist()
        require(tuple(member.filename for member in members) == EVIDENCE_MEMBERS, "evidence paths differ")
        for member in members:
            _require_safe_archive_name(member.filename)
            require(not member.is_dir(), "evidence directories are forbidden")
            require(member.compress_type == zipfile.ZIP_STORED, "evidence must be stored")
            require(member.date_time == (1980, 1, 1, 0, 0, 0), "evidence time differs")
            require(member.create_system == 3, "evidence creator system differs")
            require(member.external_attr == (stat.S_IFREG | 0o600) << 16, "evidence mode differs")
            require(member.flag_bits & 0x1 == 0, "encrypted ZIP members are forbidden")
            require(member.extra == b"" and member.comment == b"", "evidence metadata differs")
            maximum = {
                "PASS.txt": 32,
                "manifest.json": 64 * 1024,
                "runtime/runtime-validation.json": RUNTIME_REPORT_MAX_BYTES,
            }[member.filename]
            require(0 < member.file_size <= maximum, "evidence member size is invalid")
            target = output_directory / member.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source_handle, target.open("xb") as output:
                shutil.copyfileobj(source_handle, output, length=1024 * 1024)
            require(target.stat().st_size == member.file_size, "evidence extraction was short")
            extracted[member.filename] = target

    require(extracted["PASS.txt"].read_bytes() == b"PASS\n", "PASS evidence differs")
    manifest_value = _json_loads_strict(extracted["manifest.json"].read_bytes(), "manifest")
    require(isinstance(manifest_value, dict), "manifest root is not an object")
    require(
        set(manifest_value)
        == {
            "schema", "repository", "target_sha", "trusted_workflow_sha",
            "expected_source_archive_sha256", "files",
        },
        "manifest schema differs",
    )
    require(manifest_value.get("schema") == 2, "manifest version differs")
    require(manifest_value.get("repository") == REPOSITORY, "manifest repository differs")
    require(manifest_value.get("target_sha") == target_sha, "manifest target differs")
    require(manifest_value.get("trusted_workflow_sha") == workflow_sha, "manifest workflow differs")
    require(
        manifest_value.get("expected_source_archive_sha256") == expected_source_sha,
        "manifest source expectation differs",
    )
    direct_files = {
        "clicky-executable.exe": executable,
        "clicky-full-dist.zip": distribution,
        "clicky-source.zip": source,
        "runtime/runtime-validation.json": extracted["runtime/runtime-validation.json"],
    }
    file_manifest = manifest_value.get("files")
    require(isinstance(file_manifest, dict) and set(file_manifest) == set(direct_files), "file manifest differs")
    for name, path in sorted(direct_files.items()):
        record = file_manifest[name]
        require(isinstance(record, dict) and set(record) == {"bytes", "sha256"}, "file record differs")
        require(record["bytes"] == path.stat().st_size, f"manifest size differs: {name}")
        require(record["sha256"] == sha256_file(path), f"manifest hash differs: {name}")

    runtime = validate_runtime_report(
        extracted["runtime/runtime-validation.json"], target_sha, workflow_sha
    )
    reconstructed = output_directory / "reconstructed" / "Clicky.exe"
    identity = verify_distribution_archive(distribution, runtime, reconstructed)
    direct_executable_sha = sha256_file(executable)
    require(direct_executable_sha == identity["clicky_exe_sha256"], "direct EXE differs from dist")
    require(sha256_file(reconstructed) == direct_executable_sha, "reconstructed EXE differs")
    with executable.open("rb") as handle:
        require(handle.read(2) == b"MZ", "direct Clicky.exe is not a PE file")
    unsigned = runtime["unsigned_application"]
    require(unsigned["sha256"] == direct_executable_sha, "runtime EXE hash differs")
    return {
        "target_sha": target_sha,
        "workflow_sha": workflow_sha,
        "hashes": {
            "source": sha256_file(source),
            "distribution": identity["archive_sha256"],
            "executable": direct_executable_sha,
            "evidence": sha256_file(evidence_path),
        },
    }


def verify_scan_inputs(
    source: Path,
    distribution: Path,
    executable: Path,
    source_sha: str,
    distribution_sha: str,
    executable_sha: str,
) -> dict[str, str]:
    """Hash opaque candidates in the VT-secret VM without parsing or executing them."""
    require_plain_file(source, min(SOURCE_MAX_BYTES, VT_MAX_UPLOAD_BYTES), "scan source")
    require_plain_file(distribution, min(DIST_ARCHIVE_MAX_BYTES, VT_MAX_UPLOAD_BYTES), "scan dist")
    require_plain_file(executable, min(EXECUTABLE_MAX_BYTES, VT_MAX_UPLOAD_BYTES), "scan executable")
    expected = {
        "source": require_hash(source_sha, "expected source scan hash"),
        "distribution": require_hash(distribution_sha, "expected dist scan hash"),
        "executable": require_hash(executable_sha, "expected EXE scan hash"),
    }
    actual = {
        "source": sha256_file(source),
        "distribution": sha256_file(distribution),
        "executable": sha256_file(executable),
    }
    require(actual == expected, "scanner inputs differ from verifier outputs")
    return actual

def install_age(output: Path) -> str:
    require(not output.exists(), "age output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="clicky-age-") as temporary:
        archive_path = Path(temporary) / "age.zip"
        request = urllib.request.Request(
            AGE_URL,
            headers={"User-Agent": f"clicky-quarantine-age/{AGE_VERSION}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response, archive_path.open("xb") as target:
                require(response.status == 200, f"age download returned HTTP {response.status}")
                copied = 0
                for chunk in iter(lambda: response.read(1024 * 1024), b""):
                    copied += len(chunk)
                    require(copied <= AGE_ARCHIVE_MAX_BYTES, "age archive exceeds size limit")
                    target.write(chunk)
        except urllib.error.URLError as exc:
            raise HarnessError(f"could not download pinned age release: {exc}") from exc
        require(sha256_file(archive_path) == AGE_ARCHIVE_SHA256, "age archive SHA-256 differs")
        _preflight_zip(archive_path, 32, 128 * 1024)
        with zipfile.ZipFile(archive_path, "r", allowZip64=False) as archive:
            candidates = [member for member in archive.infolist() if member.filename == "age/age.exe"]
            require(len(candidates) == 1, "pinned age archive does not contain one age.exe")
            member = candidates[0]
            require(not member.is_dir() and member.file_size <= 16 * 1024 * 1024, "age.exe is invalid")
            with archive.open(member, "r") as source, output.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    require_plain_file(output, 16 * 1024 * 1024, "age.exe")
    return sha256_file(output)


def verify_ciphertext_directory(directory: Path) -> dict[str, object]:
    require(directory.is_dir() and not directory.is_symlink(), "ciphertext directory is invalid")
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    require(tuple(path.name for path in entries) == CIPHERTEXT_MEMBERS, "artifact is not ciphertext-only")
    limits = {
        "clicky-executable.exe.age": EXECUTABLE_MAX_BYTES + 1024 * 1024,
        "clicky-full-dist.zip.age": DIST_ARCHIVE_MAX_BYTES + 1024 * 1024,
        "clicky-runtime-evidence.zip.age": 4 * 1024 * 1024,
        "clicky-source.zip.age": SOURCE_MAX_BYTES + 1024 * 1024,
    }
    total = 0
    hashes: dict[str, str] = {}
    for ciphertext in entries:
        require_plain_file(ciphertext, limits[ciphertext.name], f"encrypted {ciphertext.name}")
        total += ciphertext.stat().st_size
        require(
            total <= CIPHERTEXT_PAYLOAD_MAX_BYTES,
            "ciphertext payload leaves insufficient room below the 480,000,000-byte cap",
        )
        with ciphertext.open("rb") as handle:
            require(
                handle.read(len(b"age-encryption.org/v1\n")) == b"age-encryption.org/v1\n",
                f"{ciphertext.name} is not age ciphertext",
            )
        hashes[ciphertext.name] = sha256_file(ciphertext)
    return {"bytes": total, "hashes": hashes}

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class _NoProxyHandler(urllib.request.ProxyHandler):
    def __init__(self) -> None:
        super().__init__({})

    def http_request(self, request):  # noqa: ANN001
        return request

    https_request = http_request


_VT_OPENER = urllib.request.build_opener(
    _NoProxyHandler(),
    urllib.request.HTTPSHandler(),
    _NoRedirectHandler(),
)
_VT_LAST_REQUEST_STARTED: float | None = None


def _pace_vt_request() -> None:
    global _VT_LAST_REQUEST_STARTED
    now = time.monotonic()
    if _VT_LAST_REQUEST_STARTED is not None:
        delay = _VT_LAST_REQUEST_STARTED + VT_REQUEST_MIN_INTERVAL_SECONDS - now
        if delay > 0:
            time.sleep(delay)
            now = time.monotonic()
    _VT_LAST_REQUEST_STARTED = now


def _require_vt_url(url: str, *, api_only: bool) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https", "VirusTotal URL must use HTTPS")
    require(parsed.username is None and parsed.password is None, "VirusTotal URL has credentials")
    require(parsed.port in {None, 443}, "VirusTotal URL has an unexpected port")
    require(not parsed.fragment, "VirusTotal URL has a fragment")
    host = (parsed.hostname or "").lower()
    if api_only:
        require(host == "www.virustotal.com", "VirusTotal API host differs")
        require(parsed.path.startswith("/api/v3/"), "VirusTotal API path differs")
    else:
        require(
            host == "www.virustotal.com" or host.endswith(".virustotal.com"),
            "VirusTotal upload host differs",
        )
    return parsed


def _bounded_retry_after(headers: object) -> int:
    value = headers.get("Retry-After") if hasattr(headers, "get") else None
    require(isinstance(value, str) and value.isdecimal(), "VirusTotal Retry-After is invalid")
    seconds = int(value)
    require(1 <= seconds <= 60, "VirusTotal Retry-After is outside the safe bound")
    return seconds


def _vt_request_json(
    url: str,
    api_key: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
) -> dict[str, object]:
    _require_vt_url(url, api_only=True)
    require(method == "GET" or method == "POST", "unsupported VirusTotal method")
    headers = {"x-apikey": api_key, "User-Agent": "clicky-quarantine/1"}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    retries = 0
    waited = 0
    while True:
        _pace_vt_request()
        try:
            with _VT_OPENER.open(request, timeout=90) as response:
                require(200 <= response.status < 300, f"VirusTotal returned HTTP {response.status}")
                payload = response.read(8 * 1024 * 1024 + 1)
            break
        except urllib.error.HTTPError as exc:
            if method == "GET" and exc.code == 429:
                retries += 1
                require(retries <= 5, "VirusTotal rate-limit retry count exceeded")
                seconds = _bounded_retry_after(exc.headers)
                waited += seconds
                require(waited <= 180, "VirusTotal rate-limit wait budget exceeded")
                time.sleep(seconds)
                continue
            safe_body = exc.read(4096).decode("utf-8", "replace")
            raise HarnessError(f"VirusTotal HTTP {exc.code}: {safe_body}") from exc
        except urllib.error.URLError as exc:
            raise HarnessError(f"VirusTotal request failed: {exc}") from exc
    require(len(payload) <= 8 * 1024 * 1024, "VirusTotal response exceeds size limit")
    value = _json_loads_strict(payload, "VirusTotal response")
    require(isinstance(value, dict), "VirusTotal response root is not an object")
    return value

def _vt_upload_file(url: str, path: Path, api_key: str) -> dict[str, object]:
    parsed = _require_vt_url(url, api_only=False)
    host = (parsed.hostname or "").lower()
    boundary = f"----clicky-{uuid.uuid4().hex}"
    prefix = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("ascii")
    suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
    content_length = len(prefix) + path.stat().st_size + len(suffix)
    _pace_vt_request()
    connection = http.client.HTTPSConnection(host, parsed.port or 443, timeout=120)
    try:
        request_path = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
        connection.putrequest("POST", request_path)
        connection.putheader("x-apikey", api_key)
        connection.putheader("User-Agent", "clicky-quarantine/1")
        connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        connection.putheader("Content-Length", str(content_length))
        connection.endheaders()
        connection.send(prefix)
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                connection.send(chunk)
        connection.send(suffix)
        response = connection.getresponse()
        payload = response.read(8 * 1024 * 1024 + 1)
        require(200 <= response.status < 300, f"VirusTotal upload returned HTTP {response.status}")
        require(len(payload) <= 8 * 1024 * 1024, "VirusTotal upload response is too large")
    finally:
        connection.close()
    value = _json_loads_strict(payload, "VirusTotal upload response")
    require(isinstance(value, dict), "VirusTotal upload response root is not an object")
    return value


def _sanitize_vt_stats(value: object, label: str) -> dict[str, int]:
    require(isinstance(value, dict) and value, f"{label} stats are missing")
    sanitized: dict[str, int] = {}
    for key, count in sorted(value.items()):
        require(isinstance(key, str) and re.fullmatch(r"[a-z-]+", key) is not None, f"{label} stat key is invalid")
        require(isinstance(count, int) and 0 <= count <= 1000, f"{label} stat count is invalid")
        sanitized[key] = count
    return sanitized


def _sanitize_vt_results(value: object, label: str) -> dict[str, dict[str, object]]:
    require(isinstance(value, dict) and value, f"{label} engine results are missing")
    sanitized: dict[str, dict[str, object]] = {}
    for engine, result in sorted(value.items()):
        require(isinstance(engine, str) and 1 <= len(engine) <= 200, f"{label} engine name is invalid")
        require("\r" not in engine and "\n" not in engine, f"{label} engine name contains a newline")
        require(isinstance(result, dict) and result, f"{label} engine record is invalid")
        clean_record: dict[str, object] = {}
        for key, item in sorted(result.items()):
            require(isinstance(key, str) and 1 <= len(key) <= 100, f"{label} engine field is invalid")
            require(item is None or isinstance(item, (bool, int, str)), f"{label} engine value is nested")
            if isinstance(item, str):
                require(len(item) <= 4096 and "\r" not in item and "\n" not in item, f"{label} engine value is unsafe")
            clean_record[key] = item
        sanitized[engine] = clean_record
    return sanitized


def _require_clean_vt_report(
    stats: dict[str, int], results: dict[str, dict[str, object]], label: str,
    *, require_vendor_votes: bool,
) -> None:
    require(stats.get("malicious") == 0, f"VirusTotal marked {label} malicious")
    require(stats.get("suspicious") == 0, f"VirusTotal marked {label} suspicious")
    participating = stats.get("undetected", 0) + stats.get("harmless", 0)
    require(participating >= 50, f"VirusTotal clean-engine coverage is below 50 for {label}")
    if require_vendor_votes:
        for engine in ("Malwarebytes", "Microsoft"):
            result = results.get(engine)
            require(isinstance(result, dict), f"VirusTotal {engine} result is missing")
            require(result.get("category") == "undetected", f"VirusTotal {engine} did not report undetected")


def _vt_scan_one(path: Path, api_key: str) -> dict[str, object]:
    require_plain_file(path, VT_MAX_UPLOAD_BYTES, f"VirusTotal input {path.name}")
    digest = sha256_file(path)
    upload_url = VT_UPLOAD_URL
    if path.stat().st_size > VT_DIRECT_UPLOAD_BYTES:
        upload = _vt_request_json(VT_LARGE_UPLOAD_URL, api_key)
        upload_url_value = upload.get("data")
        require(isinstance(upload_url_value, str), "VirusTotal large-upload URL is missing")
        upload_url = upload_url_value
    submitted = _vt_upload_file(upload_url, path, api_key)
    data = submitted.get("data")
    require(isinstance(data, dict), "VirusTotal upload data is missing")
    analysis_id = data.get("id")
    require(isinstance(analysis_id, str) and 1 <= len(analysis_id) <= 512, "analysis ID is invalid")
    require(re.fullmatch(r"[A-Za-z0-9_.=-]+", analysis_id) is not None, "analysis ID is unsafe")

    deadline = time.monotonic() + VT_ANALYSIS_TIMEOUT_SECONDS
    analysis_data: dict[str, object] | None = None
    while time.monotonic() < deadline:
        analysis = _vt_request_json(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", api_key
        )
        candidate = analysis.get("data")
        require(isinstance(candidate, dict), "VirusTotal analysis data is missing")
        require(candidate.get("id") == analysis_id, "VirusTotal analysis ID differs")
        attributes = candidate.get("attributes")
        require(isinstance(attributes, dict), "VirusTotal analysis attributes are missing")
        status_value = attributes.get("status")
        require(status_value in {"queued", "in-progress", "completed"}, "unknown analysis status")
        if status_value == "completed":
            analysis_data = candidate
            break
        time.sleep(VT_POLL_SECONDS)
    else:
        raise HarnessError(f"VirusTotal analysis timed out for {path.name}")

    assert analysis_data is not None
    analysis_attributes = analysis_data["attributes"]
    analysis_date = analysis_attributes.get("date")
    require(isinstance(analysis_date, int) and analysis_date > 0, "analysis date is missing")
    analysis_stats = _sanitize_vt_stats(analysis_attributes.get("stats"), "analysis")
    analysis_results = _sanitize_vt_results(analysis_attributes.get("results"), "analysis")
    file_data: dict[str, object] | None = None
    while time.monotonic() < deadline:
        file_report = _vt_request_json(
            f"https://www.virustotal.com/api/v3/files/{digest}", api_key
        )
        candidate = file_report.get("data")
        require(isinstance(candidate, dict), "VirusTotal file data is missing")
        require(candidate.get("id") == digest, "VirusTotal file ID differs from local SHA-256")
        attributes = candidate.get("attributes")
        require(isinstance(attributes, dict), "VirusTotal file attributes are missing")
        file_date = attributes.get("last_analysis_date")
        if isinstance(file_date, int) and file_date >= analysis_date:
            file_data = candidate
            break
        time.sleep(VT_POLL_SECONDS)
    else:
        raise HarnessError(f"VirusTotal file report did not bind completed analysis for {path.name}")

    assert file_data is not None
    file_attributes = file_data["attributes"]
    file_stats = _sanitize_vt_stats(file_attributes.get("last_analysis_stats"), "file report")
    file_results = _sanitize_vt_results(file_attributes.get("last_analysis_results"), "file report")
    return {
        "sha256": digest,
        "bytes": path.stat().st_size,
        "analysis_id": analysis_id,
        "file_id": file_data["id"],
        "analysis_date": analysis_date,
        "file_analysis_date": file_attributes["last_analysis_date"],
        "analysis_report": {"stats": analysis_stats, "results": analysis_results},
        "file_report": {"stats": file_stats, "results": file_results},
        "minimum_clean_participating_engines": 50,
    }


def _vt_gate_failures(files: dict[str, dict[str, object]]) -> list[str]:
    failures: list[str] = []
    for label, details in files.items():
        require_vendor_votes = label == "clicky_executable"
        for report_name in ("analysis_report", "file_report"):
            report = details[report_name]
            require(isinstance(report, dict), f"{label}.{report_name} is invalid")
            stats = report.get("stats")
            results = report.get("results")
            require(isinstance(stats, dict), f"{label}.{report_name} stats are invalid")
            require(isinstance(results, dict), f"{label}.{report_name} results are invalid")
            try:
                _require_clean_vt_report(
                    stats,
                    results,
                    label,
                    require_vendor_votes=require_vendor_votes,
                )
            except HarnessError as exc:
                failures.append(f"{label}.{report_name}: {exc}")
    return failures


def virus_total_scan(source: Path, distribution: Path, executable: Path, output: Path) -> None:
    api_key = os.environ.get("VT_API_KEY", "").strip()
    require(20 <= len(api_key) <= 512, "VT_API_KEY secret is missing or invalid")
    require("\r" not in api_key and "\n" not in api_key, "VT_API_KEY contains a newline")
    require(not output.exists(), "VirusTotal report output already exists")
    files = {
        "source_archive": _vt_scan_one(source, api_key),
        "distribution_archive": _vt_scan_one(distribution, api_key),
        "clicky_executable": _vt_scan_one(executable, api_key),
    }
    failures = _vt_gate_failures(files)
    report = {
        "schema": 2,
        "verdict": "failed" if failures else "clean",
        "failures": failures,
        "files": files,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_json_bytes(report))
    print(json.dumps(report, sort_keys=True))
    require(
        not failures,
        "VirusTotal clean gate failed: " + "; ".join(failures),
    )


def _write_recipient(path: Path, value: str) -> None:
    require(not path.exists(), "recipient output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(validate_ssh_recipient(value) + "\n", encoding="ascii")


def _append_github_outputs(path: Path, values: dict[str, str]) -> None:
    require(path.exists() and path.is_file() and not path.is_symlink(), "GITHUB_OUTPUT is invalid")
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in sorted(values.items()):
            require(re.fullmatch(r"[a-z0-9_]+", key) is not None, "unsafe output key")
            require(SHA256_RE.fullmatch(value) is not None, "unsafe output value")
            handle.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-context")
    validate.add_argument("--recipient-output", type=Path)

    checkout = subparsers.add_parser("verify-target-checkout")
    checkout.add_argument("--root", type=Path, required=True)
    checkout.add_argument("--source-output", type=Path, required=True)
    checkout.add_argument("--target-sha", required=True)
    checkout.add_argument("--github-output", type=Path)

    assemble = subparsers.add_parser("assemble")
    assemble.add_argument("--source", type=Path, required=True)
    assemble.add_argument("--runtime-report", type=Path, required=True)
    assemble.add_argument("--distribution", type=Path, required=True)
    assemble.add_argument("--executable-copy", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--target-sha", required=True)
    assemble.add_argument("--expected-source-sha256", required=True)
    assemble.add_argument("--workflow-sha", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--source", type=Path, required=True)
    verify.add_argument("--distribution", type=Path, required=True)
    verify.add_argument("--executable", type=Path, required=True)
    verify.add_argument("--output-directory", type=Path, required=True)
    verify.add_argument("--target-sha", required=True)
    verify.add_argument("--expected-source-sha256", required=True)
    verify.add_argument("--workflow-sha", required=True)
    verify.add_argument("--github-output", type=Path)

    scan_inputs = subparsers.add_parser("verify-scan-inputs")
    scan_inputs.add_argument("--source", type=Path, required=True)
    scan_inputs.add_argument("--distribution", type=Path, required=True)
    scan_inputs.add_argument("--executable", type=Path, required=True)
    scan_inputs.add_argument("--source-sha256", required=True)
    scan_inputs.add_argument("--distribution-sha256", required=True)
    scan_inputs.add_argument("--executable-sha256", required=True)

    age = subparsers.add_parser("install-age")
    age.add_argument("--output", type=Path, required=True)
    age.add_argument("--github-output", type=Path)

    ciphertext = subparsers.add_parser("verify-ciphertext")
    ciphertext.add_argument("--directory", type=Path, required=True)

    vt = subparsers.add_parser("virus-total")
    vt.add_argument("--source", type=Path, required=True)
    vt.add_argument("--distribution", type=Path, required=True)
    vt.add_argument("--executable", type=Path, required=True)
    vt.add_argument("--output", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "validate-context":
        values = validate_context_from_environment(require_recipient=args.recipient_output is not None)
        if args.recipient_output is not None:
            _write_recipient(args.recipient_output, values["recipient"])
        print(json.dumps({key: values[key] for key in ("target_sha", "workflow_sha")}, sort_keys=True))
    elif args.command == "verify-target-checkout":
        result = verify_target_checkout(args.root, args.source_output, args.target_sha)
        if args.github_output is not None:
            _append_github_outputs(
                args.github_output,
                {"source_sha256": result["source_sha256"]},
            )
        print(json.dumps(result, sort_keys=True))
    elif args.command == "assemble":
        result = create_evidence_archive(
            args.source, args.runtime_report, args.distribution, args.executable_copy,
            args.output, args.target_sha, args.expected_source_sha256, args.workflow_sha,
        )
        print(json.dumps({"evidence_sha256": result["evidence_sha256"], "target_sha": result["manifest"]["target_sha"]}, sort_keys=True))
    elif args.command == "verify":
        result = verify_evidence_archive(
            args.evidence, args.source, args.distribution, args.executable,
            args.output_directory, args.target_sha, args.expected_source_sha256,
            args.workflow_sha,
        )
        if args.github_output is not None:
            _append_github_outputs(
                args.github_output,
                {
                    "source_sha256": result["hashes"]["source"],
                    "distribution_sha256": result["hashes"]["distribution"],
                    "executable_sha256": result["hashes"]["executable"],
                    "evidence_sha256": result["hashes"]["evidence"],
                },
            )
        print(json.dumps({"hashes": result["hashes"], "target_sha": result["target_sha"]}, sort_keys=True))
    elif args.command == "verify-scan-inputs":
        hashes = verify_scan_inputs(
            args.source, args.distribution, args.executable,
            args.source_sha256, args.distribution_sha256, args.executable_sha256,
        )
        print(json.dumps({"hashes": hashes}, sort_keys=True))
    elif args.command == "install-age":
        age_sha = install_age(args.output)
        if args.github_output is not None:
            _append_github_outputs(args.github_output, {"age_exe_sha256": age_sha})
        print(json.dumps({"age_exe_sha256": age_sha}, sort_keys=True))
    elif args.command == "verify-ciphertext":
        print(json.dumps(verify_ciphertext_directory(args.directory), sort_keys=True))
    elif args.command == "virus-total":
        virus_total_scan(args.source, args.distribution, args.executable, args.output)
    else:
        parser.error("unknown command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessError as exc:
        print(f"quarantine validation failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
