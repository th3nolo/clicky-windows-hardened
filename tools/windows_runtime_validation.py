"""Windows-only dynamic security validation for a disposable sandbox.

This script uses synthetic data and never requires real credentials, audio, or
screen content. Run it only inside Windows Sandbox after the frozen environment
and unsigned local-test build have been created.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CRASH_EXIT_CODE = 73


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _child_environment(data_dir: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["LOCALAPPDATA"] = str(data_dir)
    environment["APPDATA"] = str(data_dir / "Roaming")
    environment["TEMP"] = str(data_dir / "Temp")
    environment["TMP"] = str(data_dir / "Temp")
    environment["QT_QPA_PLATFORM"] = "offscreen"
    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "DEEPGRAM_API_KEY",
        "ELEVENLABS_API_KEY",
        "TAVILY_API_KEY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ):
        environment.pop(name, None)
    for directory in (
        Path(environment["LOCALAPPDATA"]),
        Path(environment["APPDATA"]),
        Path(environment["TEMP"]),
    ):
        directory.mkdir(parents=True, exist_ok=True)
    return environment


def _run_crash_child(data_dir: Path, marker: Path) -> None:
    os.environ.update(_child_environment(data_dir))
    from audio.secure_temp import secure_wav_file

    with secure_wav_file(b"RIFF synthetic crash-test audio") as path:
        marker.write_text(str(path), encoding="utf-8")
        os._exit(CRASH_EXIT_CODE)


def _run_cleanup_child(data_dir: Path) -> None:
    os.environ.update(_child_environment(data_dir))
    from audio.secure_temp import initialize_secure_audio_temp

    initialize_secure_audio_temp()


def _validate_crash_cleanup(root: Path) -> dict[str, object]:
    data_dir = root / "crash-profile"
    marker = root / "crash-path.txt"
    environment = _child_environment(data_dir)
    crashed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--crash-child",
            str(data_dir),
            str(marker),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    _require(
        crashed.returncode == CRASH_EXIT_CODE,
        f"crash child returned {crashed.returncode}: {crashed.stderr}",
    )
    abandoned = Path(marker.read_text(encoding="utf-8").strip())
    _require(abandoned.is_file(), "crash simulation did not leave its temporary WAV")

    acl = subprocess.run(
        ["icacls.exe", str(abandoned.parent)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    _require(acl.returncode == 0, f"could not inspect audio ACL: {acl.stderr}")
    broad_principals = ("Everyone:", "BUILTIN\\Users:", "Authenticated Users:")
    _require(
        not any(principal.lower() in acl.stdout.lower() for principal in broad_principals),
        f"private audio directory contains a broad ACL: {acl.stdout}",
    )

    cleaned = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--cleanup-child",
            str(data_dir),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    _require(cleaned.returncode == 0, f"cleanup child failed: {cleaned.stderr}")
    _require(not abandoned.exists(), "crash-leftover WAV survived the startup sweep")
    return {
        "crash_exit_code": crashed.returncode,
        "leftover_removed": True,
        "audio_directory_acl": acl.stdout.strip(),
    }


def _validate_dpapi() -> dict[str, object]:
    from ai import github_copilot_provider as github

    sample = b"clicky-dpapi-dynamic-test-not-a-secret"
    protected = github._dpapi_protect(sample)
    _require(protected != sample, "DPAPI returned plaintext bytes")
    _require(github._dpapi_unprotect(protected) == sample, "DPAPI round trip failed")
    return {
        "round_trip": True,
        "plaintext_absent": sample not in protected,
        "protected_bytes": len(protected),
    }


def _validate_privacy_controls(root: Path) -> dict[str, object]:
    environment = _child_environment(root / "privacy-profile")
    os.environ.clear()
    os.environ.update(environment)

    from PyQt6.QtCore import QCoreApplication

    import companion_manager
    from audio.tts.base_tts import DisabledTTSProvider
    from config import cfg
    from privacy_controls import (
        PRIVACY_NOTICE_VERSION,
        cloud_tts_allowed,
        microphone_allowed,
        screen_capture_allowed,
    )

    app = QCoreApplication.instance() or QCoreApplication([])

    class FakeListener:
        def __init__(self, **_kwargs):
            self.start_count = 0
            self.stop_count = 0
            self.wake_word_enabled = False

        def start(self):
            self.start_count += 1

        def stop(self):
            self.stop_count += 1

        def start_recording(self):
            return None

        def stop_recording(self):
            return b""

        def set_wake_word_enabled(self, enabled):
            self.wake_word_enabled = bool(enabled)

    original_listener = companion_manager.AmbientListener
    companion_manager.AmbientListener = FakeListener
    manager = None
    try:
        manager = companion_manager.CompanionManager()
        manager._submit = lambda coroutine: coroutine.close()
        manager.start()
        _require(not microphone_allowed(cfg), "microphone permission defaulted on")
        _require(manager._listener.start_count == 0, "microphone opened without consent")
        _require(
            isinstance(manager._get_tts(), DisabledTTSProvider),
            "cloud TTS provider loaded without consent",
        )
        _require(not cloud_tts_allowed(cfg), "cloud TTS permission defaulted on")
        _require(not screen_capture_allowed(cfg), "screen permission defaulted on")

        cfg.set_privacy_permissions(
            microphone=True,
            cloud_tts=False,
            screen_capture=False,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(manager._listener.start_count == 1, "microphone did not start after consent")

        cfg.set_privacy_permissions(
            microphone=False,
            cloud_tts=True,
            screen_capture=False,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(manager._listener.stop_count >= 1, "microphone did not stop after revocation")
        cloud_tts = manager._get_tts()
        _require(
            cloud_tts.__class__.__name__ == "EdgeTTSProvider",
            "selected cloud TTS provider did not load after consent",
        )

        cfg.set_privacy_permissions(
            microphone=False,
            cloud_tts=False,
            screen_capture=True,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(screen_capture_allowed(cfg), "screen permission did not persist")
        from screen.capture import capture_all_screens

        screenshots = capture_all_screens(max_width=320)
        _require(bool(screenshots), "sandbox screen capture returned no monitors")
        decoded = base64.b64decode(screenshots[0].base64_jpeg, validate=True)
        _require(decoded.startswith(b"\xff\xd8"), "screen capture was not a JPEG")
        dimensions = [
            {
                "index": shot.index,
                "width": shot.width,
                "height": shot.height,
            }
            for shot in screenshots
        ]
    finally:
        if manager is not None:
            manager.shutdown()
        companion_manager.AmbientListener = original_listener
        app.processEvents()

    return {
        "microphone_denied_before_consent": True,
        "microphone_started_after_consent": True,
        "microphone_stopped_after_revocation": True,
        "cloud_tts_denied_before_consent": True,
        "screen_denied_before_consent": True,
        "screen_capture_after_consent": dimensions,
    }


def _window_titles_for_process(process_id: int) -> list[str]:
    user32 = ctypes.windll.user32
    titles: list[str] = []
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def callback(window, _parameter):
        owner = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value != process_id or not user32.IsWindowVisible(window):
            return True
        length = user32.GetWindowTextLengthW(window)
        if length:
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(window, buffer, length + 1)
            if buffer.value:
                titles.append(buffer.value)
        return True

    callback_reference = callback_type(callback)
    user32.EnumWindows(callback_reference, 0)
    return sorted(set(titles))


def _remote_host(endpoint: str) -> str:
    if endpoint.startswith("[") and "]" in endpoint:
        return endpoint[1 : endpoint.index("]")]
    return endpoint.rsplit(":", 1)[0]


def _connections_for_process(process_id: int) -> set[tuple[str, str, str]]:
    result = subprocess.run(
        ["netstat.exe", "-ano", "-p", "tcp"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    connections: set[tuple[str, str, str]] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0].upper() != "TCP":
            continue
        if fields[-1] != str(process_id):
            continue
        local, remote, state, _pid = fields[1:]
        connections.add((local, remote, state.upper()))
    return connections


def _validate_unsigned_application(root: Path) -> dict[str, object]:
    executable = ROOT / "dist" / "Clicky" / "Clicky.exe"
    _require(executable.is_file(), "PyInstaller did not produce Clicky.exe")
    marker = executable.parent / "UNSIGNED-LOCAL-TEST-ONLY.txt"
    _require(marker.is_file(), "unsigned local-test marker is missing")
    _require(
        (executable.parent / "_internal" / "skills" / "manifest.json").is_file(),
        "bundled skill integrity manifest is missing from the application",
    )

    profile = root / "application-profile"
    environment = _child_environment(profile)
    process = subprocess.Popen(
        [str(executable)],
        cwd=executable.parent,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    connections: set[tuple[str, str, str]] = set()
    titles: set[str] = set()
    started = time.monotonic()
    try:
        deadline = started + 15
        while time.monotonic() < deadline:
            _require(process.poll() is None, "Clicky.exe exited during baseline startup")
            connections.update(_connections_for_process(process.pid))
            titles.update(_window_titles_for_process(process.pid))
            time.sleep(0.25)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)

    _require(
        any("privacy permissions" in title.lower() for title in titles),
        f"first-run privacy dialog was not observed: {sorted(titles)}",
    )
    unexpected: list[str] = []
    for _local, remote, state in connections:
        if state == "LISTENING":
            continue
        host = _remote_host(remote)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            unexpected.append(remote)
            continue
        if not (address.is_loopback or address.is_unspecified):
            unexpected.append(remote)
    _require(
        not unexpected,
        f"Clicky made external baseline connections before consent: {unexpected}",
    )
    return {
        "running_seconds": round(time.monotonic() - started, 2),
        "window_titles": sorted(titles),
        "tcp_connections": [
            {"local": local, "remote": remote, "state": state}
            for local, remote, state in sorted(connections)
        ],
        "external_destinations_before_consent": [],
        "sha256": _sha256(executable),
    }


def _defender_executable() -> Path:
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Windows Defender"
        / "MpCmdRun.exe"
    ]
    platform = Path(
        os.environ.get("ProgramData", r"C:\ProgramData")
    ) / "Microsoft" / "Windows Defender" / "Platform"
    if platform.is_dir():
        candidates.extend(
            sorted(platform.glob("*/MpCmdRun.exe"), reverse=True)
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise AssertionError("Microsoft Defender command-line scanner is unavailable")


def _validate_defender_scan() -> dict[str, object]:
    scanner = _defender_executable()
    target = ROOT / "dist" / "Clicky"
    scan = subprocess.run(
        [str(scanner), "-Scan", "-ScanType", "3", "-File", str(target)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15 * 60,
    )
    _require(
        scan.returncode == 0,
        "Microsoft Defender scan failed or detected a threat: "
        f"exit={scan.returncode}\n{scan.stdout}\n{scan.stderr}",
    )
    return {
        "scanner": str(scanner),
        "exit_code": scan.returncode,
        "stdout": scan.stdout.strip(),
        "stderr": scan.stderr.strip(),
    }


def run(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="clicky-runtime-validation-") as tmp:
        root = Path(tmp)
        report = {
            "python": sys.version,
            "executable": sys.executable,
            "audio_crash_cleanup": _validate_crash_cleanup(root),
            "privacy_controls": _validate_privacy_controls(root),
            "dpapi": _validate_dpapi(),
            "unsigned_application": _validate_unsigned_application(root),
            "defender": _validate_defender_scan(),
        }
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--crash-child", nargs=2, metavar=("DATA_DIR", "MARKER"))
    parser.add_argument("--cleanup-child", metavar="DATA_DIR")
    args = parser.parse_args()
    if args.crash_child:
        _run_crash_child(Path(args.crash_child[0]), Path(args.crash_child[1]))
        return 0
    if args.cleanup_child:
        _run_cleanup_child(Path(args.cleanup_child))
        return 0
    if args.output is None:
        parser.error("--output is required")
    run(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
