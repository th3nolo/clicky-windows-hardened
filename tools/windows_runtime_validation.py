"""Windows-only dynamic security validation for a disposable sandbox.

This script uses synthetic data and never requires real credentials, audio, or
screen content. Run it only inside Windows Sandbox after the frozen environment
and unsigned local-test build have been created.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import ctypes
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CRASH_EXIT_CODE = 73
_EDGE_TTS_HOST = "speech.platform.bing.com"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _child_environment(
    data_dir: Path, *, offscreen: bool = True
) -> dict[str, str]:
    environment = dict(os.environ)
    environment["LOCALAPPDATA"] = str(data_dir)
    environment["APPDATA"] = str(data_dir / "Roaming")
    environment["TEMP"] = str(data_dir / "Temp")
    environment["TMP"] = str(data_dir / "Temp")
    if offscreen:
        environment["QT_QPA_PLATFORM"] = "offscreen"
    else:
        environment.pop("QT_QPA_PLATFORM", None)
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
        "CLICKY_SECURITY_SELF_TEST",
        "CLICKY_SELF_TEST_TOKEN_SHA256",
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


def _powershell_executable() -> Path:
    return (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )


def _powershell_literal(value: Path | str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _security_descriptor_sddl(path: Path) -> str:
    command = f"(Get-Acl -LiteralPath {_powershell_literal(path)}).Sddl"
    result = subprocess.run(
        [
            str(_powershell_executable()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    _require(result.returncode == 0, f"could not inspect ACL for {path}: {result.stderr}")
    sddl = result.stdout.strip().upper()
    _require(bool(sddl), f"empty security descriptor for {path}")
    return sddl


def _require_private_sddl(path: Path, *, protected: bool) -> str:
    sddl = _security_descriptor_sddl(path)
    broad_trustees = (";;;WD)", ";;;BU)", ";;;AU)", ";;;S-1-1-0)", ";;;S-1-5-11)", ";;;S-1-5-32-545)")
    _require(
        not any(trustee in sddl for trustee in broad_trustees),
        f"private audio path contains a broad ACL: {path}: {sddl}",
    )
    if protected:
        _require("D:P" in sddl, f"audio directory DACL is not protected: {sddl}")
    return sddl


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

    directory_sddl = _require_private_sddl(abandoned.parent, protected=True)
    file_sddl = _require_private_sddl(abandoned, protected=False)

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
        "audio_directory_sddl": directory_sddl,
        "audio_file_sddl": file_sddl,
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


def _observe_cloud_tts_network(cloud_tts) -> dict[str, object]:
    """Send fixed synthetic text and bind the observed peer to Edge TTS DNS."""
    import audio.tts.edge_tts_provider as edge_provider

    resolved_hosts: set[str] = set()
    resolved_addresses: set[str] = set()
    observed_connections: set[tuple[str, str, str]] = set()
    observation_errors: list[str] = []
    audio_sizes: list[int] = []
    original_getaddrinfo = socket.getaddrinfo
    stop = threading.Event()

    def recording_getaddrinfo(host, port, *args, **kwargs):
        normalized = str(host).rstrip(".").encode("idna").decode("ascii").lower()
        _require(normalized == _EDGE_TTS_HOST, f"unexpected Edge TTS host: {normalized}")
        results = original_getaddrinfo(host, port, *args, **kwargs)
        resolved_hosts.add(normalized)
        for result in results:
            resolved_addresses.add(str(result[4][0]).split("%", 1)[0])
        return results

    def sample_connections() -> None:
        while not stop.is_set():
            try:
                observed_connections.update(_connections_for_process(os.getpid()))
            except Exception as exc:
                observation_errors.append(str(exc))
                return
            stop.wait(0.02)

    async def capture_audio(data: bytes) -> None:
        audio_sizes.append(len(data))

    sampler = threading.Thread(target=sample_connections, daemon=True)
    sampler.start()
    try:
        with mock.patch.object(socket, "getaddrinfo", side_effect=recording_getaddrinfo), mock.patch.object(
            edge_provider, "play_mp3_async", new=capture_audio
        ):
            asyncio.run(cloud_tts.speak("Clicky synthetic privacy validation."))
    finally:
        stop.set()
        sampler.join(timeout=5)

    _require(not sampler.is_alive(), "network observation thread did not stop")
    _require(not observation_errors, f"network observation failed: {observation_errors}")
    _require(audio_sizes and max(audio_sizes) > 0, "cloud TTS returned no audio")
    public_addresses = {
        value
        for value in resolved_addresses
        if ipaddress.ip_address(value).is_global
    }
    _require(resolved_hosts == {_EDGE_TTS_HOST}, "Edge TTS resolved an unexpected host")
    _require(public_addresses, "cloud TTS resolved no public destination addresses")
    correlated: set[str] = set()
    for _local, remote, state in observed_connections:
        if state == "LISTENING":
            continue
        host = _remote_host(remote).split("%", 1)[0]
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            continue
        if address in public_addresses:
            correlated.add(address)
    _require(correlated, "cloud TTS captured no TCP peer matching its DNS answers")
    return {
        "synthetic_text_only": True,
        "resolved_hosts": sorted(resolved_hosts),
        "resolved_public_addresses": sorted(public_addresses),
        "correlated_tcp_addresses": sorted(correlated),
        "tcp_connections": [
            {"local": local, "remote": remote, "state": state}
            for local, remote, state in sorted(observed_connections)
        ],
        "audio_bytes": max(audio_sizes),
    }
def _screenshot_contains_synthetic_window(base64_jpeg: str) -> bool:
    from PIL import Image

    image = Image.open(io.BytesIO(base64.b64decode(base64_jpeg, validate=True))).convert(
        "RGB"
    )
    matches = 0
    for red, green, blue in image.getdata():
        if red >= 180 and green <= 100 and blue >= 180:
            matches += 1
            if matches >= 100:
                return True
    return False


def _validate_privacy_controls(root: Path) -> dict[str, object]:
    environment = _child_environment(root / "privacy-profile", offscreen=False)
    os.environ.clear()
    os.environ.update(environment)

    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication, QWidget

    import companion_manager
    from audio.tts.base_tts import DisabledTTSProvider
    from config import cfg
    from privacy_controls import (
        PRIVACY_NOTICE_VERSION,
        cloud_tts_allowed,
        microphone_allowed,
        screen_capture_allowed,
    )

    app = QApplication.instance() or QApplication([])
    synthetic_window = QWidget()
    synthetic_window.setWindowTitle("Clicky Sandbox Synthetic Screen")
    synthetic_window.setStyleSheet("background-color: #ff00ff;")
    synthetic_window.resize(420, 260)
    synthetic_window.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    synthetic_window.show()
    synthetic_window.raise_()
    synthetic_window.activateWindow()
    app.processEvents()
    time.sleep(0.5)
    app.processEvents()

    class FakeListener:
        def __init__(self, **_kwargs):
            self.start_count = 0
            self.stop_count = 0
            self.recording_start_count = 0
            self.cancel_count = 0
            self.running = False
            self.mode = "standby"
            self.buffer = []
            self.wake_word_enabled = False

        def start(self):
            self.start_count += 1
            self.running = True

        def stop(self):
            self.stop_count += 1
            self.running = False

        def start_recording(self):
            self.recording_start_count += 1
            self.mode = "recording"
            self.buffer = [b"synthetic speech"]

        def stop_recording(self):
            self.mode = "standby"
            self.buffer = []
            return b""

        def cancel_recording(self):
            self.cancel_count += 1
            self.mode = "standby"
            self.buffer = []

        def set_wake_word_enabled(self, enabled):
            self.wake_word_enabled = bool(enabled)

    class FakeLLM:
        async def stream_response(self, **_kwargs):
            yield "synthetic sandbox quiz"

    original_listener = companion_manager.AmbientListener
    original_capture = companion_manager.capture_all_screens
    companion_manager.AmbientListener = FakeListener
    captures = []

    def tracked_capture(*args, **kwargs):
        screenshots = original_capture(*args, **kwargs)
        captures.extend(screenshots)
        return screenshots

    companion_manager.capture_all_screens = tracked_capture
    manager = None
    try:
        manager = companion_manager.CompanionManager()
        manager._submit = lambda coroutine: coroutine.close()
        manager._get_llm = lambda: FakeLLM()
        manager.start()
        _require(not microphone_allowed(cfg), "microphone permission defaulted on")
        _require(manager._listener.start_count == 0, "microphone opened without consent")
        manager._begin_capture()
        _require(
            manager._listener.recording_start_count == 0,
            "recording path opened without microphone consent",
        )
        _require(
            isinstance(manager._get_tts(), DisabledTTSProvider),
            "cloud TTS provider loaded without consent",
        )
        _require(not cloud_tts_allowed(cfg), "cloud TTS permission defaulted on")
        _require(not screen_capture_allowed(cfg), "screen permission defaulted on")
        asyncio.run(manager._kickoff_quiz())
        _require(not captures, "manager captured the screen without consent")

        cfg.set_privacy_permissions(
            microphone=True,
            cloud_tts=False,
            screen_capture=False,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(manager._listener.start_count == 1, "microphone did not start after consent")
        manager._begin_capture()
        _require(
            manager._listener.recording_start_count == 1
            and manager._listener.mode == "recording",
            "recording path did not open after microphone consent",
        )

        # Revoke while actively recording. Buffered speech must be discarded
        # before a future permission grant can restart standby listening.
        cfg.set_privacy_permissions(
            microphone=False,
            cloud_tts=True,
            screen_capture=False,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(manager._listener.stop_count >= 1, "microphone did not stop after revocation")
        _require(
            manager._listener.cancel_count == 1
            and manager._listener.mode == "standby"
            and manager._listener.buffer == []
            and manager._state == companion_manager.AppState.IDLE,
            "microphone revocation retained an active recording",
        )
        cfg.set_privacy_permissions(
            microphone=True,
            cloud_tts=True,
            screen_capture=False,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(
            manager._listener.running and manager._listener.mode == "standby",
            "microphone restarted in recording mode after permission regrant",
        )
        cfg.set_privacy_permissions(
            microphone=False,
            cloud_tts=True,
            screen_capture=False,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        cloud_tts = manager._get_tts()
        _require(
            cloud_tts.__class__.__name__ == "EdgeTTSProvider",
            "selected cloud TTS provider did not load after consent",
        )
        cloud_tts_network = _observe_cloud_tts_network(cloud_tts)

        cfg.set_privacy_permissions(
            microphone=False,
            cloud_tts=False,
            screen_capture=True,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(screen_capture_allowed(cfg), "screen permission did not persist")
        asyncio.run(manager._kickoff_quiz())
        _require(bool(captures), "manager screen path captured no monitors after consent")
        _require(
            any(_screenshot_contains_synthetic_window(shot.base64_jpeg) for shot in captures),
            "screen capture did not contain the known synthetic sandbox window",
        )
        dimensions = [
            {"index": shot.index, "width": shot.width, "height": shot.height}
            for shot in captures
        ]
    finally:
        if manager is not None:
            manager.shutdown()
        companion_manager.AmbientListener = original_listener
        companion_manager.capture_all_screens = original_capture
        synthetic_window.close()
        app.processEvents()

    return {
        "microphone_device": "synthetic listener; host audio input disabled",
        "microphone_denied_before_consent": True,
        "recording_denied_before_consent": True,
        "microphone_started_after_consent": True,
        "recording_started_after_consent": True,
        "microphone_stopped_after_revocation": True,
        "microphone_recording_cancelled_after_revocation": True,
        "microphone_standby_after_regrant": True,
        "cloud_tts_denied_before_consent": True,
        "cloud_tts_after_consent": cloud_tts_network,
        "screen_denied_before_consent": True,
        "screen_capture_after_consent": dimensions,
        "synthetic_screen_content_observed": True,
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
    _require(
        result.returncode == 0,
        f"netstat TCP observation failed: {result.stderr}",
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


def _authenticode_status(executable: Path) -> dict[str, object]:
    executable_literal = _powershell_literal(executable)
    command = (
        f"$signature = Get-AuthenticodeSignature -LiteralPath {executable_literal}; "
        "[pscustomobject]@{Status=$signature.Status.ToString(); "
        "StatusMessage=$signature.StatusMessage; "
        "SignerSubject=$signature.SignerCertificate.Subject} | "
        "ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [
            str(_powershell_executable()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    _require(result.returncode == 0, f"Authenticode inspection failed: {result.stderr}")
    payload = json.loads(result.stdout)
    _require(payload.get("Status") == "NotSigned", f"unexpected pre-release signature: {payload}")
    return payload


def _validate_unsigned_application(root: Path) -> dict[str, object]:
    executable = ROOT / "dist" / "Clicky" / "Clicky.exe"
    _require(executable.is_file(), "PyInstaller did not produce Clicky.exe")
    marker = executable.parent / "UNSIGNED-LOCAL-TEST-ONLY.txt"
    _require(marker.is_file(), "unsigned local-test marker is missing")
    _require(
        (executable.parent / "_internal" / "skills" / "manifest.json").is_file(),
        "bundled skill integrity manifest is missing from the application",
    )
    signature = _authenticode_status(executable)

    self_test_profile = root / "packaged-self-test-profile"
    self_test_environment = _child_environment(self_test_profile, offscreen=False)
    self_test_environment["CLICKY_SECURITY_SELF_TEST"] = "1"
    self_test_output = root / "packaged-self-test.json"
    self_test = subprocess.Popen(
        [str(executable), "--security-self-test", str(self_test_output)],
        cwd=executable.parent,
        env=self_test_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    self_test_connections: set[tuple[str, str, str]] = set()
    deadline = time.monotonic() + 180
    while self_test.poll() is None and time.monotonic() < deadline:
        self_test_connections.update(_connections_for_process(self_test.pid))
        time.sleep(0.02)
    if self_test.poll() is None:
        self_test.kill()
        self_test.wait(timeout=10)
        raise AssertionError("packaged security self-test timed out")
    self_test_stdout, self_test_stderr = self_test.communicate(timeout=10)
    _require(
        self_test.returncode == 0,
        "packaged security self-test failed: "
        f"exit={self_test.returncode}\n{self_test_stdout}\n{self_test_stderr}",
    )
    _require(self_test_output.is_file(), "packaged self-test wrote no evidence")
    packaged_self_test = json.loads(self_test_output.read_text(encoding="utf-8"))
    packaged_cloud = packaged_self_test["cloud_tts"]
    resolved = {
        str(value).split("%", 1)[0]
        for value in packaged_cloud["resolved_public_addresses"]
    }
    correlated: set[str] = set()
    unexpected_self_test: list[str] = []
    for _local, remote, state in self_test_connections:
        if state == "LISTENING":
            continue
        host = _remote_host(remote).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            unexpected_self_test.append(remote)
            continue
        if address.is_loopback or address.is_unspecified:
            continue
        if str(address) in resolved:
            correlated.add(str(address))
        else:
            unexpected_self_test.append(remote)
    _require(not unexpected_self_test, f"packaged self-test used unexpected peers: {unexpected_self_test}")
    _require(correlated, "packaged TTS captured no TCP peer matching its DNS answers")
    packaged_cloud["correlated_tcp_addresses"] = sorted(correlated)
    packaged_cloud["tcp_connections"] = [
        {"local": local, "remote": remote, "state": state}
        for local, remote, state in sorted(self_test_connections)
    ]

    profile = root / "application-profile"
    environment = _child_environment(profile, offscreen=False)
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
            address = ipaddress.ip_address(host.split("%", 1)[0])
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
        "authenticode": signature,
        "packaged_security_self_test": packaged_self_test,
    }


def _defender_executable() -> Path:
    platform = Path(
        os.environ.get("ProgramData", r"C:\ProgramData")
    ) / "Microsoft" / "Windows Defender" / "Platform"
    candidates = (
        sorted(platform.glob("*/MpCmdRun.exe"), reverse=True)
        if platform.is_dir()
        else []
    )
    candidates.append(
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Windows Defender"
        / "MpCmdRun.exe"
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise AssertionError("Microsoft Defender command-line scanner is unavailable")


def _tree_sha256(directory: Path) -> str:
    """Hash the complete regular-file tree and reject reparse indirection."""
    digest = hashlib.sha256()
    candidates = sorted(
        directory.rglob("*"),
        key=lambda candidate: candidate.relative_to(directory).as_posix(),
    )
    for path in candidates:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        _require(
            not path.is_symlink() and not (attributes & 0x400),
            f"distribution contains a reparse point: {path}",
        )
        if path.is_dir():
            continue
        _require(path.is_file(), f"distribution contains a non-regular entry: {path}")
        relative = path.relative_to(directory).as_posix().encode("utf-8")
        digest.update(b"F")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(path.stat().st_size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()
def _defender_status() -> dict[str, object]:
    command = (
        "Get-MpComputerStatus | Select-Object AntivirusEnabled, "
        "RealTimeProtectionEnabled, AMProductVersion, AntivirusSignatureVersion, "
        "AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [
            str(_powershell_executable()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    _require(result.returncode == 0, f"Defender status failed: {result.stderr}")
    status = json.loads(result.stdout)
    _require(status.get("AntivirusEnabled") is True, f"Defender is disabled: {status}")
    _require(status.get("AntivirusSignatureVersion"), f"Defender signatures unavailable: {status}")
    return status


def _validate_defender_scan(
    *,
    expected_distribution_sha256: str | None = None,
    update_signatures: bool,
) -> dict[str, object]:
    scanner = _defender_executable()
    signature_update = None
    if update_signatures:
        signature_update = subprocess.run(
            [str(scanner), "-SignatureUpdate"],
            check=False, capture_output=True, text=True, timeout=15 * 60,
        )
        _require(
            signature_update.returncode == 0,
            "Microsoft Defender signature update failed: "
            f"exit={signature_update.returncode}\n"
            f"{signature_update.stdout}\n{signature_update.stderr}",
        )
    status = _defender_status()
    target = ROOT / "dist" / "Clicky"
    before = _tree_sha256(target)
    if expected_distribution_sha256 is not None:
        _require(
            before == expected_distribution_sha256,
            "distribution changed before a Defender scan",
        )
    scan = subprocess.run(
        [
            str(scanner), "-Scan", "-ScanType", "3", "-File", str(target),
            "-DisableRemediation",
        ],
        check=False, capture_output=True, text=True, timeout=15 * 60,
    )
    after = _tree_sha256(target)
    _require(before == after, "Defender changed the no-remediation scan target")
    _require(
        scan.returncode == 0,
        "Microsoft Defender found a threat or the scan failed: "
        f"exit={scan.returncode}\n{scan.stdout}\n{scan.stderr}",
    )
    return {
        "scanner": str(scanner),
        "signature_update_requested": update_signatures,
        "signature_update_exit_code": (
            signature_update.returncode if signature_update is not None else None
        ),
        "signature_update_stdout": (
            signature_update.stdout.strip()[-16000:] if signature_update is not None else ""
        ),
        "signature_update_stderr": (
            signature_update.stderr.strip()[-16000:] if signature_update is not None else ""
        ),
        "status": status,
        "scan_exit_code": scan.returncode,
        "disable_remediation": True,
        "distribution_sha256_before": before,
        "distribution_sha256_after": after,
        "stdout": scan.stdout.strip()[-16000:],
        "stderr": scan.stderr.strip()[-16000:],
    }


def run(output: Path) -> None:
    _require(os.name == "nt", "Windows runtime validation requires Windows")
    _require(
        os.environ.get("CLICKY_WINDOWS_SANDBOX") == "1",
        "runtime validation requires the disposable Windows Sandbox launcher",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="clicky-runtime-validation-") as tmp:
        root = Path(tmp)
        pre_execution_scan = _validate_defender_scan(update_signatures=True)
        pristine = pre_execution_scan["distribution_sha256_before"]
        audio_crash_cleanup = _validate_crash_cleanup(root)
        privacy_controls = _validate_privacy_controls(root)
        dpapi = _validate_dpapi()
        unsigned_application = _validate_unsigned_application(root)
        post_execution_tree = _tree_sha256(ROOT / "dist" / "Clicky")
        _require(
            post_execution_tree == pristine,
            "packaged execution changed or deleted distribution content",
        )
        post_execution_scan = _validate_defender_scan(
            expected_distribution_sha256=pristine,
            update_signatures=False,
        )
        report = {
            "python": sys.version,
            "executable": sys.executable,
            "audio_crash_cleanup": audio_crash_cleanup,
            "privacy_controls": privacy_controls,
            "dpapi": dpapi,
            "unsigned_application": unsigned_application,
            "defender": {
                "pristine_distribution_sha256": pristine,
                "pre_execution": pre_execution_scan,
                "post_execution_tree_sha256": post_execution_tree,
                "post_execution": post_execution_scan,
            },
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
