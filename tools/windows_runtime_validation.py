"""Windows-only dynamic security validation for a disposable boundary.

This script uses synthetic data and never requires real credentials, audio, or
screen content. Run it only inside the reviewed Windows Sandbox launcher or the
trusted GitHub-hosted workflow after the frozen environment and unsigned local-
test or Store-input build has been created.
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
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from functools import lru_cache
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from validation_boundary import require_disposable_windows_boundary
CRASH_EXIT_CODE = 73
_EDGE_TTS_HOST = "speech.platform.bing.com"
_VIRUSTOTAL_MAX_FILE_BYTES = 650_000_000
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_STORE_MARKER_TEMPLATE = (
    ROOT / "packaging" / "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
)


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


def _windows_powershell_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.casefold() == "psmodulepath":
            del environment[name]
    return environment


def _security_descriptor_sddl(path: Path) -> str:
    command = (
        "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; "
        f"(Get-Acl -LiteralPath {_powershell_literal(path)}).Sddl"
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
        env=_windows_powershell_environment(),
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
    import screen.capture_exclusion as capture_exclusion

    app = QApplication.instance() or QApplication([])
    capture_exclusion.install_qt_capture_exclusion(app)
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
            self.capture_id = None
            self.wake_word_enabled = False

        def start(self):
            self.start_count += 1
            self.running = True

        def stop(self):
            self.stop_count += 1
            self.running = False

        def start_recording(self, capture_id=None, on_frame=None):
            self.recording_start_count += 1
            self.mode = "recording"
            self.buffer = [b"synthetic speech"]
            self.capture_id = capture_id
            if on_frame is not None:
                on_frame(b"synthetic speech")
            return True

        def stop_recording(self, capture_id=None):
            if self.capture_id is None:
                return b"" if capture_id is None else None
            if capture_id is not None and capture_id != self.capture_id:
                return None
            self.mode = "standby"
            self.buffer = []
            self.capture_id = None
            return b""

        def cancel_recording(self, capture_id=None):
            if self.capture_id is None:
                return False
            if capture_id is not None and capture_id != self.capture_id:
                return False
            self.cancel_count += 1
            self.mode = "standby"
            self.buffer = []
            self.capture_id = None
            return True

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
    manager_errors: list[str] = []
    try:
        manager = companion_manager.CompanionManager()
        manager.sig_error.connect(manager_errors.append)
        manager._submit = lambda coroutine, _session=None: coroutine.close()
        manager._get_llm = lambda: FakeLLM()
        manager.start()
        _require(
            manager.set_model("sandbox-validation-model"),
            "could not select the synthetic local validation model",
        )
        _require(not microphone_allowed(cfg), "microphone permission defaulted on")
        _require(manager._listener.start_count == 0, "microphone opened without consent")
        manager.on_hotkey_press()
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
        quiz_session = manager._turns.start_processing()
        _require(quiz_session is not None, "could not open denied quiz turn")
        asyncio.run(manager._kickoff_quiz(quiz_session))
        _require(not captures, "manager captured the screen without consent")

        cfg.set_privacy_permissions(
            microphone=True,
            cloud_tts=False,
            screen_capture=False,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        _require(manager._listener.start_count == 1, "microphone did not start after consent")
        manager.on_hotkey_press()
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
        manager_errors.clear()
        _require(screen_capture_allowed(cfg), "screen permission did not persist")
        quiz_session = manager._turns.start_processing()
        _require(quiz_session is not None, "could not open consented quiz turn")
        asyncio.run(manager._kickoff_quiz(quiz_session))
        capture_error = (
            manager_errors[-1]
            if manager_errors
            else "the manager emitted no capture error"
        )
        _require(
            bool(captures),
            "manager screen path captured no monitors after consent: "
            f"{capture_error}",
        )
        _require(
            not any(
                _screenshot_contains_synthetic_window(shot.base64_jpeg)
                for shot in captures
            ),
            "screen capture leaked the known Clicky-owned synthetic window",
        )

        native_backend = capture_exclusion.Win32OwnedWindowBackend()

        class ForceFallbackBackend:
            def visible_owned_windows(self):
                return native_backend.visible_owned_windows()

            def snapshot(self, handle):
                return native_backend.snapshot(handle)

            def exclude_from_capture(self, _handle):
                return False

            def hide(self, handle):
                return native_backend.hide(handle)

            def is_visible(self, handle):
                return native_backend.is_visible(handle)

            def flush_compositor(self):
                return native_backend.flush_compositor()

            def restore(self, snapshot):
                return native_backend.restore(snapshot)

        def placement_tuple(snapshot):
            placement = snapshot.placement
            rectangle = placement.rcNormalPosition
            return (
                int(placement.showCmd),
                int(rectangle.left),
                int(rectangle.top),
                int(rectangle.right),
                int(rectangle.bottom),
                snapshot.was_foreground,
            )

        synthetic_handle = int(synthetic_window.winId())
        _require(
            bool(
                ctypes.windll.user32.SetWindowDisplayAffinity(
                    synthetic_handle, 0
                )
            ),
            "could not clear synthetic affinity before fallback validation",
        )
        cleared_affinity = ctypes.c_ulong()
        _require(
            bool(
                ctypes.windll.user32.GetWindowDisplayAffinity(
                    synthetic_handle,
                    ctypes.byref(cleared_affinity),
                )
            )
            and cleared_affinity.value == 0,
            "synthetic affinity did not clear before fallback validation",
        )
        before_fallback = native_backend.snapshot(synthetic_handle)
        previous_controller = capture_exclusion._DEFAULT_CONTROLLER
        capture_exclusion._DEFAULT_CONTROLLER = (
            capture_exclusion.WindowCaptureController(ForceFallbackBackend())
        )
        try:
            fallback_screens = original_capture()
            _require(
                not any(
                    _screenshot_contains_synthetic_window(shot.base64_jpeg)
                    for shot in fallback_screens
                ),
                "hide/capture/restore fallback leaked the Clicky-owned window",
            )
            try:
                capture_exclusion.capture_without_owned_windows(
                    lambda: (_ for _ in ()).throw(
                        RuntimeError("synthetic capture failure")
                    )
                )
            except RuntimeError as exc:
                _require(
                    str(exc) == "synthetic capture failure",
                    "capture fallback changed the synthetic failure",
                )
            else:
                raise AssertionError("synthetic capture failure did not propagate")
        finally:
            capture_exclusion._DEFAULT_CONTROLLER = previous_controller
        after_fallback = native_backend.snapshot(synthetic_handle)
        _require(
            native_backend.is_visible(synthetic_handle),
            "Clicky-owned window remained hidden after fallback",
        )
        _require(
            placement_tuple(after_fallback) == placement_tuple(before_fallback),
            "Clicky-owned window placement changed after fallback",
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
        "clicky_owned_window_excluded": True,
        "owned_window_fallback_restored": True,
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
        "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; "
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
        env=_windows_powershell_environment(),
    )
    _require(result.returncode == 0, f"Authenticode inspection failed: {result.stderr}")
    payload = json.loads(result.stdout)
    _require(payload.get("Status") == "NotSigned", f"unexpected pre-release signature: {payload}")
    return payload


def _validate_release_markers(
    distribution: Path,
    *,
    release_kind: str,
    source_commit: str | None,
) -> None:
    local_marker = distribution / "UNSIGNED-LOCAL-TEST-ONLY.txt"
    store_marker = distribution / "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
    commit_marker = distribution / "SOURCE-COMMIT.txt"
    if release_kind == "local":
        _require(source_commit is None, "local validation forbids a source commit")
        _require(local_marker.is_file(), "unsigned local-test marker is missing")
        _require(
            not store_marker.exists() and not commit_marker.exists(),
            "local artifact contains Store release markers",
        )
        return
    _require(release_kind == "store", "unsupported release kind")
    _require(
        source_commit is not None
        and _COMMIT_RE.fullmatch(source_commit) is not None,
        "Store validation requires the exact source commit",
    )
    _require(not local_marker.exists(), "Store input retains the local-test marker")
    _require(store_marker.is_file(), "unsigned Store-input marker is missing")
    _require(
        store_marker.read_bytes() == _STORE_MARKER_TEMPLATE.read_bytes(),
        "Store-input marker differs from the reviewed text",
    )
    _require(commit_marker.is_file(), "Store source-commit marker is missing")
    _require(
        commit_marker.read_text(encoding="ascii").strip() == source_commit,
        "Store source-commit marker differs from the requested commit",
    )


def _validate_unsigned_application(
    root: Path,
    *,
    release_kind: str,
    source_commit: str | None,
) -> dict[str, object]:
    executable = ROOT / "dist" / "Clicky" / "Clicky.exe"
    _require(executable.is_file(), "PyInstaller did not produce Clicky.exe")
    _validate_release_markers(
        executable.parent,
        release_kind=release_kind,
        source_commit=source_commit,
    )
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
        self_test_stdout, self_test_stderr = self_test.communicate(timeout=10)
        raise AssertionError(
            "packaged security self-test timed out\n"
            f"stdout tail:\n{self_test_stdout[-4096:]}\n"
            f"stderr tail:\n{self_test_stderr[-4096:]}"
        )
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
        f"distribution contains an alternate data stream: {path}",
    )


def _validate_distribution_entry(path: Path, *, directory: bool) -> os.stat_result:
    details = path.lstat()
    attributes = getattr(details, "st_file_attributes", 0)
    _require(
        not path.is_symlink() and not (attributes & 0x400),
        f"distribution contains a reparse point: {path}",
    )
    _require_no_alternate_streams(path)
    if directory:
        _require(
            stat.S_ISDIR(details.st_mode),
            f"distribution contains a non-directory entry: {path}",
        )
    else:
        _require(
            stat.S_ISREG(details.st_mode),
            f"distribution contains a non-regular entry: {path}",
        )
        _require(
            details.st_nlink == 1,
            f"distribution contains a hard-linked file: {path}",
        )
    return details


def _validated_distribution_files(directory: Path) -> tuple[Path, ...]:
    _validate_distribution_entry(directory, directory=True)
    files: list[Path] = []

    def raise_walk_error(error: OSError) -> None:
        raise AssertionError(f"distribution traversal failed: {error}") from error

    for current_name, directory_names, file_names in os.walk(
        directory,
        topdown=True,
        onerror=raise_walk_error,
        followlinks=False,
    ):
        current = Path(current_name)
        _validate_distribution_entry(current, directory=True)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            _validate_distribution_entry(current / name, directory=True)
        for name in file_names:
            path = current / name
            _validate_distribution_entry(path, directory=False)
            files.append(path)
    return tuple(
        sorted(files, key=lambda path: path.relative_to(directory).as_posix())
    )


def _tree_identity_from_files(
    directory: Path, candidates: tuple[Path, ...]
) -> dict[str, object]:
    digest = hashlib.sha256()
    digest.update(b"clicky-dist-tree-v1\0")
    total_bytes = 0
    for path in candidates:
        details = _validate_distribution_entry(path, directory=False)
        relative = path.relative_to(directory).as_posix().encode("utf-8")
        total_bytes += details.st_size
        digest.update(b"F")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(details.st_size.to_bytes(8, "big"))
        copied = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                copied += len(chunk)
                digest.update(chunk)
        _require(copied == details.st_size, f"distribution file changed while hashing: {path}")
    return {
        "scheme": "clicky-dist-tree-v1",
        "tree_sha256": digest.hexdigest(),
        "file_count": len(candidates),
        "total_bytes": total_bytes,
    }


def _distribution_snapshot(
    directory: Path,
) -> tuple[dict[str, object], tuple[Path, ...]]:
    candidates = _validated_distribution_files(directory)
    return _tree_identity_from_files(directory, candidates), candidates


def _tree_identity(directory: Path) -> dict[str, object]:
    """Hash the complete regular-file tree and reject hidden indirection."""
    return _distribution_snapshot(directory)[0]


def _tree_sha256(directory: Path) -> str:
    return str(_tree_identity(directory)["tree_sha256"])


def _export_distribution(
    directory: Path, archive_output: Path, executable_output: Path
) -> dict[str, object]:
    _require(not archive_output.exists(), "distribution archive output already exists")
    _require(not executable_output.exists(), "executable copy output already exists")
    _require(archive_output.parent.is_dir(), "distribution archive parent is missing")
    _require(executable_output.parent.is_dir(), "executable copy parent is missing")
    resolved_directory = directory.resolve()
    for output in (archive_output, executable_output):
        resolved_output = output.resolve()
        _require(
            resolved_directory != resolved_output
            and resolved_directory not in resolved_output.parents,
            "distribution export must be outside the distribution tree",
        )

    identity, candidates = _distribution_snapshot(directory)
    with zipfile.ZipFile(
        archive_output,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        allowZip64=True,
        strict_timestamps=True,
    ) as archive:
        for path in candidates:
            details = _validate_distribution_entry(path, directory=False)
            relative = path.relative_to(directory).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with path.open("rb") as source, archive.open(info, "w") as target:
                copied = 0
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    copied += len(chunk)
                    target.write(chunk)
            _require(
                copied == details.st_size,
                f"distribution file changed while exporting: {path}",
            )

    _require(
        archive_output.stat().st_size <= _VIRUSTOTAL_MAX_FILE_BYTES,
        "distribution archive exceeds VirusTotal exact-file upload limit",
    )

    executable = directory / "Clicky.exe"
    _require(executable in candidates, "Clicky.exe is missing from the distribution")
    executable_details = _validate_distribution_entry(executable, directory=False)
    with executable.open("rb") as source, executable_output.open("xb") as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)
    _require(
        executable_output.stat().st_size == executable_details.st_size
        and _sha256(executable_output) == _sha256(executable),
        "exported executable differs from the packaged executable",
    )
    return {
        **identity,
        "archive_sha256": _sha256(archive_output),
        "archive_bytes": archive_output.stat().st_size,
        "executable_sha256": _sha256(executable_output),
    }


def run(
    output: Path,
    archive_output: Path,
    executable_output: Path,
    *,
    release_kind: str = "local",
    source_commit: str | None = None,
) -> None:
    _require(os.name == "nt", "Windows runtime validation requires Windows")
    boundary = require_disposable_windows_boundary()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="clicky-runtime-validation-") as tmp:
        root = Path(tmp)
        distribution = ROOT / "dist" / "Clicky"
        pristine = _tree_identity(distribution)
        audio_crash_cleanup = _validate_crash_cleanup(root)
        privacy_controls = _validate_privacy_controls(root)
        dpapi = _validate_dpapi()
        unsigned_application = _validate_unsigned_application(
            root,
            release_kind=release_kind,
            source_commit=source_commit,
        )
        post_execution = _tree_identity(distribution)
        _require(
            post_execution == pristine,
            "packaged execution changed or deleted distribution content",
        )
        exported = _export_distribution(
            distribution, archive_output, executable_output
        )
        _require(
            exported["tree_sha256"] == pristine["tree_sha256"]
            and exported["file_count"] == pristine["file_count"]
            and exported["total_bytes"] == pristine["total_bytes"],
            "exported distribution identity differs from the validated tree",
        )
        _require(
            exported["executable_sha256"] == unsigned_application["sha256"],
            "exported executable identity differs from packaged execution",
        )
        report = {
            "python": sys.version,
            "executable": sys.executable,
            "release_kind": release_kind,
            "source_commit": source_commit,
            "runtime_boundary": boundary,
            "audio_crash_cleanup": audio_crash_cleanup,
            "privacy_controls": privacy_controls,
            "dpapi": dpapi,
            "unsigned_application": unsigned_application,
            "distribution_integrity": {
                "scheme": pristine["scheme"],
                "pristine_tree_sha256": pristine["tree_sha256"],
                "post_execution_tree_sha256": post_execution["tree_sha256"],
                "unchanged": True,
                "file_count": pristine["file_count"],
                "total_bytes": pristine["total_bytes"],
                "archive_sha256": exported["archive_sha256"],
                "archive_bytes": exported["archive_bytes"],
                "clicky_exe_sha256": exported["executable_sha256"],
            },
        }
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--distribution-archive", type=Path)
    parser.add_argument("--executable-copy", type=Path)
    parser.add_argument("--release-kind", choices=("local", "store"), default="local")
    parser.add_argument("--source-commit")
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
    if args.distribution_archive is None:
        parser.error("--distribution-archive is required")
    if args.executable_copy is None:
        parser.error("--executable-copy is required")
    run(
        args.output,
        args.distribution_archive,
        args.executable_copy,
        release_kind=args.release_kind,
        source_commit=args.source_commit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
