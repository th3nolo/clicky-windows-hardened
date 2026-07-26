"""Security self-test executed only by the disposable Windows Sandbox harness."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from unittest import mock

from validation_boundary import require_disposable_windows_boundary


_SELF_TEST_SENTINEL = "CLICKY_SECURITY_SELF_TEST"
_EXPECTED_TOKEN_DIGEST = "CLICKY_SELF_TEST_TOKEN_SHA256"
_EDGE_TTS_HOST = "speech.platform.bing.com"
_SYNTHETIC_TTS_TEXT = "Clicky synthetic privacy validation."


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _require_isolated_packaged_runtime() -> None:
    _require(bool(getattr(sys, "frozen", False)), "self-test requires the packaged executable")
    require_disposable_windows_boundary()
    _require(os.environ.get(_SELF_TEST_SENTINEL) == "1", "self-test sentinel is missing")


def read_dpapi_child() -> int:
    """Verify a parent-created DPAPI token from a second packaged process."""
    _require_isolated_packaged_runtime()
    from ai import github_copilot_provider as github

    expected = os.environ.get(_EXPECTED_TOKEN_DIGEST, "")
    token = github._read_encrypted_token()
    if token is None:
        return 2
    actual = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return 0 if expected and actual == expected else 3


def _validate_dpapi_persistence() -> dict[str, object]:
    from ai import github_copilot_provider as github

    token = "clicky-packaged-dpapi-self-test-not-a-secret"
    token_path = github._token_path()
    _require(not token_path.exists(), "refusing to overwrite an existing GitHub token")
    try:
        github._store_github_token(token)
        blob = token_path.read_bytes()
        _require(blob.startswith(github._TOKEN_FILE_MAGIC), "DPAPI token magic is missing")
        _require(token.encode("utf-8") not in blob, "plaintext token is present on disk")
        _require(github._read_encrypted_token() == token, "same-process DPAPI read failed")
        environment = dict(os.environ)
        environment[_EXPECTED_TOKEN_DIGEST] = hashlib.sha256(token.encode()).hexdigest()
        child = subprocess.run(
            [sys.executable, "--security-self-test-read-dpapi"],
            check=False, capture_output=True, env=environment, timeout=30,
        )
        _require(child.returncode == 0, f"second-process DPAPI read failed: {child.returncode}")
        return {
            "magic_present": True,
            "plaintext_absent": True,
            "same_process_read": True,
            "second_process_read": True,
            "encrypted_bytes": len(blob),
        }
    finally:
        token_path.unlink(missing_ok=True)


def _validate_secure_audio() -> dict[str, object]:
    from audio.secure_temp import secure_wav_file

    payload = b"RIFF packaged synthetic audio"
    with secure_wav_file(payload) as path:
        _require(path.read_bytes() == payload, "packaged secure audio write failed")
        recorded_path = path
    _require(not recorded_path.exists(), "packaged secure audio cleanup failed")
    return {"private_write": True, "normal_cleanup": True}


def _validate_bundled_skills() -> dict[str, object]:
    from skills import _verified_bundled_skill_sources, load_all

    verified = _verified_bundled_skill_sources()
    _require(bool(verified), "packaged bundled-skill verification returned no sources")
    loaded = load_all()
    _require(bool(loaded), "packaged bundled skills did not load")
    return {
        "verified_files": sorted(path.name for path, _source, _digest in verified),
        "loaded_names": sorted(str(skill["name"]) for skill in loaded),
    }


def _validate_privacy_defaults() -> dict[str, object]:
    from config import cfg
    from privacy_controls import cloud_tts_allowed, microphone_allowed, notice_accepted, screen_capture_allowed

    _require(not notice_accepted(cfg), "packaged privacy notice defaulted to accepted")
    _require(not microphone_allowed(cfg), "packaged microphone permission defaulted on")
    _require(not cloud_tts_allowed(cfg), "packaged cloud TTS permission defaulted on")
    _require(not screen_capture_allowed(cfg), "packaged screen permission defaulted on")
    return {
        "notice_accepted": False,
        "microphone_allowed": False,
        "cloud_tts_allowed": False,
        "screen_capture_allowed": False,
    }


def _validate_microphone_revocation() -> dict[str, object]:
    import companion_manager
    from config import cfg
    from privacy_controls import PRIVACY_NOTICE_VERSION

    class StatefulListener:
        def __init__(self, **_kwargs):
            self.running = False
            self.mode = "standby"
            self.buffer = []
            self.cancel_count = 0

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

        def start_recording(self):
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

        def set_wake_word_enabled(self, _enabled):
            return None

    cfg.set_privacy_permissions(
        microphone=True, cloud_tts=True, screen_capture=True,
        notice_version=PRIVACY_NOTICE_VERSION,
    )
    original = companion_manager.AmbientListener
    companion_manager.AmbientListener = StatefulListener
    manager = None
    try:
        manager = companion_manager.CompanionManager()
        manager.refresh_privacy_permissions()
        manager._begin_capture()
        _require(manager._listener.mode == "recording", "packaged manager did not record")
        cfg.set_privacy_permissions(
            microphone=False, cloud_tts=True, screen_capture=True,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        cancelled = (
            manager._listener.cancel_count == 1
            and manager._listener.mode == "standby"
            and manager._listener.buffer == []
            and manager._state == companion_manager.AppState.IDLE
        )
        _require(cancelled, "packaged manager retained speech after mic revocation")
        cfg.set_privacy_permissions(
            microphone=True, cloud_tts=True, screen_capture=True,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        manager.refresh_privacy_permissions()
        standby = manager._listener.running and manager._listener.mode == "standby"
        _require(standby, "packaged manager restarted in recording mode")
        return {
            "cancelled_after_revocation": True,
            "standby_after_regrant": True,
        }
    finally:
        if manager is not None:
            manager.shutdown()
        companion_manager.AmbientListener = original


def _contains_magenta(base64_jpeg: str) -> bool:
    from PIL import Image

    image = Image.open(io.BytesIO(base64.b64decode(base64_jpeg, validate=True))).convert("RGB")
    matches = 0
    for red, green, blue in image.getdata():
        if red >= 180 and green <= 100 and blue >= 180:
            matches += 1
            if matches >= 100:
                return True
    return False


def _validate_screen_capture() -> dict[str, object]:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication, QWidget
    from screen.capture import capture_all_screens

    app = QApplication.instance() or QApplication([])
    window = QWidget()
    window.setWindowTitle("Clicky Packaged Synthetic Screen")
    window.setStyleSheet("background-color: #ff00ff;")
    window.resize(420, 260)
    window.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    window.show()
    window.raise_()
    window.activateWindow()
    app.processEvents()
    time.sleep(0.5)
    app.processEvents()
    try:
        screenshots = capture_all_screens()
        observed = any(_contains_magenta(item.base64_jpeg) for item in screenshots)
        _require(observed, "packaged capture missed the synthetic screen")
        return {
            "synthetic_content_observed": True,
            "screens": [
                {"index": item.index, "width": item.width, "height": item.height}
                for item in screenshots
            ],
        }
    finally:
        window.close()
        app.processEvents()


def _validate_cloud_tts() -> dict[str, object]:
    import audio.tts.edge_tts_provider as edge_provider

    resolved_hosts: set[str] = set()
    resolved_addresses: set[str] = set()
    audio_sizes: list[int] = []
    original_getaddrinfo = socket.getaddrinfo

    def recording_getaddrinfo(host, port, *args, **kwargs):
        normalized = str(host).rstrip(".").encode("idna").decode("ascii").lower()
        _require(normalized == _EDGE_TTS_HOST, f"unexpected packaged TTS host: {normalized}")
        results = original_getaddrinfo(host, port, *args, **kwargs)
        resolved_hosts.add(normalized)
        for result in results:
            resolved_addresses.add(str(result[4][0]).split("%", 1)[0])
        return results

    async def capture_audio(data: bytes) -> None:
        audio_sizes.append(len(data))

    with mock.patch.object(socket, "getaddrinfo", side_effect=recording_getaddrinfo), mock.patch.object(
        edge_provider, "play_mp3_async", new=capture_audio
    ):
        asyncio.run(edge_provider.EdgeTTSProvider().speak(_SYNTHETIC_TTS_TEXT))
    public = sorted(
        value for value in resolved_addresses if ipaddress.ip_address(value).is_global
    )
    _require(resolved_hosts == {_EDGE_TTS_HOST}, "packaged TTS host evidence differs")
    _require(public, "packaged TTS resolved no public addresses")
    _require(audio_sizes and max(audio_sizes) > 0, "packaged TTS returned no audio")
    return {
        "synthetic_text_only": True,
        "resolved_hosts": sorted(resolved_hosts),
        "resolved_public_addresses": public,
        "correlated_tcp_addresses": [],
        "audio_bytes": max(audio_sizes),
    }


def run(output: Path) -> int:
    """Run packaged primitives and emit bounded, non-secret JSON evidence."""
    _require_isolated_packaged_runtime()
    output.parent.mkdir(parents=True, exist_ok=True)
    privacy_defaults = _validate_privacy_defaults()
    report = {
        "runtime_boundary": {
            "frozen": bool(getattr(sys, "frozen", False)),
            "executable": sys.executable,
            **require_disposable_windows_boundary(),
        },
        "dpapi_token_persistence": _validate_dpapi_persistence(),
        "secure_audio": _validate_secure_audio(),
        "bundled_skills": _validate_bundled_skills(),
        "privacy_defaults": privacy_defaults,
        "microphone_state": _validate_microphone_revocation(),
        "screen_capture": _validate_screen_capture(),
        "cloud_tts": _validate_cloud_tts(),
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
