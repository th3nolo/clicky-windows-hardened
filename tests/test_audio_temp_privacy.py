"""Standard-library tests for private, crash-cleaned temporary audio."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "clicky_secure_audio_temp_test", ROOT / "audio" / "secure_temp.py"
)
assert SPEC is not None and SPEC.loader is not None
secure_temp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secure_temp)


class SecureAudioTempTests(unittest.TestCase):
    def setUp(self) -> None:
        secure_temp._INITIALIZED = False
        secure_temp._CURRENT_FILES.clear()

    def test_audio_file_is_private_and_removed_after_use(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=False
        ):
            with secure_temp.secure_wav_file(b"RIFF-private-audio") as path:
                self.assertEqual(path.read_bytes(), b"RIFF-private-audio")
                self.assertEqual(path.parent, Path(tmp) / "Clicky" / "audio-temp")
                if os.name != "nt":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse(path.exists())

    def test_audio_file_is_removed_when_transcription_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=False
        ):
            path = None
            with self.assertRaisesRegex(RuntimeError, "transcription failed"):
                with secure_temp.secure_wav_file(b"RIFF-private-audio") as current:
                    path = current
                    raise RuntimeError("transcription failed")
            self.assertIsNotNone(path)
            self.assertFalse(path.exists())

    def test_transcription_oserror_is_not_misreported_as_storage_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=False
        ):
            with self.assertRaisesRegex(OSError, "model failed"):
                with secure_temp.secure_wav_file(b"RIFF-private-audio"):
                    raise OSError("model failed")

    def test_crash_leftover_from_terminated_process_is_swept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            crashed = (
                directory
                / "clicky-audio-99999999-0000000000000000-"
                "00000000000000000000000000000000.wav"
            )
            crashed.write_bytes(b"private speech")
            with mock.patch.object(
                secure_temp, "_pid_is_running", return_value=False
            ):
                self.assertEqual(secure_temp.cleanup_stale_audio(directory), 1)
            self.assertFalse(crashed.exists())

    def test_live_process_audio_is_not_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            active = (
                directory
                / f"clicky-audio-{os.getpid()}-0000000000000000-"
                "00000000000000000000000000000000.wav"
            )
            active.write_bytes(b"active speech")
            self.assertEqual(secure_temp.cleanup_stale_audio(directory), 0)
            self.assertTrue(active.exists())

    def test_old_unrecognized_clicky_audio_file_is_swept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            stale = directory / "clicky-audio-legacy.wav"
            stale.write_bytes(b"legacy speech")
            old = time.time() - secure_temp._STALE_AFTER_SECONDS - 1
            os.utime(stale, (old, old))
            self.assertEqual(secure_temp.cleanup_stale_audio(directory), 1)
            self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
