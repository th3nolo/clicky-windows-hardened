"""Explicit STT readiness and local-only fallback policy."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from audio.stt import readiness
import companion_manager as manager_module
from companion_manager import CompanionManager
from privacy_controls import PRIVACY_NOTICE_VERSION


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ready_config(**updates):
    values = {
        "deepgram_api_key": "process-only",
        "openai_api_key": "process-only",
        "privacy_consent_version": PRIVACY_NOTICE_VERSION,
        "microphone_consent": True,
        "cloud_stt_consent": True,
        "whisper_model": "base",
        "whisper_model_sha256": "a" * 64,
        "whispercpp_model_sha256": "b" * 64,
    }
    values.update(updates)
    return types.SimpleNamespace(**values)


class ReadinessProbeTests(unittest.TestCase):
    def test_rows_show_fixed_destinations_without_network_probe(self):
        with mock.patch.object(
            readiness.importlib.util,
            "find_spec",
            return_value=object(),
        ), mock.patch.object(
            readiness,
            "resolve_faster_whisper_model",
            return_value=Path("verified-faster"),
        ), mock.patch.object(
            readiness,
            "resolve_whisper_cpp_model",
            return_value=Path("verified-cpp"),
        ):
            rows = readiness.collect_stt_readiness(ready_config())

        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row.ready for row in rows))
        destinations = {row.provider: row.destination for row in rows}
        self.assertEqual(
            destinations["deepgram"],
            "wss://api.deepgram.com/v1/listen",
        )
        self.assertEqual(
            destinations["openai"],
            "https://api.openai.com/v1/audio/transcriptions",
        )
        self.assertEqual(
            destinations["faster_whisper"],
            "This Windows device only",
        )

    def test_missing_consent_and_invalid_local_identity_are_explicit(self):
        with mock.patch.object(
            readiness.importlib.util,
            "find_spec",
            return_value=object(),
        ), mock.patch.object(
            readiness,
            "resolve_faster_whisper_model",
            side_effect=readiness.LocalModelUnavailable("digest mismatch"),
        ), mock.patch.object(
            readiness,
            "resolve_whisper_cpp_model",
            side_effect=readiness.LocalModelUnavailable("model absent"),
        ):
            rows = readiness.collect_stt_readiness(
                ready_config(cloud_stt_consent=False)
            )

        by_provider = {row.provider: row for row in rows}
        self.assertFalse(by_provider["deepgram"].ready)
        self.assertIn(
            "cloud speech-to-text permission is off",
            by_provider["deepgram"].detail,
        )
        self.assertFalse(by_provider["faster_whisper"].ready)
        self.assertIn(
            "digest mismatch",
            by_provider["faster_whisper"].detail,
        )

    def test_probe_has_no_network_or_model_acquisition_surface(self):
        source = (
            ROOT / "audio" / "stt" / "readiness.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "httpx",
            "aiohttp",
            "websocket",
            "subprocess",
            "urlopen",
            "urlretrieve(",
            "install(",
        ):
            self.assertNotIn(forbidden, source)


class FallbackPreferenceTests(unittest.TestCase):
    def test_default_off_and_explicit_local_choice_persist(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("stt_fallback_config")
            selected = config.Config()
            self.assertEqual(selected.stt_fallback_provider(), "")
            selected.set_stt_fallback_provider("faster_whisper")

            restored = config.Config()
            self.assertEqual(
                restored.stt_fallback_provider(),
                "faster_whisper",
            )
            payload = json.loads(
                (Path(temporary) / "Clicky" / "preferences.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                payload["preferences"]["stt_fallback_provider"],
                "faster_whisper",
            )

    def test_cross_cloud_and_same_provider_fallback_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("stt_fallback_rejection_config")
            selected = config.Config()
            with self.assertRaisesRegex(ValueError, "Cross-cloud"):
                selected.set_stt_fallback_provider("openai")

            selected.set_stt_provider("faster_whisper")
            with self.assertRaisesRegex(ValueError, "must differ"):
                selected.set_stt_fallback_provider("faster_whisper")


class _Turns:
    def is_current(self, _session):
        return True


class _Signal:
    def __init__(self):
        self.values = []

    def emit(self, value):
        self.values.append(value)


class _STT:
    def __init__(self, *, result="", error=None):
        self.result = result
        self.error = error
        self.pcm = []

    async def transcribe(self, pcm):
        self.pcm.append(pcm)
        if self.error is not None:
            raise self.error
        return self.result


class _FallbackHarness:
    def __init__(self, primary, fallback):
        self._streaming_stt = {}
        self._turns = _Turns()
        self._primary = primary
        self._fallback = fallback
        self.sig_error = _Signal()

    def _get_stt(self):
        return self._primary

    def _get_fallback_stt(self):
        return self._fallback

    def _emit_turn_signal(self, _session, signal, *args):
        signal.emit(*args)
        return True


class FallbackExecutionTests(unittest.TestCase):
    def test_failure_is_explicit_when_fallback_is_off(self):
        primary = _STT(error=RuntimeError("cloud unavailable"))
        harness = _FallbackHarness(primary, None)
        session = types.SimpleNamespace(sequence=7)
        with mock.patch.object(
            manager_module.cfg,
            "stt_provider",
            return_value="openai",
        ), mock.patch.object(
            manager_module.cfg,
            "stt_fallback_provider",
            return_value="",
        ):
            with self.assertRaisesRegex(RuntimeError, "fallback is off"):
                asyncio.run(
                    CompanionManager._transcribe_with_configured_fallback(
                        harness,
                        b"captured-pcm",
                        session,
                    )
                )

        self.assertEqual(primary.pcm, [b"captured-pcm"])
        self.assertEqual(harness.sig_error.values, [])

    def test_user_approved_local_fallback_is_visible_and_uses_same_pcm(self):
        primary = _STT(error=RuntimeError("cloud unavailable"))
        fallback = _STT(result="local transcript")
        harness = _FallbackHarness(primary, fallback)
        session = types.SimpleNamespace(sequence=8)
        with mock.patch.object(
            manager_module.cfg,
            "stt_provider",
            return_value="deepgram_batch",
        ), mock.patch.object(
            manager_module.cfg,
            "stt_fallback_provider",
            return_value="faster_whisper",
        ):
            result = asyncio.run(
                CompanionManager._transcribe_with_configured_fallback(
                    harness,
                    b"captured-pcm",
                    session,
                )
            )

        self.assertEqual(result, ("local transcript", "faster_whisper"))
        self.assertEqual(fallback.pcm, [b"captured-pcm"])
        self.assertEqual(len(harness.sig_error.values), 1)
        self.assertIn("approved local", harness.sig_error.values[0])
        self.assertIn(
            "no additional cloud provider",
            harness.sig_error.values[0],
        )

    def test_local_fallback_failure_does_not_cross_to_another_provider(self):
        primary = _STT(error=RuntimeError("cloud unavailable"))
        fallback = _STT(error=RuntimeError("local unavailable"))
        harness = _FallbackHarness(primary, fallback)
        session = types.SimpleNamespace(sequence=9)
        with mock.patch.object(
            manager_module.cfg,
            "stt_provider",
            return_value="openai",
        ), mock.patch.object(
            manager_module.cfg,
            "stt_fallback_provider",
            return_value="whisper_cpp",
        ):
            with self.assertRaisesRegex(RuntimeError, "Both OpenAI Whisper"):
                asyncio.run(
                    CompanionManager._transcribe_with_configured_fallback(
                        harness,
                        b"captured-pcm",
                        session,
                    )
                )

        self.assertEqual(primary.pcm, [b"captured-pcm"])
        self.assertEqual(fallback.pcm, [b"captured-pcm"])

    def test_settings_surface_names_readiness_and_policy(self):
        tray = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        dialog = (ROOT / "ui" / "stt_readiness.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("Speech readiness && fallback", tray)
        self.assertIn("fallback:", tray)
        self.assertIn("Fallback is off by default", dialog)
        self.assertIn("never falls across cloud providers", dialog)

    def test_dialog_renders_selected_mode_destination_and_policy(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication
        from ui import stt_readiness as readiness_ui

        application = QApplication.instance() or QApplication([])
        with mock.patch.object(readiness_ui.QTimer, "singleShot"):
            dialog = readiness_ui.SpeechReadinessDialog()
        rows = (
            readiness.STTReadiness(
                "openai",
                "OpenAI Whisper",
                "cloud batch",
                "https://api.openai.com/v1/audio/transcriptions",
                True,
                "Configured and consented.",
            ),
        )
        dialog._show_results(rows)
        application.processEvents()

        rendered = dialog.results.toPlainText()
        self.assertIn("OpenAI Whisper", rendered)
        self.assertIn(
            "https://api.openai.com/v1/audio/transcriptions",
            rendered,
        )
        self.assertIn("Current policy:", dialog.policy_status.text())
        dialog.close()


if __name__ == "__main__":
    unittest.main()
