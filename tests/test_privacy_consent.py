"""Standard-library tests for fail-closed sensitive-capability consent."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import privacy_controls


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivacyControlTests(unittest.TestCase):
    def test_permissions_fail_closed_before_notice_acceptance(self) -> None:
        configured = types.SimpleNamespace(
            privacy_consent_version=0,
            microphone_consent=True,
            cloud_tts_consent=True,
            screen_capture_consent=True,
        )
        self.assertFalse(privacy_controls.microphone_allowed(configured))
        self.assertFalse(privacy_controls.cloud_tts_allowed(configured))
        self.assertFalse(privacy_controls.screen_capture_allowed(configured))

    def test_each_permission_is_independent(self) -> None:
        configured = types.SimpleNamespace(
            privacy_consent_version=privacy_controls.PRIVACY_NOTICE_VERSION,
            microphone_consent=True,
            cloud_tts_consent=False,
            screen_capture_consent=False,
        )
        self.assertTrue(privacy_controls.microphone_allowed(configured))
        self.assertFalse(privacy_controls.cloud_tts_allowed(configured))
        self.assertFalse(privacy_controls.screen_capture_allowed(configured))

    def test_defaults_are_disabled_and_choices_persist_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=True
        ):
            config = load_config("privacy_config_defaults")
            initial = config.Config()
            self.assertEqual(initial.privacy_consent_version, 0)
            self.assertFalse(initial.microphone_consent)
            self.assertFalse(initial.cloud_tts_consent)
            self.assertFalse(initial.screen_capture_consent)

            initial.set_privacy_permissions(
                microphone=True,
                cloud_tts=False,
                screen_capture=True,
                notice_version=privacy_controls.PRIVACY_NOTICE_VERSION,
            )
            reloaded = config.Config()
            self.assertEqual(
                reloaded.privacy_consent_version,
                privacy_controls.PRIVACY_NOTICE_VERSION,
            )
            self.assertTrue(reloaded.microphone_consent)
            self.assertFalse(reloaded.cloud_tts_consent)
            self.assertTrue(reloaded.screen_capture_consent)

    def test_tampered_preference_types_grant_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=True
        ):
            directory = Path(tmp) / "Clicky"
            directory.mkdir()
            (directory / "preferences.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "preferences": {
                            "privacy_consent_version": True,
                            "microphone_consent": "yes",
                            "cloud_tts_consent": 1,
                            "screen_capture_consent": [],
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = load_config("privacy_config_tampered")
            loaded = config.Config()
            self.assertEqual(loaded.privacy_consent_version, 0)
            self.assertFalse(loaded.microphone_consent)
            self.assertFalse(loaded.cloud_tts_consent)
            self.assertFalse(loaded.screen_capture_consent)

    def test_invalid_notice_version_is_rejected_without_partial_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=True
        ):
            config = load_config("privacy_config_invalid_version")
            loaded = config.Config()
            with self.assertRaises(ValueError):
                loaded.set_privacy_permissions(
                    microphone=True,
                    cloud_tts=True,
                    screen_capture=True,
                    notice_version=privacy_controls.PRIVACY_NOTICE_VERSION + 1,
                )
            reloaded = config.Config()
            self.assertEqual(reloaded.privacy_consent_version, 0)
            self.assertFalse(reloaded.microphone_consent)

    def test_storage_failure_does_not_grant_in_memory_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=True
        ):
            config = load_config("privacy_config_storage_failure")
            loaded = config.Config()
            with mock.patch.object(
                config, "_save_preferences", side_effect=OSError("disk blocked")
            ), self.assertRaisesRegex(OSError, "disk blocked"):
                loaded.set_privacy_permissions(
                    microphone=True,
                    cloud_tts=True,
                    screen_capture=True,
                    notice_version=privacy_controls.PRIVACY_NOTICE_VERSION,
                )
            self.assertEqual(loaded.privacy_consent_version, 0)
            self.assertFalse(loaded.microphone_consent)
            self.assertFalse(loaded.cloud_tts_consent)
            self.assertFalse(loaded.screen_capture_consent)


class PrivacyWiringTests(unittest.TestCase):
    def test_consent_prompt_precedes_hotkey_and_microphone_start(self) -> None:
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        prompt = source.index(
            "Sensitive capabilities remain off until the current privacy notice"
        )
        hotkey = source.index("hotkey.start()", prompt)
        listener = source.index("manager.start()", hotkey)
        self.assertLess(prompt, hotkey)
        self.assertLess(hotkey, listener)

    def test_manager_gates_every_screen_capture_path(self) -> None:
        source = (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("capture_all_screens()"), 2)
        self.assertIn(
            "if sensitive or identity_q or not screen_permission:", source
        )
        quiz_gate = source.index(
            'if not screen_capture_allowed(cfg):\n'
            '            self.sig_error.emit(\n'
            '                "Quiz Mode needs screen capture permission.'
        )
        quiz_capture = source.index("capture_all_screens()", quiz_gate)
        self.assertLess(quiz_gate, quiz_capture)

    def test_manager_gates_microphone_and_cloud_tts(self) -> None:
        source = (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        self.assertIn("if microphone_allowed(cfg):", source)
        self.assertIn("if not microphone_allowed(cfg):", source)
        self.assertIn("if not cloud_tts_allowed(cfg):", source)
        tts_gate = source.index("if not cloud_tts_allowed(cfg):")
        edge_import = source.index(
            "from audio.tts.edge_tts_provider import EdgeTTSProvider"
        )
        self.assertLess(tts_gate, edge_import)


if __name__ == "__main__":
    unittest.main()
