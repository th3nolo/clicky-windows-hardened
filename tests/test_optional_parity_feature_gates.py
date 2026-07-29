"""Persistence and independent gates for restored optional parity features."""

from __future__ import annotations

import importlib.util
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


def privacy(**updates):
    values = {
        "privacy_consent_version": privacy_controls.PRIVACY_NOTICE_VERSION,
        "microphone_consent": True,
        "cloud_stt_consent": True,
        "cloud_tts_consent": True,
        "screen_capture_consent": False,
        "coding_agent_consent": False,
        "external_place_search_consent": True,
        "market_data_consent": True,
        "realtime_voice_enabled": True,
    }
    values.update(updates)
    return types.SimpleNamespace(**values)


class OptionalParityFeatureGateTests(unittest.TestCase):
    def test_optional_features_default_off_and_persist_independently(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=True
        ):
            config = load_config("optional_parity_defaults")
            configured = config.Config()
            self.assertFalse(configured.realtime_voice_enabled)
            self.assertFalse(configured.signed_skill_import_enabled)
            self.assertFalse(configured.meeting_countdowns_enabled)
            self.assertIsNone(configured.realtime_output_device_index)

            configured.set_optional_feature("realtime_voice", True)
            configured.set_optional_feature("meeting_countdowns", True)
            configured.set_realtime_output_device_index(9)
            reloaded = config.Config()
            self.assertTrue(reloaded.realtime_voice_enabled)
            self.assertFalse(reloaded.signed_skill_import_enabled)
            self.assertTrue(reloaded.meeting_countdowns_enabled)
            self.assertEqual(reloaded.realtime_output_device_index, 9)

    def test_unknown_feature_and_invalid_device_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=True
        ):
            config = load_config("optional_parity_rejections")
            configured = config.Config()
            with self.assertRaises(ValueError):
                configured.set_optional_feature("unreviewed", True)
            with self.assertRaises(TypeError):
                configured.set_optional_feature("realtime_voice", 1)
            with self.assertRaises(ValueError):
                configured.set_realtime_output_device_index(-1)

    def test_realtime_requires_feature_and_all_three_audio_permissions(self):
        self.assertTrue(privacy_controls.realtime_voice_allowed(privacy()))
        for values in (
            {"realtime_voice_enabled": False},
            {"microphone_consent": False},
            {"cloud_stt_consent": False},
            {"cloud_tts_consent": False},
            {
                "privacy_consent_version":
                    privacy_controls.PRIVACY_NOTICE_VERSION - 1
            },
        ):
            self.assertFalse(
                privacy_controls.realtime_voice_allowed(privacy(**values))
            )

    def test_external_place_and_market_data_are_independent(self):
        self.assertTrue(
            privacy_controls.external_place_search_allowed(privacy())
        )
        self.assertTrue(privacy_controls.market_data_allowed(privacy()))
        self.assertFalse(
            privacy_controls.external_place_search_allowed(
                privacy(external_place_search_consent=False)
            )
        )
        self.assertTrue(
            privacy_controls.market_data_allowed(
                privacy(external_place_search_consent=False)
            )
        )
        self.assertFalse(
            privacy_controls.market_data_allowed(
                privacy(market_data_consent=False)
            )
        )

    def test_expanded_privacy_choices_persist_atomically(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": tmp}, clear=True
        ):
            config = load_config("optional_parity_privacy")
            configured = config.Config()
            configured.set_privacy_permissions(
                microphone=False,
                cloud_stt=False,
                cloud_tts=False,
                screen_capture=False,
                external_place_search=True,
                market_data=False,
                notice_version=privacy_controls.PRIVACY_NOTICE_VERSION,
            )
            reloaded = config.Config()
            self.assertTrue(reloaded.external_place_search_consent)
            self.assertFalse(reloaded.market_data_consent)

    def test_privacy_dialog_exposes_both_external_data_destinations(self):
        source = (ROOT / "ui" / "privacy_consent.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("configured map provider", source)
        self.assertIn("end-of-day stock quote", source)
        self.assertIn(
            "external_place_search=self.external_place_search.isChecked()",
            source,
        )
        self.assertIn("market_data=self.market_data.isChecked()", source)


if __name__ == "__main__":
    unittest.main()
