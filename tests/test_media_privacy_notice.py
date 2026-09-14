"""Exact-model notices and opt-in routing preferences without app startup."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai.provider_catalog import MUSE_VIDEO_MODELS, supports_video, video_model_notices
from ai.provider_endpoints import provider_endpoint
from privacy_controls import PRIVACY_NOTICE_VERSION
from tests.provider_test_support import load_config


class MediaModelNoticeTests(unittest.TestCase):
    def test_supported_models_keep_compatibility_and_contributor_disclosure(self):
        for model in MUSE_VIDEO_MODELS:
            with self.subTest(model=model):
                self.assertTrue(supports_video("openrouter", model))
                notices = " ".join(video_model_notices("openrouter", model))
                self.assertIn("Meta's products", notices)
                self.assertIn("may use", notices)

    def test_audio_caveat_is_specific_to_muse_13(self):
        old = " ".join(video_model_notices("openrouter", "meta/muse-spark-1.2-contributor"))
        new = " ".join(video_model_notices("openrouter", "meta/muse-spark-1.3-contributor"))
        self.assertNotIn("audio understanding", old)
        self.assertIn("audio understanding is currently limited", new)

    def test_unrelated_provider_or_model_receives_no_contributor_claim(self):
        for provider, model in (
            ("openai", "meta/muse-spark-1.3-contributor"),
            ("openrouter", "meta/muse-spark-1.3"),
            ("ollama", "local-model"),
            ("openrouter", None),
        ):
            with self.subTest(provider=provider, model=model):
                self.assertEqual(video_model_notices(provider, model), ())


class ExplicitEndpointTests(unittest.TestCase):
    def test_explicit_local_and_cloud_base_paths_remain_available(self):
        for value in (
            "http://127.0.0.1:1234/v1", "http://localhost:8080/proxy",
            "http://[::1]:1234/v1", "https://router.example/anthropic",
        ):
            with self.subTest(value=value):
                self.assertEqual(provider_endpoint(value + "/", default=""), value)

    def test_bad_endpoint_shapes_are_rejected_without_echoing_input(self):
        for value in (
            "ftp://example.com", "https:///v1", "https://", "relative/path",
            "https://secret@example.com", "https://user:secret@example.com",
            "https://example.com?secret=x", "https://example.com#secret",
            "https://example.com?", "https://example.com#",
            "https://example.com:70000", "http://localhost:abc/v1",
            "http://localhost:/v1", "https://example.com/\x85secret",
            " https://example.com", "https://example.com/\nsecret",
            "https://example.com/\x00secret", "https://example.com\\secret",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                provider_endpoint(value, default="")
            self.assertNotIn("secret", str(error.exception))


class OpenRouterPrivacyPreferenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = patch.dict(os.environ, {"LOCALAPPDATA": self.directory.name}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.config = load_config("media_privacy_config")
        self.instance = self.config.Config()

    def save(self, **extra):
        self.instance.set_privacy_permissions(
            microphone=False, cloud_stt=False, cloud_tts=False,
            screen_capture=False, notice_version=PRIVACY_NOTICE_VERSION, **extra,
        )

    def test_default_preserves_routing_and_opt_in_survives_older_callers(self):
        self.assertFalse(self.instance.openrouter_private_routing)
        self.save(openrouter_private_routing=True)
        self.save()  # Older callers changing consent must not remove this restriction.
        restored = load_config("media_privacy_reload").Config()
        self.assertTrue(restored.openrouter_private_routing)
        self.save(openrouter_private_routing=False)
        self.assertFalse(load_config("media_privacy_disabled").Config().openrouter_private_routing)

    def test_invalid_values_do_not_replace_saved_restriction(self):
        self.save(openrouter_private_routing=True)
        for value in ("false", 0, 1, [], {}):
            with self.subTest(value=value), self.assertRaises(TypeError):
                self.save(openrouter_private_routing=value)
        self.assertTrue(load_config("media_privacy_invalid").Config().openrouter_private_routing)

    def test_failed_save_does_not_change_in_memory_restriction(self):
        with patch.object(self.config, "_save_preferences", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                self.save(openrouter_private_routing=True)
        self.assertFalse(self.instance.openrouter_private_routing)

    def test_speech_key_is_environment_only_and_never_persisted(self):
        with patch.dict(os.environ, {"OPENAI_SPEECH_API_KEY": "synthetic-speech-key"}):
            self.assertEqual(self.config.Config().openai_speech_api_key, "synthetic-speech-key")
        self.save(openrouter_private_routing=True)
        payload = json.loads((Path(self.directory.name) / "Clicky" / "preferences.json").read_text())
        self.assertNotIn("openai_speech_api_key", payload["preferences"])
        self.assertNotIn("synthetic-speech-key", json.dumps(payload))

    def test_speech_only_key_selects_speech_without_selecting_chat(self):
        self.instance.openai_speech_api_key = "synthetic-speech-key"
        self.assertTrue(self.instance.has_openai_speech_credentials())
        self.assertEqual(self.instance.stt_provider(), "openai")
        self.assertIn("openai", self.instance.available_stt_providers())
        self.assertEqual(self.instance.tts_provider(), "openai")
        self.assertIsNone(self.instance.openai_api_key)

    def test_custom_chat_key_is_not_advertised_for_official_speech(self):
        self.instance.openai_api_key = "synthetic-router-key"
        self.instance.openai_base_url = "https://synthetic.invalid/v1"
        self.assertFalse(self.instance.has_openai_speech_credentials())
        self.assertNotIn("openai", self.instance.available_stt_providers())
        self.assertNotEqual(self.instance.tts_provider(), "openai")
        self.instance.openai_speech_api_key = "synthetic-speech-key"
        self.assertTrue(self.instance.has_openai_speech_credentials())
        self.assertEqual(self.instance.stt_provider(), "openai")
        self.assertEqual(self.instance.tts_provider(), "openai")

    def test_default_official_chat_key_remains_compatible_with_speech(self):
        self.instance.openai_api_key = "synthetic-openai-key"
        for endpoint in ("", "https://api.openai.com/v1", "https://api.openai.com/v1/"):
            with self.subTest(endpoint=endpoint):
                self.instance.openai_base_url = endpoint
                self.assertTrue(self.instance.has_openai_speech_credentials())
                self.assertEqual(self.instance.stt_provider(), "openai")
                self.assertEqual(self.instance.tts_provider(), "openai")

    def test_only_clicky_owned_endpoint_variables_change_routing(self):
        with patch.dict(os.environ, {
            "OPENAI_BASE_URL": "https://shared.invalid/v1",
            "ANTHROPIC_BASE_URL": "https://shared.invalid",
        }):
            configured = self.config.Config()
            self.assertEqual(configured.openai_base_url, "")
            self.assertEqual(configured.anthropic_base_url, "https://api.anthropic.com")
        with patch.dict(os.environ, {
            "CLICKY_OPENAI_BASE_URL": "http://localhost:1234/v1/",
            "CLICKY_ANTHROPIC_BASE_URL": "https://router.example/anthropic/",
        }):
            configured = self.config.Config()
            self.assertEqual(configured.openai_base_url, "http://localhost:1234/v1")
            self.assertEqual(configured.anthropic_base_url, "https://router.example/anthropic")
        self.save()
        payload = json.loads((Path(self.directory.name) / "Clicky" / "preferences.json").read_text())
        self.assertNotIn("openai_base_url", payload["preferences"])
        self.assertNotIn("anthropic_base_url", payload["preferences"])

    def test_explicit_router_vision_setting_is_endpoint_bound_and_not_persisted(self):
        with patch.dict(os.environ, {
            "CLICKY_OPENAI_BASE_URL": "http://localhost:1234/v1/",
            "CLICKY_OPENAI_VISION_MODELS": "qwen-vl,local-vl",
        }):
            configured = self.config.Config()
        self.assertEqual(configured.openai_router_vision_models,
                         {"http://localhost:1234/v1": ("qwen-vl", "local-vl")})
        self.save()
        payload = json.loads((Path(self.directory.name) / "Clicky" / "preferences.json").read_text())
        self.assertNotIn("openai_router_vision_models", payload["preferences"])


if __name__ == "__main__":
    unittest.main()
