"""Standard-library contracts for reviewed, provider-specific TTS voices."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from audio.tts.voice_catalog import (
    TTS_PROVIDERS,
    default_voice_id,
    provider_destination,
    reviewed_voice,
    reviewed_voices,
    selected_voice,
)
from audio.tts.voice_preview import (
    VOICE_PREVIEW_TEXT,
    VOICE_PREVIEW_TIMEOUT_SECONDS,
    speak_voice_preview,
)
from tutor_features.multilang import _LANG_VOICE


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReviewedVoiceCatalogTests(unittest.TestCase):
    def test_every_provider_has_fixed_destination_default_and_unique_ids(self):
        self.assertEqual(
            {
                provider: provider_destination(provider)
                for provider in TTS_PROVIDERS
            },
            {
                "edge_tts": "speech.platform.bing.com",
                "openai": "api.openai.com",
                "elevenlabs": "api.elevenlabs.io",
            },
        )
        for provider in TTS_PROVIDERS:
            voices = reviewed_voices(provider)
            ids = [voice.voice_id for voice in voices]
            self.assertTrue(ids)
            self.assertEqual(len(ids), len(set(ids)))
            self.assertIn(default_voice_id(provider), ids)
            self.assertTrue(
                all(voice.destination == provider_destination(provider) for voice in voices)
            )

    def test_unknown_provider_and_arbitrary_voice_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            reviewed_voices("custom")
        with self.assertRaises(ValueError):
            reviewed_voice("edge_tts", "file:///unreviewed")
        with self.assertRaises(TypeError):
            reviewed_voice("openai", None)

    def test_tampered_persisted_values_resolve_to_reviewed_defaults(self):
        for provider in TTS_PROVIDERS:
            resolved = selected_voice(provider, "../../tampered")
            self.assertEqual(resolved.voice_id, default_voice_id(provider))

    def test_multilingual_runtime_voices_are_all_reviewed_edge_ids(self):
        reviewed = {voice.voice_id for voice in reviewed_voices("edge_tts")}
        self.assertLessEqual(
            {voice_id for _label, voice_id in _LANG_VOICE.values()},
            reviewed,
        )


class VoicePreferenceTests(unittest.TestCase):
    def test_voice_persists_independently_per_provider(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": tmp},
            clear=True,
        ):
            config = load_config("tts_voice_preferences")
            configured = config.Config()
            original_instructions = configured.custom_instructions

            self.assertEqual(
                configured.set_tts_voice("edge_tts", "en-US-AriaNeural"),
                "en-US-AriaNeural",
            )
            self.assertEqual(
                configured.set_tts_voice("openai", "coral"),
                "coral",
            )
            self.assertEqual(
                configured.set_tts_voice(
                    "elevenlabs",
                    "EXAVITQu4vr4xnSDxMaL",
                ),
                "EXAVITQu4vr4xnSDxMaL",
            )

            reloaded = config.Config()
            self.assertEqual(
                reloaded.get_tts_voice("edge_tts"),
                "en-US-AriaNeural",
            )
            self.assertEqual(reloaded.get_tts_voice("openai"), "coral")
            self.assertEqual(
                reloaded.get_tts_voice("elevenlabs"),
                "EXAVITQu4vr4xnSDxMaL",
            )
            self.assertEqual(reloaded.custom_instructions, original_instructions)

    def test_unreviewed_selection_does_not_mutate_memory_or_disk(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": tmp},
            clear=True,
        ):
            config = load_config("tts_voice_rejection")
            configured = config.Config()
            before = configured.get_tts_voice("edge_tts")
            with self.assertRaises(ValueError):
                configured.set_tts_voice("edge_tts", "arbitrary")
            self.assertEqual(configured.get_tts_voice("edge_tts"), before)
            self.assertEqual(config.Config().get_tts_voice("edge_tts"), before)


class VoicePreviewBoundaryTests(unittest.TestCase):
    class Speaker:
        def __init__(self):
            self.spoken = []

        async def speak(self, text):
            self.spoken.append(text)

    def test_preview_uses_only_fixed_text_and_exact_reviewed_provider(self):
        speaker = self.Speaker()
        factory_calls = []

        def factory(provider, voice_id):
            factory_calls.append((provider, voice_id))
            return speaker

        selected = asyncio.run(
            speak_voice_preview(
                "openai",
                "coral",
                cloud_tts_permission=True,
                provider_factory=factory,
            )
        )

        self.assertEqual(selected.voice_id, "coral")
        self.assertEqual(factory_calls, [("openai", "coral")])
        self.assertEqual(speaker.spoken, [VOICE_PREVIEW_TEXT])

    def test_permission_and_catalog_checks_happen_before_provider_creation(self):
        factory = mock.Mock()
        with self.assertRaises(PermissionError):
            asyncio.run(
                speak_voice_preview(
                    "edge_tts",
                    "en-US-AvaNeural",
                    cloud_tts_permission=False,
                    provider_factory=factory,
                )
            )
        with self.assertRaises(ValueError):
            asyncio.run(
                speak_voice_preview(
                    "edge_tts",
                    "arbitrary",
                    cloud_tts_permission=True,
                    provider_factory=factory,
                )
            )
        factory.assert_not_called()

    def test_preview_timeout_is_strictly_bounded_and_cancellable(self):
        class SlowSpeaker:
            async def speak(self, _text):
                await asyncio.sleep(1)

        with self.assertRaises(asyncio.TimeoutError):
            asyncio.run(
                speak_voice_preview(
                    "edge_tts",
                    "en-US-AvaNeural",
                    cloud_tts_permission=True,
                    provider_factory=lambda _provider, _voice: SlowSpeaker(),
                    timeout_seconds=0.01,
                )
            )
        for invalid in (0, -1, VOICE_PREVIEW_TIMEOUT_SECONDS + 0.01, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                asyncio.run(
                    speak_voice_preview(
                        "edge_tts",
                        "en-US-AvaNeural",
                        cloud_tts_permission=True,
                        provider_factory=lambda _provider, _voice: self.Speaker(),
                        timeout_seconds=invalid,
                    )
                )

    def test_preview_source_has_no_fallback_or_user_text_parameter(self):
        source = (ROOT / "audio" / "tts" / "voice_preview.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("VOICE_PREVIEW_TEXT", source)
        self.assertNotIn("_speak_with_failure_fallback", source)
        self.assertNotIn("local_status_tts", source)
        self.assertNotIn("custom_instructions", source)


if __name__ == "__main__":
    unittest.main()
