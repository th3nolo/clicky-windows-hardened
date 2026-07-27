"""Explicit, bounded transcription vocabulary behavior."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from audio.stt import deepgram_stt, openai_stt
from audio.stt.vocabulary import (
    MAX_USER_TERMS,
    SHIPPED_TERMS,
    VocabularyError,
    approved_vocabulary,
    sanitize_user_terms,
    validate_user_terms,
)


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class VocabularyBoundaryTests(unittest.TestCase):
    def test_shipped_and_user_terms_are_bounded_and_deduplicated(self):
        user = [" clicky ", "Open AI", "open  ai", "\x00bad", "x" * 65]
        clean = approved_vocabulary(user)
        self.assertEqual(clean, SHIPPED_TERMS + ("Open AI",))
        self.assertLessEqual(len(clean), 64)

    def test_editor_validation_rejects_invalid_or_excess_terms(self):
        with self.assertRaisesRegex(VocabularyError, "printable"):
            validate_user_terms(["valid", "line\nbreak"])
        with self.assertRaisesRegex(VocabularyError, "At most"):
            validate_user_terms(
                [f"approved-{index}" for index in range(MAX_USER_TERMS + 1)]
            )

    def test_untrusted_preference_load_fails_closed_without_raising(self):
        terms = [f"term-{index}" for index in range(MAX_USER_TERMS + 20)]
        terms.extend(["bad\nterm", "\x00bad", "Clicky"])
        clean = sanitize_user_terms(terms)
        self.assertEqual(len(clean), MAX_USER_TERMS)
        self.assertNotIn("Clicky", clean)


class VocabularyPreferenceTests(unittest.TestCase):
    def test_only_explicitly_saved_terms_persist(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("vocabulary_preference_config")
            instance = config.Config()
            saved = instance.set_transcription_vocabulary(
                ["Acme Product", "API", "api"]
            )
            self.assertEqual(saved, ("Acme Product", "API"))
            restored = config.Config()
            self.assertEqual(
                restored.transcription_vocabulary,
                ("Acme Product", "API"),
            )
            payload = json.loads(
                config._preferences_path().read_text(encoding="utf-8")
            )
            self.assertEqual(
                payload["preferences"]["transcription_vocabulary"],
                ["Acme Product", "API"],
            )


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "results": {
                "channels": [{"alternatives": [{"transcript": "done"}]}]
            }
        }


class FakeHttpClient:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.post_calls = []
        type(self).instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        return FakeResponse()


class FakeOpenAITranscriptions:
    def __init__(self):
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return " approved transcript "


class FakeOpenAIClient:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.audio = mock.Mock()
        self.audio.transcriptions = FakeOpenAITranscriptions()
        type(self).instances.append(self)


class VocabularyProviderTests(unittest.TestCase):
    def test_deepgram_batch_sends_only_approved_terms(self):
        FakeHttpClient.instances = []

        async def exercise():
            provider = deepgram_stt.DeepgramSTT(
                vocabulary=("Clicky", "Approved Term", "approved term")
            )
            with mock.patch.object(
                deepgram_stt.httpx, "AsyncClient", FakeHttpClient
            ), mock.patch.object(
                deepgram_stt, "pcm16_to_wav", return_value=b"synthetic-wav"
            ):
                transcript = await provider.transcribe(bytes(320))
            return transcript

        self.assertEqual(asyncio.run(exercise()), "done")
        client = FakeHttpClient.instances[0]
        self.assertFalse(client.kwargs["trust_env"])
        url, request = client.post_calls[0]
        self.assertEqual(url, deepgram_stt.DEEPGRAM_URL)
        self.assertEqual(
            [
                value
                for key, value in request["params"]
                if key == "keywords"
            ],
            ["Clicky", "Approved Term"],
        )

    def test_openai_batch_sends_only_approved_terms_as_prompt(self):
        FakeOpenAIClient.instances = []

        async def exercise():
            with mock.patch.object(
                openai_stt, "AsyncOpenAI", FakeOpenAIClient
            ), mock.patch.object(
                openai_stt, "pcm16_to_wav", return_value=b"synthetic-wav"
            ):
                provider = openai_stt.OpenAISTT(
                    vocabulary=(
                        "Clicky",
                        "Approved Term",
                        "approved term",
                        "\x00rejected",
                    )
                )
                transcript = await provider.transcribe(bytes(320))
            return transcript

        self.assertEqual(asyncio.run(exercise()), "approved transcript")
        request = (
            FakeOpenAIClient.instances[0]
            .audio.transcriptions.calls[0]
        )
        self.assertEqual(request["prompt"], "Clicky, Approved Term")
        self.assertEqual(request["model"], "whisper-1")
        self.assertEqual(request["response_format"], "text")

    def test_unsupported_providers_do_not_read_or_send_vocabulary(self):
        for relative in (
            "audio/stt/faster_whisper_stt.py",
            "audio/stt/whisper_cpp_stt.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("transcription_vocabulary", source)
            self.assertNotIn("approved_vocabulary", source)

    def test_manager_uses_only_saved_vocabulary_not_incidental_context(self):
        source = (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        self.assertIn("vocabulary=cfg.transcription_vocabulary", source)
        for forbidden in (
            "vocabulary=title",
            "vocabulary=transcript",
            "vocabulary=self._attached_docs",
            "vocabulary=images_b64",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
