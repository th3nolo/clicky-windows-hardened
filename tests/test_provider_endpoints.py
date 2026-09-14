"""Characterize endpoint identity where cache and speech-key boundaries meet."""

import unittest

from ai.provider_endpoints import (
    ANTHROPIC_BASE_URL,
    OPENAI_BASE_URL,
    anthropic_endpoint,
    is_custom_openai_endpoint,
    openai_endpoint,
)
from audio.openai_credentials import openai_speech_api_key


class ProviderEndpointTests(unittest.TestCase):
    def test_official_defaults_and_trailing_slashes_share_identity(self):
        for resolve, official in (
            (openai_endpoint, OPENAI_BASE_URL),
            (anthropic_endpoint, ANTHROPIC_BASE_URL),
        ):
            for value in (None, "", official, official + "/", official + "///"):
                with self.subTest(resolve=resolve.__name__, value=value):
                    self.assertEqual(resolve(value), official)
        for value in (None, "", OPENAI_BASE_URL, OPENAI_BASE_URL + "///"):
            with self.subTest(speech_endpoint=value):
                self.assertFalse(is_custom_openai_endpoint(value))
                self.assertEqual(openai_speech_api_key(
                    speech_key=None, chat_key="chat-dummy", chat_base_url=value,
                ), "chat-dummy")

    def test_custom_identity_preserves_host_case_ports_and_path_prefixes(self):
        cases = (
            ("http://127.0.0.1:9876/custom/v1///", "http://127.0.0.1:9876/custom/v1"),
            ("http://localhost:11434/v1/", "http://localhost:11434/v1"),
            ("https://router.invalid/anthropic/", "https://router.invalid/anthropic"),
            ("https://API.OPENAI.COM/v1/", "https://API.OPENAI.COM/v1"),
            ("https://api.openai.com:443/v1/", "https://api.openai.com:443/v1"),
            ("https://api.openai.com/v1/extra", "https://api.openai.com/v1/extra"),
            # Validation is a separate config boundary; identity does not repair it.
            ("/", ""),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(openai_endpoint(value), expected)
                self.assertEqual(anthropic_endpoint(value), expected)
                self.assertTrue(is_custom_openai_endpoint(value))
                with self.assertRaisesRegex(RuntimeError, "chat router credential was not sent"):
                    openai_speech_api_key(
                        speech_key=None, chat_key="router-dummy", chat_base_url=value,
                    )
                self.assertEqual(openai_speech_api_key(
                    speech_key="speech-dummy", chat_key="router-dummy", chat_base_url=value,
                ), "speech-dummy")

    def test_missing_keys_keep_the_existing_failure(self):
        with self.assertRaisesRegex(RuntimeError, "OPENAI_SPEECH_API_KEY or OPENAI_API_KEY"):
            openai_speech_api_key(speech_key=None, chat_key=None, chat_base_url="")


if __name__ == "__main__":
    unittest.main()
