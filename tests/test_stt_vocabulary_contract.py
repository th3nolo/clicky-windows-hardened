"""Keep the manual vocabulary validation contract aligned with provider behavior."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def approved_vocabulary_section() -> str:
    testing = (ROOT / "TESTING.md").read_text(encoding="utf-8")
    section = testing.split("### Approved transcription vocabulary", 1)[1]
    return " ".join(section.split("\n### ", 1)[0].split())


class VocabularyManualContractTests(unittest.TestCase):
    def test_manual_contract_covers_each_provider_behavior(self):
        section = approved_vocabulary_section()

        self.assertIn("Deepgram live WebSocket", section)
        self.assertIn("Deepgram batch request", section)
        self.assertIn("OpenAI batch request", section)
        self.assertIn("`prompt` field", section)
        self.assertIn(
            "both local STT modes receive no vocabulary input",
            section,
        )
        self.assertNotIn(
            "OpenAI and both local STT modes receive no vocabulary parameter",
            section,
        )

    def test_source_matches_the_documented_openai_and_local_contract(self):
        openai_source = (ROOT / "audio/stt/openai_stt.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'prompt=", ".join(self._vocabulary)',
            openai_source,
        )

        for relative in (
            "audio/stt/faster_whisper_stt.py",
            "audio/stt/whisper_cpp_stt.py",
        ):
            local_source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("transcription_vocabulary", local_source)
            self.assertNotIn("approved_vocabulary", local_source)


if __name__ == "__main__":
    unittest.main()
