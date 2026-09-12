"""Built-in voice intent matching without intercepting ordinary questions."""

from __future__ import annotations

import unittest

from tutor import (
    VoiceCommand,
    classify_voice_command,
    is_journal_today,
    is_journal_week,
    is_next,
    is_quiz_review,
    is_repeat,
    is_stop,
)


class VoiceCommandTests(unittest.TestCase):
    def test_supported_phrases(self) -> None:
        cases = {
            VoiceCommand.STOP: ("stop", " QUIT! ", "cancel", "never mind", "nevermind"),
            VoiceCommand.NEXT: ("next", "continue", "go on", "keep going", "what's next?"),
            VoiceCommand.REPEAT: (
                "repeat", "say it again", "say that again", "say again",
                "once more", "what did you say?", "what d’you say?",
            ),
            VoiceCommand.JOURNAL_TODAY: (
                "What did I learn today?", "what have I learned so far",
                "Please tell me what did I asked today",
            ),
            VoiceCommand.JOURNAL_WEEK: (
                "What did I learn this week?", "what have I learned recently",
                "what did I learn in the past week",
            ),
            VoiceCommand.QUIZ_REVIEW: (
                "quiz me", "review me on my notes", "test me on what I learned",
                "Please quiz me on algebra",
            ),
        }
        for expected, phrases in cases.items():
            for phrase in phrases:
                with self.subTest(phrase=phrase):
                    self.assertEqual(classify_voice_command(phrase), expected)

    def test_ordinary_questions_are_not_control_commands(self) -> None:
        for text in (
            "", "   ", "How do I stop this sequence from diverging?",
            "How do I cancel common factors?", "Find the next prime number",
            "Why do the digits repeat?", "Continue the proof by induction",
            "What is the next step in solving this equation?", "stop and repeat",
            "never mind the denominator", "What did I learn yesterday?",
        ):
            with self.subTest(text=text):
                self.assertIsNone(classify_voice_command(text))

    def test_ambiguous_journal_and_quiz_requests_preserve_priority(self) -> None:
        for text, expected in (
            ("quiz me on what did I learn today", VoiceCommand.JOURNAL_TODAY),
            ("quiz me; what did I learn this week?", VoiceCommand.JOURNAL_WEEK),
            (
                "What did I learn this week, and what did I learn today?",
                VoiceCommand.JOURNAL_TODAY,
            ),
        ):
            with self.subTest(text=text):
                self.assertEqual(classify_voice_command(text), expected)

    def test_legacy_predicates_still_match_independently(self) -> None:
        predicates = (
            (is_stop, "stop"),
            (is_next, "next"),
            (is_repeat, "repeat"),
            (is_journal_today, "what did I learn today"),
            (is_journal_week, "what did I learn this week"),
            (is_quiz_review, "quiz me"),
        )
        for predicate, phrase in predicates:
            with self.subTest(phrase=phrase):
                self.assertTrue(predicate(phrase))
                self.assertFalse(predicate(""))
        ambiguous = "Quiz me on what did I learn today"
        self.assertTrue(is_journal_today(ambiguous))
        self.assertTrue(is_quiz_review(ambiguous))


if __name__ == "__main__":
    unittest.main()
