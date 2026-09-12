"""Drawing markup stays hidden regardless of network chunk boundaries."""

import unittest

from ai.response_text import ResponseText


class ResponseTextTests(unittest.TestCase):
    def test_every_split_of_a_response_produces_the_same_visible_text(self):
        text = "Look [POINT:10,20:here]at x² [CIRCLE:5,6,3]and solve."
        for boundary in range(len(text) + 1):
            with self.subTest(boundary=boundary):
                stream = ResponseText()
                visible = stream.feed(text[:boundary]) + stream.feed(text[boundary:])
                self.assertEqual(visible + stream.finish(), "Look at x² and solve.")

    def test_character_stream_preserves_math_and_multiple_annotations(self):
        stream = ResponseText()
        text = "[CLEAR]x ∈ [0, 1]. [ARROW:1,2->3,4]Next."
        visible = "".join(stream.feed(char) for char in text) + stream.finish()
        self.assertEqual(visible, "x ∈ [0, 1]. Next.")

    def test_finish_preserves_existing_incomplete_text_behavior_and_resets(self):
        stream = ResponseText()
        self.assertEqual(stream.feed("prefix [POINT:1"), "prefix ")
        self.assertEqual(stream.finish(), "[POINT:1")
        self.assertEqual(stream.finish(), "")
        self.assertEqual(stream.feed("fresh"), "fresh")
