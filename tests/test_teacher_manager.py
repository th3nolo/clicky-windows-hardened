"""Real manager release/teacher orchestration; fake device, provider and MCP IO."""

import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from PyQt6.QtCore import Qt

from tests import test_original_voice_video as original
from ai.response_selection import ResponseDispatch
from automation import inknotes_mcp


module = original.module
PAGE = {"notebook_id": "synthetic-book", "page_id": "page-a", "revision": 7}
ANSWER = "Multiply each row by the vector. The result is sixteen and thirty-nine."


def page_result(page):
    return {"content": [{"type": "text", "text": json.dumps(page)}]}


class TeacherManagerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Reuse the existing real CompanionManager lifecycle fixture without
        # inheriting (and rerunning) its separate integration test methods.
        original.OriginalVoiceVideoTests.setUp(self)
        self.recorder.finish.return_value = original.encode_clip(
            *original.sample_clip(), lambda: False
        )
        self.manager._web_search_enabled = False
        self.manager._multilang = False
        self.manager._code_mode_auto = False
        self.manager._journal_enabled = False
        self.events = []
        self.errors = []
        self.manager.sig_error.connect(
            self.errors.append, type=Qt.ConnectionType.DirectConnection
        )
        self.client = SimpleNamespace(call=AsyncMock(side_effect=self.read_page))
        self.stack.enter_context(patch.object(inknotes_mcp, "InkNotesMcpClient", return_value=self.client))
        self.stack.enter_context(patch.object(inknotes_mcp, "foreground_notebook_pid", return_value=12345))
        self.stack.enter_context(patch.object(module, "active_window_title", return_value="Synthetic notebook"))
        self.stack.enter_context(patch.object(module, "capture_all_screens", return_value=[]))
        self.stack.enter_context(patch.object(module.skills_pkg, "match", return_value=None))
        self.stack.enter_context(patch.object(self.manager, "_handle_voice_command", AsyncMock(return_value=False)))
        self.stack.enter_context(patch("audio.stt.openrouter_stt._pcm16_to_mp3", return_value=b"synthetic-mp3"))
        self.stack.enter_context(patch("ai.model_selection.model_supports_vision", return_value=True))
        self.stack.enter_context(patch.object(self.manager, "_transcribe_with_configured_fallback", AsyncMock(side_effect=self.transcribe)))
        self.backend = SimpleNamespace(stream_multimodal_response=self.reason)
        self.stack.enter_context(patch.object(self.manager, "_acquire_response_dispatch", return_value=ResponseDispatch(self.selection, self.backend)))
        self.speak = self.stack.enter_context(patch.object(self.manager, "_speak_with_failure_fallback", AsyncMock(side_effect=self.narrate)))
        self.lesson = self.stack.enter_context(patch.object(self.manager, "_play_lesson", AsyncMock()))

    def tearDown(self):
        original.OriginalVoiceVideoTests.tearDown(self)

    async def read_page(self, tool, *args, **kwargs):
        self.assertEqual(tool, "inknotes_read_page")
        self.events.append("snapshot")
        return page_result(PAGE)

    async def transcribe(self, pcm, session):
        self.events.append("transcribe")
        return "Write the complete explanation here", "openrouter"

    async def reason(self, **kwargs):
        self.events.append("reason")
        yield ANSWER

    async def narrate(self, text, session):
        self.events.append(("speak", text))
        return True

    async def process_capture(self):
        self.manager.on_hotkey_press()
        session = self.manager._turns.active
        self.assertIsNotNone(session)
        self.manager._turns.release_capture(session)
        await self.manager._end_capture_and_process(session)
        self.assertEqual(self.errors, [])
        self.assertIsNone(self.manager._turns.active)

    async def test_release_snapshot_precedes_transcription_and_reasoning(self):
        writer = self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", AsyncMock(return_value="Writing not verified.")))
        await self.process_capture()
        self.assertEqual(self.events[:3], ["snapshot", "transcribe", "reason"])
        writer.assert_awaited_once()
        self.assertEqual(writer.call_args.kwargs["expected_page"], PAGE)
        self.assertIs(writer.call_args.kwargs["supports_vision"], True)
        self.assertIs(writer.call_args.args[1], self.backend)
        self.assertEqual(writer.call_args.args[4], ANSWER)
        self.lesson.assert_awaited_once()

    async def test_changed_page_reaches_real_planner_with_original_snapshot(self):
        # The real planner owns mismatch rejection. Manager must not replace
        # release identity with the page which is foreground after reasoning.
        self.client.call.side_effect = [page_result(PAGE), page_result({**PAGE, "page_id": "page-b", "revision": 8})]
        self.client.request = AsyncMock(return_value={"tools": []})
        self.backend.stream_response = AsyncMock(side_effect=AssertionError("A stale page must never reach planning"))
        await self.process_capture()
        self.assertEqual(self.client.call.await_count, 2)
        self.client.request.assert_awaited_once_with("tools/list")
        self.backend.stream_response.assert_not_called()
        self.assertIn("No ink was added", self.manager._last_response)
        self.lesson.assert_awaited_once()

    async def test_step_narration_order_then_verified_completion_skips_full_repeat(self):
        async def write(*args, on_event, **kwargs):
            self.events.append("teacher-start")
            await on_event({"type": "step", "narration": "First row."})
            self.events.append("first-finished")
            await on_event({"type": "step", "narration": "Second row."})
            await on_event({"type": "verification", "complete": True})
            return "The explanation is verified."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.assertEqual(self.events[3:], ["teacher-start", ("speak", "First row."), "first-finished", ("speak", "Second row."), ("speak", "The explanation is verified.")])
        self.lesson.assert_not_awaited()
        self.assertIn(ANSWER, self.manager._last_response)

    async def test_incomplete_verification_keeps_full_lesson_after_step_narration(self):
        async def write(*args, on_event, **kwargs):
            await on_event({"type": "step", "narration": "First row."})
            await on_event({"type": "verification", "complete": False})
            return "Only the first step was added."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.speak.assert_awaited_once()
        self.lesson.assert_awaited_once()
        self.assertEqual(self.lesson.call_args.args[0], ANSWER)
        self.assertIn("Only the first step", self.lesson.call_args.args[1])

    async def test_complete_verification_without_successful_narration_keeps_fallback(self):
        self.speak.side_effect = None
        self.speak.return_value = False
        async def write(*args, on_event, **kwargs):
            await on_event({"type": "step", "narration": "First row."})
            await on_event({"type": "verification", "complete": True})
            return "Notebook verified; narration unavailable."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.lesson.assert_awaited_once()

    async def test_one_failed_step_keeps_full_fallback_despite_other_spoken_steps(self):
        # A later successful step must not erase an earlier speech failure.
        self.speak.side_effect = [True, False, True]
        async def write(*args, on_event, **kwargs):
            for narration in ("First row.", "Second row.", "Check the result."):
                await on_event({"type": "step", "narration": narration})
            await on_event({"type": "verification", "complete": True})
            return "All notebook steps verified."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.assertEqual(self.speak.await_count, 3)
        self.lesson.assert_awaited_once()
        self.assertEqual(self.lesson.call_args.args[0], ANSWER)


if __name__ == "__main__":
    unittest.main()
