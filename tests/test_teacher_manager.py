"""Real manager release/teacher orchestration; fake device, provider and MCP IO."""

import json
import asyncio
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
    def test_control_metadata_preserves_verification_flags_without_source_payload(self):
        event = module._notebook_event_metadata({
            "type": "verification", "complete": True,
            "independent_output_reader": True, "structural_readback": True,
            "model_visual_assessment": False, "image": "private-source",
        })
        self.assertEqual(event, {
            "type": "verification", "complete": True,
            "independent_output_reader": True, "structural_readback": True,
            "model_visual_assessment": False,
        })
        normalized = module._notebook_event_metadata({
            "type": "command_normalized", "tool": "inknotes_draw_curves",
            "component_id": "row-example", "paths": [{"private": True}],
        })
        self.assertNotIn("paths", normalized)
        self.assertEqual(normalized["type"], "command_normalized")

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
        self.lesson.assert_not_awaited()
        self.speak.assert_not_awaited()

    async def test_typed_notebook_task_reuses_native_planner_without_microphone_or_screen_capture(self):
        request = "On a new blank page DRAW a native curved A."
        events = []
        self.manager.sig_notebook_event.connect(
            lambda sequence, event: events.append((sequence, event)),
            type=Qt.ConnectionType.DirectConnection,
        )
        transcribe = AsyncMock(side_effect=AssertionError("typed task must not transcribe"))
        self.manager._transcribe_with_configured_fallback = transcribe

        async def write(*args, on_event, **kwargs):
            await on_event({
                "type": "source_image_checkpoint",
                "source_page_identity": PAGE,
                "target_page_identity": PAGE,
                "source_image_seed": [{"image": "must-not-leak"}],
            })
            await on_event({"type": "step", "tool": "inknotes_draw_curves",
                            "annotation_id": "native-a", "narration": "Letter A drawn."})
            await on_event({"type": "verification", "complete": False})
            return "The letter was added but completion was not verified."

        writer = self.stack.enter_context(
            patch.object(inknotes_mcp, "write_explanation", side_effect=write)
        )
        with patch.object(module, "screen_capture_allowed", return_value=True), \
                patch.object(module, "capture_all_screens", side_effect=AssertionError("typed task must not capture desktop screens")):
            task_id = self.manager.submit_notebook_task(request, 12345)
            self.assertIsInstance(task_id, int)
            self.assertEqual(
                self.manager.submit_notebook_task(request, 12345),
                "A Clicky task is already active.",
            )
            deadline = asyncio.get_running_loop().time() + 2
            while self.manager._turns.active is not None and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.01)

        self.assertIsNone(self.manager._turns.active)
        self.assertEqual(self.manager._listener.stop_recording.call_count, 0)
        transcribe.assert_not_awaited()
        writer.assert_awaited_once()
        self.assertEqual(writer.call_args.kwargs["expected_page"], PAGE)
        self.assertEqual(writer.call_args.args[3], request)
        self.assertTrue(any(event["type"] == "task_started" for _, event in events))
        self.assertTrue(any(event["type"] == "step" for _, event in events))
        source = next(event for _, event in events if event["type"] == "source_checkpoint")
        self.assertEqual(source["source_page_identity"], PAGE)
        self.assertEqual(source["reference_count"], 1)
        self.assertNotIn("source_image_seed", source)

    async def test_typed_notebook_task_stop_cancels_and_a_later_submission_can_start(self):
        started = asyncio.Event()

        async def pending(*args, **kwargs):
            started.set()
            await asyncio.sleep(30)

        with patch.object(module, "screen_capture_allowed", return_value=True), \
                patch.object(self.manager, "_end_capture_and_process", side_effect=pending):
            first = self.manager.submit_notebook_task("Draw a native label.", 12345)
            self.assertIsInstance(first, int)
            deadline = asyncio.get_running_loop().time() + 2
            while not started.is_set() and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.01)
            self.assertTrue(started.is_set())
            self.assertEqual(
                self.manager.submit_notebook_task("Draw another native label.", 12345),
                "A Clicky task is already active.",
            )
            self.manager.stop()
            deadline = asyncio.get_running_loop().time() + 2
            while self.manager._turns.active is not None and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.01)
            self.assertIsNone(self.manager._turns.active)
            second = self.manager.submit_notebook_task("Draw another native label.", 12345)
            self.assertIsInstance(second, int)
            self.manager.stop()

    async def test_explicit_native_redraw_bypasses_prose_draft_and_enters_planner(self):
        request = "Draw handwritten letters as native pen traces on a new page and redraw the whole scene."
        self.manager._transcribe_with_configured_fallback = AsyncMock(
            return_value=(request, "openrouter"),
        )
        self.stack.enter_context(patch.object(
            self.manager, "_stream_tutor_response",
            AsyncMock(side_effect=AssertionError("explicit native redraw must not request a prose draft")),
        ))
        writer = self.stack.enter_context(patch.object(
            inknotes_mcp, "write_explanation",
            AsyncMock(return_value="Native redraw started; the first visible ink batch was requested."),
        ))
        chunks, completed = [], []
        self.manager.sig_response_chunk.connect(chunks.append, type=Qt.ConnectionType.DirectConnection)
        self.manager.sig_response_done.connect(completed.append, type=Qt.ConnectionType.DirectConnection)

        await self.process_capture()

        writer.assert_awaited_once()
        self.assertEqual(writer.call_args.args[3], request)
        self.assertIn("Begin with the next required observation", writer.call_args.args[4])
        self.assertNotIn(ANSWER, completed[-1])
        self.assertEqual(completed[-1], "Native redraw started; the first visible ink batch was requested.")
        self.assertNotIn("Unconfirmed draft", "".join(chunks))
        self.assertIn("Preparing the requested native InkNotes redraw", "".join(chunks))

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
        self.lesson.assert_not_awaited()
        self.speak.assert_not_awaited()

    async def test_steps_stay_visible_and_only_verified_completion_is_spoken(self):
        assessment = "The final image shows the marked row vector and its direction."
        async def write(*args, on_event, **kwargs):
            self.events.append("teacher-start")
            await on_event({"type": "step", "narration": "First row."})
            self.events.append("first-finished")
            await on_event({"type": "step", "narration": "Second row."})
            await on_event({"type": "verification", "complete": True, "assessment": assessment})
            return "The explanation is verified."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        grounded = assessment + "\n\nThe explanation is verified."
        self.assertEqual(self.events[3:], ["teacher-start", "first-finished", ("speak", module._speakable(grounded))])
        self.assertEqual(self.speak.await_count, 1)
        self.lesson.assert_not_awaited()
        self.assertEqual(
            self.manager._last_response,
            assessment + "\n\nThe explanation is verified.",
        )
        self.assertNotIn(ANSWER, self.manager._last_response)

    async def test_verified_assessment_without_steps_does_not_replay_provisional_draft(self):
        assessment = "The final page shows the saved enclosure, arrow, and row vector label."
        status = "The notebook is saved and the explanation is verified."

        async def write(*args, on_event, **kwargs):
            await on_event({"type": "verification", "complete": True, "assessment": assessment})
            return status

        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()

        grounded = assessment + "\n\n" + status
        self.assertEqual(self.manager._last_response, grounded)
        history = self.manager._app_memory[module.app_key("Synthetic notebook")]
        self.assertEqual(history[-1].content, grounded)
        self.assertNotIn(ANSWER, self.manager._last_response)
        self.lesson.assert_not_awaited()
        self.assertEqual(
            [call.args[0] for call in self.speak.await_args_list],
            [module._speakable(grounded)],
        )

    async def test_partial_planner_run_keeps_truthful_status_visible_without_tts(self):
        states = []
        self.manager.sig_state_changed.connect(states.append, type=Qt.ConnectionType.DirectConnection)
        get_tts = self.stack.enter_context(patch.object(self.manager, "_get_tts"))
        async def write(*args, on_event, **kwargs):
            await on_event({"type": "step", "narration": "First row."})
            await on_event({"type": "verification", "complete": False})
            return "Only the first step was added."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.speak.assert_not_awaited()
        get_tts.assert_not_called()
        self.assertNotIn(module.AppState.SPEAKING, states)
        self.lesson.assert_not_awaited()
        self.assertEqual(self.manager._last_response, "Only the first step was added.")
        self.assertNotIn(ANSWER, self.manager._last_response)

    async def test_final_speech_failure_does_not_repeat_completed_steps(self):
        self.speak.side_effect = None
        self.speak.return_value = False
        async def write(*args, on_event, **kwargs):
            await on_event({"type": "step", "narration": "First row."})
            await on_event({"type": "verification", "complete": True,
                            "assessment": "The final page shows the completed annotation."})
            return "Notebook verified; narration unavailable."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.speak.assert_awaited_once()
        self.lesson.assert_not_awaited()

    async def test_many_step_callbacks_still_produce_one_final_speech(self):
        async def write(*args, on_event, **kwargs):
            for narration in ("First row.", "Second row.", "Check the result."):
                await on_event({"type": "step", "narration": narration})
            await on_event({"type": "verification", "complete": True,
                            "assessment": "The final page shows every completed notebook step."})
            return "All notebook steps verified."
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.assertEqual(self.speak.await_count, 1)
        self.assertEqual(self.speak.call_args.args[0], module._speakable(
            "The final page shows every completed notebook step.\n\nAll notebook steps verified."))
        self.lesson.assert_not_awaited()

    async def test_clarification_replaces_draft_and_speaks_only_question(self):
        question = "Is the lower symbol a three or an eight?"
        status = "Clicky needs clarification before continuing: " + question + " No ink was added."
        chunks, completed = [], []
        self.manager.sig_response_chunk.connect(chunks.append, type=Qt.ConnectionType.DirectConnection)
        self.manager.sig_response_done.connect(completed.append, type=Qt.ConnectionType.DirectConnection)
        self.manager._lesson_steps = ["Old unconfirmed calculation"]
        async def write(*args, on_event, **kwargs):
            await on_event({"type": "clarification", "question": question, "complete": False})
            return status
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.assertIn("Unconfirmed draft", chunks[0])
        self.assertEqual(completed[-1], status)
        self.assertNotIn(ANSWER, completed[-1])
        self.speak.assert_not_awaited()
        self.lesson.assert_not_awaited()
        self.assertEqual(self.manager._last_response, status)
        self.assertEqual(self.manager._lesson_steps, [])
        history = self.manager._app_memory[module.app_key("Synthetic notebook")]
        self.assertEqual(history[-1].content, status)

    async def test_clarification_after_partial_step_preserves_truthful_status(self):
        question = "Which row should the remaining arrow refer to?"
        status = "Clicky needs clarification before continuing: " + question + " Earlier completed ink remains on the page."
        async def write(*args, on_event, **kwargs):
            await on_event({"type": "step", "narration": "The first row is marked."})
            await on_event({"type": "clarification", "question": question, "complete": False})
            # Clarification is terminal for narration, even if an erroneous
            # later callback claims completion or supplies another step.
            await on_event({"type": "verification", "complete": True})
            await on_event({"type": "step", "narration": "Unconfirmed second row."})
            return status
        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()
        self.speak.assert_not_awaited()
        self.assertEqual(self.manager._last_response, status)
        self.lesson.assert_not_awaited()

    async def test_timeout_replaces_provisional_draft_and_speaks_only_status(self):
        timeout_status = (
            "Notebook teaching reached its time limit. Some ink may have been added; "
            "completion and saving were not verified."
        )
        completed = []
        self.manager.sig_response_done.connect(
            completed.append, type=Qt.ConnectionType.DirectConnection
        )
        self.manager._lesson_steps = ["Provisional next step"]

        async def write(*args, on_event, **kwargs):
            await on_event({"type": "step", "narration": "The first mark was completed."})
            return timeout_status

        self.stack.enter_context(
            patch.object(inknotes_mcp, "write_explanation", side_effect=write)
        )
        await self.process_capture()

        self.assertEqual(completed[-1], timeout_status)
        self.assertNotIn(ANSWER, completed[-1])
        self.speak.assert_not_awaited()
        self.lesson.assert_not_awaited()
        self.assertEqual(self.manager._last_response, timeout_status)
        self.assertEqual(self.manager._lesson_steps, [])
        history = self.manager._app_memory[module.app_key("Synthetic notebook")]
        self.assertEqual(history[-1].content, timeout_status)

    async def test_stale_planner_callback_never_speaks_a_step_or_final_status(self):
        async def write(*args, on_event, **kwargs):
            await on_event({"type": "step", "narration": "A mark was added."})
            self.manager._turns.cancel_active()
            await on_event({"type": "step", "narration": "This stale step is ignored."})
            return "A stale planner result must not be spoken."

        self.stack.enter_context(patch.object(inknotes_mcp, "write_explanation", side_effect=write))
        await self.process_capture()

        self.speak.assert_not_awaited()
        self.lesson.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
