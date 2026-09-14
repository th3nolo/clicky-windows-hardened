"""Behavior checks for the manager's extracted local and streaming phases."""

import asyncio
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

import companion_manager as manager_module
from companion_manager import CompanionManager
from screen.capture import ScreenShot
from turn_coordinator import TurnCoordinator
from tutor import VoiceCommand
from ai.response_selection import ProviderIdentity, ResponseDispatch, ResponseSelection


class TutorRoutingTests(unittest.IsolatedAsyncioTestCase):
    def local_host(self):
        return types.SimpleNamespace(
            _walkthrough=Mock(active=False), _lesson_steps=[], _last_response="",
            _turns=TurnCoordinator(), _advance_walkthrough=AsyncMock(),
            _advance_lesson_step=AsyncMock(), _reply_local=AsyncMock(),
            _spaced_review=AsyncMock(), _emit_turn_signal=Mock(), _emit_state=Mock(),
            _speak_with_failure_fallback=AsyncMock(), sig_response_chunk=object(),
            sig_response_done=object(),
        )

    async def test_next_prefers_active_walkthrough_over_text_lesson(self):
        host = self.local_host()
        host._walkthrough.active = True
        host._lesson_steps = ["text lesson"]
        session = host._turns.start_processing()
        handled = await CompanionManager._handle_voice_command(host, VoiceCommand.NEXT, "app", session)
        self.assertTrue(handled)
        host._advance_walkthrough.assert_awaited_once_with(session, from_voice=True)
        host._advance_lesson_step.assert_not_awaited()

    async def test_repeat_needs_history_and_new_question_cancels_walkthrough(self):
        host = self.local_host()
        session = host._turns.start_processing()
        self.assertFalse(await CompanionManager._handle_voice_command(host, VoiceCommand.REPEAT, "app", session))
        host._last_response = "previous explanation"
        self.assertTrue(await CompanionManager._handle_voice_command(host, VoiceCommand.REPEAT, "app", session))
        host._speak_with_failure_fallback.assert_awaited_once_with("previous explanation", session)
        host._walkthrough.active = True
        self.assertFalse(await CompanionManager._handle_voice_command(host, None, "app", session))
        host._walkthrough.cancel.assert_called_once_with("turn_superseded")

    def stream_host(self, generator):
        turns = TurnCoordinator()
        return types.SimpleNamespace(
            _acquire_response_dispatch=lambda *_: ResponseDispatch(
                ResponseSelection(ProviderIdentity("openai", "synthetic"), "selected", 1),
                types.SimpleNamespace(stream_response=generator),
            ),
            _turns=turns, _current_model="selected", _parse_points=Mock(),
            _emit_turn_signal=Mock(), sig_response_chunk=object(),
        ), turns.start_processing()

    async def test_stream_hides_split_markup_and_preserves_full_response(self):
        async def response(**_request):
            for chunk in ("Look [PO", "INT:1,2]here", "."):
                yield chunk
        host, session = self.stream_host(response)
        result = await CompanionManager._stream_tutor_response(host, "question", [], [], "system", session, False)
        self.assertEqual(result, ("Look [POINT:1,2]here.", False))
        visible = "".join(call.args[2] for call in host._emit_turn_signal.call_args_list)
        self.assertEqual(visible, "Look here.")
        host._parse_points.assert_called()

    async def test_stale_stream_closes_without_emitting_or_completing(self):
        closed = asyncio.Event()
        async def response(**_request):
            try:
                yield "stale"
            finally:
                closed.set()
        host, session = self.stream_host(response)
        host._turns.cancel(session)
        self.assertEqual(await CompanionManager._stream_tutor_response(host, "q", [], [], "s", session, False), ("", False))
        host._emit_turn_signal.assert_not_called()
        self.assertTrue(closed.is_set())

    async def test_walkthrough_overflow_is_not_displayed_as_narration(self):
        async def response(**_request):
            yield "abcdef"
        host, session = self.stream_host(response)
        with patch.object(manager_module, "MAX_PAYLOAD_BYTES", 5):
            result = await CompanionManager._stream_tutor_response(host, "q", [], [], "s", session, True)
        self.assertEqual(result, ("", True))
        host._emit_turn_signal.assert_not_called()
        host._parse_points.assert_not_called()

    async def test_local_locator_returns_logical_coordinates_without_remote_call(self):
        host = self.local_host()
        host._get_llm = Mock()
        session = host._turns.start_processing()
        shot = ScreenShot(
            index=2, width=1280, height=720, base64_jpeg="image",
            physical_width=1920, physical_height=1080,
            physical_left=-1920, physical_top=0, dpi_scale=1.5,
            logical_left=-1280, logical_top=0,
        )
        local = types.ModuleType("ai.hybrid_pointer")
        local.find_target = Mock(return_value=types.SimpleNamespace(
            source="uia", x=-640, y=360,
        ))
        remote = types.ModuleType("ai.element_locator")
        remote.detect_element = AsyncMock()
        with patch.dict("sys.modules", {
            "ai.hybrid_pointer": local, "ai.element_locator": remote,
        }), patch.object(manager_module.cfg, "anthropic_api_key", "configured"):
            result = await CompanionManager._locate_question_target(
                host, "where is save", shot, session,
            )
        self.assertEqual(result, (-640.0, 360.0))
        local.find_target.assert_called_once_with(
            "where is save", screenshot=shot,
            llm_provider=host._get_llm.return_value, skip_vision=True,
        )
        remote.detect_element.assert_not_awaited()
