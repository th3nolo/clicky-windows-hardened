"""Original hotkey/manager multimodal path; synthetic media, no device/network."""

import asyncio
import base64
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication
_QT_APP = QApplication.instance() or QApplication([])
import companion_manager as module
from ai.base_provider import Message
from ai.response_selection import ProviderIdentity, ResponseDispatch, ResponseSelection
from tests import test_companion_barge_in as lifecycle
from tests.test_video_input import sample_clip
from screen.voice_clip import encode_clip


MODEL = "meta/muse-spark-1.3-contributor"


class OriginalVoiceVideoTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        lifecycle.CompanionBargeInTests.setUp(self)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.selection = ResponseSelection(ProviderIdentity("openrouter", "https://openrouter.ai/api/v1"), MODEL, 1)
        for name, value in (("openrouter_voice_video_enabled", True), ("openrouter_api_key", "synthetic-key"), ("openrouter_private_routing", False)):
            self.stack.enter_context(patch.object(module.cfg, name, value, create=True))
        self.stack.enter_context(patch.object(module.cfg, "stt_provider", return_value="openrouter"))
        self.stack.enter_context(patch.object(module, "cloud_stt_allowed", return_value=True))
        self.stack.enter_context(patch.object(self.manager, "_video_sharing_allowed", return_value=True))
        self.stack.enter_context(patch.object(self.manager, "_response_selection", return_value=self.selection))
        self.stack.enter_context(patch.object(self.manager, "_new_streaming_stt", return_value=None))
        self.recorder = MagicMock()
        self.recorder.timeline_frames.return_value = sample_clip()[0]
        self.recorder.transcription_pcm.return_value = b"\x01\x00" * 3200
        self.stack.enter_context(patch.object(module, "VoiceClipRecorder", return_value=self.recorder))
        self.manager._listener = MagicMock()
        self.manager._listener.start_recording.return_value = True
        self.manager._listener.stop_recording.return_value = b"\x01\x00" * 3200
        self.manager._current_model = MODEL

    def tearDown(self):
        lifecycle.CompanionBargeInTests.tearDown(self)

    async def test_normal_hotkey_capture_attaches_timed_audio_and_stop_cancels_video(self):
        self.manager.on_hotkey_press()
        session = self.manager._turns.active
        self.recorder.start.assert_called_once()
        self.assertEqual(self.manager._listener.start_recording.call_args.kwargs["on_timed_frame"], self.recorder.add_audio)
        self.assertIn(session.sequence, self.manager._tutor_video_captures)
        self.manager.stop()
        self.recorder.cancel.assert_called()
        self.assertEqual(self.manager._tutor_video_captures, {})

    async def test_original_end_capture_preserves_history_parser_and_lesson_output(self):
        video = encode_clip(*sample_clip(), lambda: False)
        self.recorder.finish.return_value = video
        transcript = "Explain this calculation"
        prior = Message("assistant", "Previous context")
        self.manager._app_memory[module.app_key("Synthetic notebook")] = [prior]
        self.manager._web_search_enabled = False
        self.manager._multilang = False
        self.manager._code_mode_auto = False
        self.manager._journal_enabled = False
        forwarded = []
        async def multimodal(**kwargs):
            forwarded.append(kwargs)
            yield "The first step is correct."
        backend = SimpleNamespace(stream_multimodal_response=multimodal)
        dispatch = ResponseDispatch(self.selection, backend)
        transcripts = []
        self.manager.sig_transcript_final.connect(lambda seq, text: transcripts.append(text), type=Qt.ConnectionType.DirectConnection)
        with patch.object(self.manager, "_transcribe_with_configured_fallback", AsyncMock(return_value=(transcript,"openrouter"))), patch.object(self.manager, "_acquire_response_dispatch", return_value=dispatch), patch.object(self.manager, "_handle_voice_command", AsyncMock(return_value=False)), patch.object(module.skills_pkg,"match",return_value=None), patch.object(module,"active_window_title",return_value="Synthetic notebook"), patch.object(module,"capture_all_screens",return_value=[]), patch("audio.stt.openrouter_stt._pcm16_to_mp3",return_value=b"mp3 audio"), patch.object(self.manager,"_parse_points") as parse, patch.object(self.manager,"_play_lesson",AsyncMock()) as lesson:
            self.manager.on_hotkey_press()
            session = self.manager._turns.active
            self.manager._turns.release_capture(session)
            await self.manager._end_capture_and_process(session)
        self.assertEqual(transcripts,[transcript])
        self.assertEqual(len(forwarded),1)
        self.assertEqual(forwarded[0]["user_text"],transcript)
        self.assertEqual(forwarded[0]["model"],MODEL)
        self.assertIs(forwarded[0]["video"],video)
        self.assertEqual(base64.b64decode(forwarded[0]["audio_b64"]),b"mp3 audio")
        self.assertIs(forwarded[0]["history"][0],prior)
        self.assertEqual(len(forwarded[0]["timeline_frames"]), 3)
        self.assertEqual(forwarded[0]["timeline_frames"][0][0], 0.0)
        self.assertIn("Muse 1.2 only transcribed",forwarded[0]["system_prompt"])
        parse.assert_not_called()  # Playback owns pointing; streaming must not jump ahead.
        lesson.assert_awaited_once()
        self.assertEqual(self.manager._tutor_video_captures,{})

    async def test_incompatible_selected_model_blocks_microphone_and_video(self):
        wrong = ResponseSelection(self.selection.identity,"other-model",2)
        with patch.object(self.manager,"_response_selection",return_value=wrong):
            self.manager.on_hotkey_press()
        self.recorder.start.assert_not_called()
        self.manager._listener.start_recording.assert_not_called()

    async def test_real_timed_microphone_audio_reaches_transcription(self):
        import time
        import numpy as np
        from audio.ambient_listener import AmbientListener
        from screen.voice_clip import VoiceClipRecorder
        recorder = VoiceClipRecorder(lambda: True)
        listener = AmbientListener(lambda level: None, lambda: None)
        listener._running = True
        self.manager._listener = listener
        speech = np.full((480, 1), 1000, dtype=np.int16)
        transcribe = AsyncMock(return_value=("", "openrouter"))
        # Only screen/device/network boundaries are replaced. Audio ownership,
        # real callback, seal, manager release and STT input remain integrated.
        with patch.object(module, "VoiceClipRecorder", return_value=recorder), \
                patch.object(recorder, "start"), \
                patch.object(self.manager, "_transcribe_with_configured_fallback", transcribe):
            self.manager.on_hotkey_press()
            session = self.manager._turns.active
            recorder._started = time.monotonic() - 1
            for _ in range(8):
                listener._callback(speech, len(speech), None, None)
            self.assertEqual(listener._rec_buffer, [])
            self.manager._turns.release_capture(session)
            await self.manager._end_capture_and_process(session)
        transcribe.assert_awaited_once_with(speech.tobytes() * 8, session)
        self.assertEqual(self.manager._tutor_video_captures, {})
        self.assertEqual(recorder._audio, [])

    async def test_transcription_failure_has_no_local_fallback_in_multimodal_turn(self):
        self.manager.on_hotkey_press()
        session = self.manager._turns.active
        with patch.object(self.manager,"_get_stt",return_value=SimpleNamespace(transcribe=AsyncMock(side_effect=RuntimeError("failure")))), patch.object(self.manager,"_get_fallback_stt") as fallback:
            with self.assertRaisesRegex(RuntimeError,"no fallback"):
                await self.manager._transcribe_with_configured_fallback(b"pcm",session)
        fallback.assert_not_called()

    async def test_media_encoding_failure_keeps_completed_transcript_visible(self):
        self.recorder.finish.side_effect = RuntimeError("private-provider-detail")
        transcripts, errors = [], []
        self.manager.sig_transcript_final.connect(lambda seq,text: transcripts.append(text),type=Qt.ConnectionType.DirectConnection)
        self.manager.sig_error.connect(errors.append,type=Qt.ConnectionType.DirectConnection)
        with patch.object(self.manager,"_transcribe_with_configured_fallback",AsyncMock(return_value=("Check my equation","openrouter"))):
            self.manager.on_hotkey_press()
            session = self.manager._turns.active
            self.manager._turns.release_capture(session)
            await self.manager._end_capture_and_process(session)
        self.assertEqual(transcripts,["Check my equation"])
        self.assertEqual(len(errors),1)
        self.assertNotIn("private-provider-detail",errors[0])
        self.assertEqual(self.manager._tutor_video_captures,{})

    async def test_missing_pcm_finishes_capture_and_cancels_video(self):
        self.manager._listener.stop_recording.return_value = None
        self.manager.on_hotkey_press()
        session = self.manager._turns.active
        self.manager._turns.release_capture(session)
        await self.manager._end_capture_and_process(session)
        self.assertEqual(self.manager._tutor_video_captures,{})
        self.assertIsNone(self.manager._turns.active)

    async def test_failed_transcription_releases_turn_for_next_request(self):
        errors = []
        self.manager.sig_error.connect(errors.append, type=Qt.ConnectionType.DirectConnection)
        transcribe = AsyncMock(side_effect=[RuntimeError("private-provider-detail"), ("", "openrouter")])
        with patch.object(self.manager, "_transcribe_with_configured_fallback", transcribe):
            for _ in range(2):
                self.manager.on_hotkey_press()
                session = self.manager._turns.active
                self.assertIsNotNone(session)
                self.manager._turns.release_capture(session)
                await self.manager._end_capture_and_process(session)
                self.assertIsNone(self.manager._turns.active)
                self.assertEqual(self.manager._tutor_video_captures, {})
        self.assertEqual(transcribe.await_count, 2)
        self.assertIn("Speech transcription failed", errors[0])
        self.assertIn("retry now", errors[0])
        self.assertNotIn("private-provider-detail", errors[0])

    async def test_narration_response_is_bounded(self):
        async def stream(**kwargs):
            yield "x" * (64*1024+1)
        dispatch = ResponseDispatch(self.selection,SimpleNamespace(stream_response=stream))
        session = self.manager._turns.start_processing()
        with patch.object(self.manager,"_acquire_response_dispatch",return_value=dispatch):
            with self.assertRaisesRegex(RuntimeError,"bounded narration"):
                await self.manager._stream_tutor_response("question",[],[],"Tutor",session,False,selection=self.selection)

    async def test_point_tag_holds_real_overlay_until_turn_completion(self):
        from ui.overlay import CursorOverlay
        from PyQt6.QtGui import QCursor
        from PyQt6.QtCore import QPoint
        overlay = CursorOverlay()
        self.addCleanup(overlay.close)
        self.manager.sig_point_hold.connect(overlay.set_point_hold, type=Qt.ConnectionType.DirectConnection)
        self.manager.sig_point_at.connect(overlay.point_at, type=Qt.ConnectionType.DirectConnection)
        self.manager.sig_point_release.connect(overlay.release_point, type=Qt.ConnectionType.DirectConnection)
        session = self.manager._turns.start_processing()
        with patch.object(self.manager, "_denorm", return_value=(500, 130)), \
                patch.object(QCursor, "pos", return_value=QPoint(10,10)), \
                patch.object(QCursor, "setPos") as move_mouse:
            self.manager._parse_points('[POINT:781,271:Plus:screen1]', session)
            self.assertTrue(overlay._hold_dwell)
            with patch('ui.overlay.time.monotonic', return_value=overlay._fly_t0 + 100):
                overlay._tick()
                overlay._tick()
            self.assertEqual((overlay._display_pos.x(), overlay._display_pos.y()), (500, 130))
            self.manager._finish_turn(session)
            self.assertFalse(overlay._hold_dwell)
            move_mouse.assert_not_called()

    async def test_normal_tutor_does_not_draw_screen_annotations(self):
        drawings = []
        self.manager.sig_draw.connect(drawings.append, type=Qt.ConnectionType.DirectConnection)
        session = self.manager._turns.start_processing()
        with patch.object(self.manager, '_speak_with_failure_fallback', AsyncMock()) as speak:
            await self.manager._play_lesson('One [CIRCLE:100,100,40:one].', 'One.', session)
        self.assertEqual(drawings, [])
        speak.assert_awaited_once_with('One.', session)
        self.manager._finish_turn(session)

    async def test_repeated_points_follow_spoken_passages_and_stop_on_cancel(self):
        events = []
        session = self.manager._turns.start_processing()
        self.manager.sig_point_at.connect(lambda x, y, label: events.append(label), type=Qt.ConnectionType.DirectConnection)
        async def speak(text, current):
            events.append(text)
            if text == 'Second column.':
                self.manager._finish_turn(current)
            return True
        response = '[POINT:100,100:first:screen1]First column.[POINT:200,200:second:screen1]Second column.[POINT:300,300:third:screen1]Third column.'
        with patch.object(self.manager, '_denorm', return_value=(100, 100)), patch.object(self.manager, '_speak_with_failure_fallback', side_effect=speak):
            await self.manager._play_lesson(response, 'unused', session)
        self.assertEqual(events, ['first', 'First column.', 'second', 'Second column.'])

    async def test_voice_note_routes_generated_answer_to_insertion(self):
        mcp_write = self.stack.enter_context(patch('automation.inknotes_mcp.write_explanation', AsyncMock(return_value='Handwriting saved.')))
        self.stack.enter_context(patch('automation.inknotes_mcp.foreground_notebook_pid', return_value=12345))
        self.recorder.finish.return_value = encode_clip(*sample_clip(), lambda: False)
        self.manager._web_search_enabled = False
        self.manager._multilang = False
        self.manager._code_mode_auto = False
        self.manager._journal_enabled = False
        answer = 'First: 1+4+18=23. Second: 2+8+24=34. Third: 3+10+27=40. Result: [23,34,40].'
        async def stream(**kwargs):
            self.assertIn('NOTE REQUEST', kwargs['system_prompt'])
            yield answer
        dispatch = ResponseDispatch(self.selection, SimpleNamespace(stream_multimodal_response=stream))
        with patch.object(self.manager, '_transcribe_with_configured_fallback', AsyncMock(return_value=('Write the complete explanation here', 'openrouter'))), patch.object(self.manager, '_acquire_response_dispatch', return_value=dispatch), patch.object(self.manager, '_handle_voice_command', AsyncMock(return_value=False)), patch.object(module.skills_pkg, 'match', return_value=None), patch.object(module, 'active_window_title', return_value='Synthetic notebook'), patch.object(module, 'capture_all_screens', return_value=[]), patch('audio.stt.openrouter_stt._pcm16_to_mp3', return_value=b'mp3'), patch.object(self.manager._tutor_notes, 'write', return_value='Insertion attempted.') as insert, patch.object(self.manager, '_play_lesson', AsyncMock()):
            self.manager.on_hotkey_press()
            session = self.manager._turns.active
            self.manager._turns.release_capture(session)
            await self.manager._end_capture_and_process(session)
        insert.assert_not_called()  # The obsolete prepared-text-box path is disabled.
        mcp_write.assert_awaited_once()
        self.assertEqual(mcp_write.call_args.args[4], answer)
        self.assertIsNone(self.manager._turns.active)
