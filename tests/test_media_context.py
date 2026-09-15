import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import companion_manager as manager_module
from ai.response_selection import ProviderIdentity, ResponseDispatch, ResponseSelection
from automation.media_context import MAX_TEMPORAL_FRAMES, build_media_context
from companion_manager import CompanionManager
from turn_coordinator import TurnCoordinator


class MediaContextSelectionTests(unittest.TestCase):
    def test_static_notebook_question_prefers_the_relevant_crop(self):
        context = build_media_context(
            "What does this row vector mean in my notebook?",
            current_screenshots_b64=("other-monitor", "notebook-screen"),
            active_screenshot_b64="notebook-screen",
            relevant_crop_b64="notebook-vector-crop",
            timeline_frames=((0.0, "first"), (8.0, "last")),
            video_available=True,
        )

        self.assertEqual(context.mode, "static")
        self.assertFalse(context.include_video)
        self.assertEqual(context.screenshots_b64, ("notebook-vector-crop",))
        self.assertEqual(context.timeline_frames, ())

    def test_temporal_question_uses_bounded_ordered_interval_frames(self):
        frames = tuple((float(second), f"frame-{second}") for second in range(8))
        context = build_media_context(
            "What changed after I moved to the next page?",
            current_screenshots_b64=("current",),
            active_screenshot_b64="current",
            timeline_frames=frames,
            video_available=True,
        )

        self.assertEqual(context.mode, "temporal")
        self.assertFalse(context.include_video)
        self.assertEqual(context.screenshots_b64, ())
        self.assertEqual(len(context.timeline_frames), MAX_TEMPORAL_FRAMES)
        self.assertEqual(
            [seconds for seconds, _ in context.timeline_frames], [0.0, 2.0, 5.0, 7.0]
        )

    def test_english_recall_of_a_complete_held_movement_uses_interval_frames(self):
        frames = tuple((float(second), f"frame-{second}") for second in range(8))
        context = build_media_context(
            "What did I do while I held and moved the diagram?",
            active_screenshot_b64="current",
            timeline_frames=frames,
            video_available=True,
        )

        self.assertEqual(context.mode, "temporal")
        self.assertFalse(context.include_video)
        self.assertEqual(context.screenshots_b64, ())
        self.assertEqual(
            [seconds for seconds, _ in context.timeline_frames], [0.0, 2.0, 5.0, 7.0]
        )

    def test_recall_phrases_cover_english_and_spanish(self):
        for request in (
            "What was I doing?",
            "Walk me through what I did.",
            "How did I get here?",
            "¿Qué estaba haciendo?",
        ):
            with self.subTest(request=request):
                context = build_media_context(
                    request,
                    active_screenshot_b64="current",
                    timeline_frames=((0.0, "first"), (8.0, "last")),
                    video_available=True,
                )
                self.assertEqual(context.mode, "temporal")
                self.assertFalse(context.include_video)
                self.assertEqual(context.timeline_frames, ((0.0, "first"), (8.0, "last")))

    def test_next_math_step_stays_static(self):
        context = build_media_context(
            "Explain the next step of this equation.",
            active_screenshot_b64="equation-screen",
            timeline_frames=((0.0, "first"), (8.0, "last")),
            video_available=True,
        )

        self.assertEqual(context.mode, "static")
        self.assertEqual(context.screenshots_b64, ("equation-screen",))
        self.assertEqual(context.timeline_frames, ())

    def test_explicit_motion_uses_video_without_extracted_frames(self):
        context = build_media_context(
            "Watch the cursor movement while I drag the diagram.",
            active_screenshot_b64="current",
            timeline_frames=((0.0, "first"), (5.0, "last")),
            video_available=True,
        )

        self.assertEqual(context.mode, "motion")
        self.assertTrue(context.include_video)
        self.assertEqual(context.screenshots_b64, ("current",))
        self.assertEqual(context.timeline_frames, ())

    def test_video_metadata_question_does_not_force_motion_upload(self):
        context = build_media_context(
            "What title am I watching?",
            active_screenshot_b64="current",
            timeline_frames=((0.0, "first"), (5.0, "last")),
            video_available=True,
        )

        self.assertEqual(context.mode, "static")
        self.assertFalse(context.include_video)
        self.assertEqual(context.timeline_frames, ())

    def test_motion_request_without_video_falls_back_to_ordered_frames(self):
        context = build_media_context(
            "Describe the cursor movement while I drag the diagram.",
            active_screenshot_b64="current",
            timeline_frames=((0.0, "first"), (4.0, "middle"), (8.0, "last")),
            video_available=False,
        )

        self.assertEqual(context.mode, "temporal")
        self.assertFalse(context.include_video)
        self.assertEqual(context.screenshots_b64, ())
        self.assertEqual([seconds for seconds, _ in context.timeline_frames], [0.0, 4.0, 8.0])

    def test_spanish_temporal_request_keeps_ordered_frames_and_rejects_nonfinite_time(self):
        context = build_media_context(
            "¿Qué hice antes y después de arrastrar la figura?",
            active_screenshot_b64="current",
            timeline_frames=((0.0, "first"), (float("inf"), "invalid"), (8.0, "last")),
            video_available=False,
        )

        self.assertEqual(context.mode, "temporal")
        self.assertEqual(context.timeline_frames, ((0.0, "first"), (8.0, "last")))


class _StreamingHost:
    _stream_tutor_response = CompanionManager._stream_tutor_response

    def __init__(self, backend):
        self._turns = TurnCoordinator()
        self.session = self._turns.start_processing()
        selection = ResponseSelection(
            ProviderIdentity("openrouter", "synthetic"),
            "meta/muse-spark-1.3-contributor", 1,
        )
        self._dispatch = ResponseDispatch(selection, backend)
        self._tutor_video_captures = {
            self.session.sequence: SimpleNamespace(
                selection=selection,
                recorder=SimpleNamespace(require_sharing_allowed=lambda: None),
            )
        }
        self.sig_response_chunk = Mock()

    def _acquire_response_dispatch(self, selection):
        return self._dispatch

    def _video_sharing_allowed(self):
        return True

    def _emit_turn_signal(self, session, signal, value):
        signal(value)


class ProductionAssemblyTests(unittest.IsolatedAsyncioTestCase):
    async def test_frame_only_context_reaches_the_production_provider_call(self):
        received = []

        async def stream_multimodal_response(**kwargs):
            received.append(kwargs)
            yield "The page changed after the navigation."

        host = _StreamingHost(SimpleNamespace(
            stream_multimodal_response=stream_multimodal_response,
        ))
        context = build_media_context(
            "What changed after I navigated to the next page?",
            active_screenshot_b64="current-screen",
            timeline_frames=tuple((float(i), f"frame-{i}") for i in range(8)),
            video_available=True,
        )
        with patch.object(manager_module.cfg, "openrouter_voice_video_enabled", True, create=True):
            response, overflow = await host._stream_tutor_response(
                "What changed after I navigated to the next page?",
                list(context.screenshots_b64), [], "Tutor", host.session, False,
                video=None,
                audio_b64="audio-from-the-original-turn",
                timeline_frames=list(context.timeline_frames),
            )

        self.assertFalse(overflow)
        self.assertEqual(response, "The page changed after the navigation.")
        self.assertEqual(len(received), 1)
        request = received[0]
        self.assertIsNone(request["video"])
        self.assertEqual(request["audio_b64"], "audio-from-the-original-turn")
        self.assertEqual(request["screenshots_b64"], [])
        self.assertEqual(
            request["timeline_frames"], list(context.timeline_frames)
        )
        self.assertIn("ordered timestamped history frames", request["system_prompt"])


if __name__ == "__main__":
    unittest.main()
