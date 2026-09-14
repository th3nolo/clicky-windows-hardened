"""Exercise normal hotkey capture with synthetic speech configuration only."""

import asyncio
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import companion_manager as module
from companion_manager import CompanionManager
from audio.stt import readiness
from audio.stt.local_models import LocalModelUnavailable
from turn_coordinator import TurnCoordinator, TurnPhase
from tests.test_stt_readiness import _FallbackHarness, _STT


class CaptureHost:
    on_hotkey_press = CompanionManager.on_hotkey_press
    _begin_capture = CompanionManager._begin_capture
    _begin_dictation_capture = CompanionManager._begin_dictation_capture
    _pin_capture_stt = CompanionManager._pin_capture_stt
    _start_tutor_video = CompanionManager._start_tutor_video
    _cancel_tutor_video = CompanionManager._cancel_tutor_video
    _stt_selection_identity = staticmethod(CompanionManager._stt_selection_identity)

    def __init__(self):
        self._input_lock = threading.RLock()
        self._microphone_test_id = self._tts_preview_id = None
        self._realtime_controller = self._pressed_session = None
        self._turns = TurnCoordinator()
        self._capture_stt_identities = {}
        self._tutor_video_captures = {}
        self._streaming_stt = {}
        self._get_stt = mock.Mock()
        self._cancel_streaming_stt = mock.Mock()
        self._dictation = mock.Mock()
        self._tutor_notes = mock.Mock()
        self._inknotes_pids = {}
        self._listener = mock.Mock()
        self._listener.start_recording.return_value = True
        self._walkthrough = mock.Mock()
        self._new_streaming_stt = mock.Mock(return_value=None)
        self._task_followup_voice_armed = False
        self._cancel_outputs = mock.Mock()
        self._emit_state = mock.Mock()
        self._emit_turn_signal = mock.Mock()
        self.sig_error = mock.Mock()
        self.sig_dictation_error = mock.Mock()
        self.sig_transcript_begin = mock.Mock()
        self.sig_transcript_end = mock.Mock()

    def _finish_turn(self, session):
        self._turns.complete(session)


def configuration(provider='faster_whisper', fallback='', **updates):
    values = dict(
        stt_provider=lambda: provider,
        stt_fallback_provider=lambda: fallback,
        whisper_model_sha256='',
        whispercpp_model_sha256='',
        openrouter_api_key='synthetic-openrouter',
        openrouter_private_routing=False,
        openrouter_voice_video_enabled=False,
    )
    values.update(updates)
    return SimpleNamespace(**values)


class HotkeyPreflightTests(unittest.TestCase):
    def setUp(self):
        self.host = CaptureHost()
        for patch in (
            mock.patch.object(module, 'microphone_allowed', return_value=True),
            mock.patch.object(module, 'cloud_stt_allowed', return_value=True),
            mock.patch.object(readiness.importlib.util, 'find_spec', return_value=object()),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def test_openrouter_only_missing_model_identity_fails_before_recording(self):
        with mock.patch.object(module, 'cfg', configuration()):
            self.host.on_hotkey_press()
        self.host._listener.start_recording.assert_not_called()
        self.host._new_streaming_stt.assert_not_called()
        self.assertIsNone(self.host._turns.active)
        self.assertIsNone(self.host._pressed_session)
        self.host._emit_turn_signal.assert_called_once()
        message = self.host._emit_turn_signal.call_args.args[-1]
        self.assertIn('WHISPER_MODEL_SHA256', message)
        self.assertIn('Speech readiness & fallback', message)
        self.assertIn('OpenRouter Muse', message)
        self.assertIn('Ask with screen + voice', message)

    def test_ready_local_configuration_allows_one_recording(self):
        with mock.patch.object(module, 'cfg', configuration(whisper_model_sha256='a' * 64)):
            self.host.on_hotkey_press()
            self.host.on_hotkey_press()
        self.host._listener.start_recording.assert_called_once()
        self.assertEqual(self.host._turns.phase, TurnPhase.CAPTURING)
        self.host._emit_turn_signal.assert_not_called()

    def test_approved_configured_local_fallback_keeps_capture_available(self):
        cfg = configuration(fallback='whisper_cpp', whispercpp_model_sha256='a' * 64)
        with mock.patch.object(module, 'cfg', cfg):
            self.host.on_hotkey_press()
        self.host._listener.start_recording.assert_called_once()
        self.host._emit_turn_signal.assert_not_called()

    def test_all_cloud_modes_bypass_local_prerequisites(self):
        for provider in ('deepgram', 'deepgram_batch', 'openai', 'openrouter'):
            with self.subTest(provider=provider), mock.patch.object(module, 'cfg', configuration(provider)):
                host = CaptureHost()
                host.on_hotkey_press()
                host._listener.start_recording.assert_called_once()

    def test_cloud_consent_gate_remains_before_capture(self):
        with mock.patch.object(module, 'cfg', configuration('openai')), mock.patch.object(module, 'cloud_stt_allowed', return_value=False):
            self.host.on_hotkey_press()
        self.host._listener.start_recording.assert_not_called()
        self.assertIsNone(self.host._turns.active)

    def test_openrouter_missing_key_stops_before_capture(self):
        with mock.patch.object(module, 'cfg', configuration('openrouter', openrouter_api_key=None)):
            self.host.on_hotkey_press()
        self.host._listener.start_recording.assert_not_called()
        self.assertIn('OPENROUTER_API_KEY', self.host._emit_turn_signal.call_args.args[-1])

    def test_tutor_and_dictation_reject_provider_or_routing_change_during_capture(self):
        for dictation in (False, True):
            for attribute, value in (('stt_provider', lambda: 'faster_whisper'), ('openrouter_private_routing', True), ('openrouter_api_key', 'different')):
                with self.subTest(dictation=dictation, attribute=attribute), mock.patch.object(module, 'cfg', configuration('openrouter')) as cfg:
                    host = CaptureHost()
                    if dictation:
                        session = host._turns.start_capture()
                        self.assertTrue(host._begin_dictation_capture(SimpleNamespace(turn=session)))
                    else:
                        host.on_hotkey_press()
                        session = host._pressed_session
                    setattr(cfg, attribute, value)
                    with self.assertRaisesRegex(RuntimeError, 'changed during capture'):
                        asyncio.run(CompanionManager._transcribe_with_configured_fallback(host, b'pcm', session))
                    host._get_stt.assert_not_called()

    def test_stt_cache_is_bound_to_provider_key_and_routing(self):
        cfg = configuration('openrouter')
        host = SimpleNamespace(_stt=None, _stt_identity=None,
            _stt_selection_identity=CompanionManager._stt_selection_identity,
            _create_batch_stt=mock.Mock(side_effect=lambda provider: object()))
        with mock.patch.object(module, 'cfg', cfg):
            initial = CompanionManager._get_stt(host)
            self.assertIs(initial, CompanionManager._get_stt(host))
            cfg.openrouter_private_routing = True
            self.assertIsNot(initial, CompanionManager._get_stt(host))
            cfg.stt_provider = lambda: 'faster_whisper'
            local = CompanionManager._get_stt(host)
            self.assertIs(local, CompanionManager._get_stt(host))
        self.assertEqual(host._create_batch_stt.call_args_list,
            [mock.call('openrouter'), mock.call('openrouter'), mock.call('faster_whisper')])

    def test_empty_transcript_shows_retry_guidance_without_response_dispatch(self):
        host = CaptureHost()
        session = host._turns.start_capture()
        host._listener.stop_recording.return_value = bytes(6400)
        host._walkthrough.paused_for_voice = False
        host._transcribe_with_configured_fallback = mock.AsyncMock(return_value=('', 'openrouter'))
        host._consume_task_followup_voice_capture = mock.Mock(return_value=False)
        asyncio.run(CompanionManager._end_capture_and_process(host, session))
        self.assertIn('No intelligible speech', host._emit_turn_signal.call_args.args[-1])
        self.assertIsNone(host._turns.active)

    def test_dictation_start_failure_drops_captured_identity(self):
        host = CaptureHost()
        session = SimpleNamespace(turn=host._turns.start_capture())
        host._listener.start_recording.side_effect = RuntimeError('synthetic microphone failure')
        with mock.patch.object(module, 'cfg', configuration('openrouter')):
            self.assertFalse(host._begin_dictation_capture(session))
        self.assertEqual(host._capture_stt_identities, {})

    def test_dictation_short_or_failed_stop_drops_captured_identity(self):
        for failure in (False, True):
            with self.subTest(failure=failure), mock.patch.object(module, 'cfg', configuration('openrouter')):
                host = CaptureHost()
                session = SimpleNamespace(turn=host._turns.start_capture())
                self.assertTrue(host._begin_dictation_capture(session))
                if failure:
                    host._listener.stop_recording.side_effect = RuntimeError('synthetic stop failure')
                else:
                    host._listener.stop_recording.return_value = b'\0\0'
                asyncio.run(CompanionManager._end_dictation_capture(host, session))
                self.assertEqual(host._capture_stt_identities, {})


class LocalPreflightTests(unittest.TestCase):
    def test_missing_package_is_actionable(self):
        with mock.patch.object(readiness.importlib.util, 'find_spec', return_value=None):
            for provider in readiness.LOCAL_FALLBACK_PROVIDERS:
                self.assertIn('speech package is unavailable', readiness.local_stt_setup_issue(configuration(), provider))

    def test_each_local_provider_requires_its_own_digest(self):
        with mock.patch.object(readiness.importlib.util, 'find_spec', return_value=object()):
            self.assertIn('WHISPERCPP_MODEL_SHA256', readiness.local_stt_setup_issue(configuration(), 'whisper_cpp'))
            self.assertIn('WHISPER_MODEL_SHA256', readiness.local_stt_setup_issue(configuration(), 'faster_whisper'))

    def test_preflight_never_hashes_or_resolves_models(self):
        with mock.patch.object(readiness.importlib.util, 'find_spec', return_value=object()), mock.patch.object(readiness, 'resolve_faster_whisper_model') as faster, mock.patch.object(readiness, 'resolve_whisper_cpp_model') as cpp:
            cfg = configuration(whisper_model_sha256='a' * 64, whispercpp_model_sha256='b' * 64)
            for provider in readiness.STT_PROVIDER_DETAILS:
                self.assertEqual(readiness.local_stt_setup_issue(cfg, provider), '')
            faster.assert_not_called()
            cpp.assert_not_called()


class LocalFailureDetailTests(unittest.TestCase):
    def test_local_model_error_is_shown_after_runtime_validation(self):
        host = _FallbackHarness(_STT(error=LocalModelUnavailable('SHA-256 mismatch for synthetic model')), None)
        with mock.patch.object(module, 'cfg', configuration()):
            with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
                asyncio.run(CompanionManager._transcribe_with_configured_fallback(host, b'pcm', SimpleNamespace(sequence=1)))

    def test_cloud_exception_content_is_not_exposed_or_logged(self):
        host = _FallbackHarness(_STT(error=RuntimeError('synthetic-sensitive-provider-content')), None)
        with mock.patch.object(module, 'cfg', configuration('openai')), self.assertLogs('clicky.manager', level='WARNING') as logs:
            with self.assertRaises(RuntimeError) as error:
                asyncio.run(CompanionManager._transcribe_with_configured_fallback(host, b'pcm', SimpleNamespace(sequence=1)))
        self.assertNotIn('synthetic-sensitive', str(error.exception))
        self.assertNotIn('synthetic-sensitive', ''.join(logs.output))
        self.assertIn('provider=openai', ''.join(logs.output))

    def test_cancelled_primary_does_not_report_failure_or_use_fallback(self):
        fallback = _STT(result='not used')
        host = _FallbackHarness(_STT(error=asyncio.CancelledError()), fallback)
        with mock.patch.object(module, 'cfg', configuration(fallback='whisper_cpp')):
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(CompanionManager._transcribe_with_configured_fallback(host, b'pcm', SimpleNamespace(sequence=1)))
        self.assertEqual(fallback.pcm, [])
        self.assertEqual(host.sig_error.values, [])
