"""Synthetic UI and real SDK-serialization checks; no desktop or network I/O."""
import asyncio
import os
import types
import unittest
from unittest import mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import httpx
from PyQt6.QtWidgets import QApplication, QLabel
from config import Config
from ui import privacy_consent
from ui.panel import CompanionPanel, AppState
from ai import openai_compatible_provider as provider_module
from ai.sdk_isolation import create_openai_client
from audio.stt.readiness import STTReadiness
from ui.stt_readiness import SpeechReadinessDialog


class FirstRunPermissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def make_dialog(self, **values):
        cfg = Config(active_llm='openrouter', openrouter_api_key='synthetic', **values)
        with mock.patch.object(privacy_consent, 'cfg', cfg), mock.patch.object(
            privacy_consent, 'build_feature_available', return_value=False
        ):
            dialog = privacy_consent.PrivacyConsentDialog()
        self.addCleanup(dialog.close)
        return dialog, cfg

    def test_optional_services_start_collapsed_and_remain_disabled(self):
        dialog, cfg = self.make_dialog()
        self.assertTrue(dialog.optional_features.isHidden())
        self.assertFalse(dialog.coding_agent.isChecked())
        self.assertFalse(dialog.market_data.isChecked())
        dialog.optional_toggle.click()
        self.assertFalse(dialog.optional_features.isHidden())
        self.assertFalse(dialog.coding_agent.isChecked())
        with mock.patch.object(privacy_consent, 'cfg', cfg), mock.patch.object(
            cfg, 'set_privacy_permissions'
        ) as save:
            dialog._save()
        self.assertFalse(save.call_args.kwargs['coding_agent'])
        self.assertFalse(save.call_args.kwargs['market_data'])

    def test_existing_optional_grant_is_visible_and_preserved(self):
        dialog, cfg = self.make_dialog(coding_agent_consent=True)
        self.assertFalse(dialog.optional_features.isHidden())
        with mock.patch.object(privacy_consent, 'cfg', cfg), mock.patch.object(
            cfg, 'set_privacy_permissions'
        ) as save:
            dialog._save()
        self.assertTrue(save.call_args.kwargs['coding_agent'])

    def test_error_opens_panel_and_persists_as_response(self):
        panel = types.SimpleNamespace(_response_text='Your answer is four.',
                                      _error_label=QLabel(),
                                      show=mock.Mock(), raise_=mock.Mock())
        CompanionPanel.show_error(panel, 'Speech output failed; read the answer below.')
        self.assertEqual(panel._response_text, 'Your answer is four.')
        self.assertIn('Speech output failed', panel._error_label.text())
        self.assertFalse(panel._error_label.isHidden())
        panel.show.assert_called_once()
        panel.raise_.assert_called_once()

    def test_new_speech_turn_clears_old_error_without_clearing_later_tts_failure(self):
        panel = types.SimpleNamespace(_transcript_session=1, _transcript_label=QLabel(),
            _error_label=QLabel(), _response_text='old answer', _response_label=QLabel(),
            show=mock.Mock(), raise_=mock.Mock())
        panel.clear_error = lambda: CompanionPanel.clear_error(panel)
        CompanionPanel.show_error(panel, 'Old failure')
        CompanionPanel.begin_transcript(panel, 2)
        self.assertTrue(panel._error_label.isHidden())
        CompanionPanel.update_response(panel, 'Successful retry')
        CompanionPanel.show_error(panel, 'Voice playback failed')
        self.assertEqual(panel._response_text, 'Successful retry')
        self.assertIn('Voice playback failed', panel._error_label.text())

    def test_cloud_configuration_is_not_presented_as_live_readiness(self):
        dialog = types.SimpleNamespace(_checking=True, refresh_button=mock.Mock(), results=mock.Mock())
        SpeechReadinessDialog._show_results(dialog, [STTReadiness(
            'openrouter', 'Muse 1.2', 'cloud batch', 'OpenRouter', True,
            'Configured and consented. No request was made.')])
        rendered = dialog.results.setHtml.call_args.args[0]
        self.assertIn('CONFIGURED', rendered)
        self.assertNotIn('>READY<', rendered)

    def test_completed_transcript_stays_visible_until_next_recording(self):
        panel = types.SimpleNamespace(_transcript_session=1, _transcript_label=QLabel(), clear_error=mock.Mock())
        CompanionPanel.update_final_transcript(panel, 1, 'Point to the plus button')
        CompanionPanel.end_transcript(panel, 1)
        self.assertIn('Point to the plus button', panel._transcript_label.text())
        self.assertFalse(panel._transcript_label.isHidden())
        CompanionPanel.begin_transcript(panel, 2)
        self.assertEqual(panel._transcript_label.text(), '')

    def test_media_retry_clears_old_error_but_speaking_does_not(self):
        panel = types.SimpleNamespace(_state=AppState.IDLE, _error_label=QLabel(),
            _status_dot=QLabel(), _status_label=QLabel(), _waveform=mock.Mock(),
            _refresh_capture_controls=mock.Mock(),
            show=mock.Mock(), raise_=mock.Mock())
        panel.clear_error = lambda: CompanionPanel.clear_error(panel)
        CompanionPanel.show_error(panel, 'Old media failure')
        CompanionPanel.set_state(panel, AppState.THINKING)
        self.assertTrue(panel._error_label.isHidden())
        CompanionPanel.show_error(panel, 'New playback failure')
        CompanionPanel.set_state(panel, AppState.SPEAKING)
        CompanionPanel.set_state(panel, AppState.IDLE)
        self.assertIn('New playback failure', panel._error_label.text())
        self.assertFalse(panel._error_label.isHidden())


class EmptyProviderResponseTests(unittest.IsolatedAsyncioTestCase):
    async def run_response(self, model, content):
        import json
        requests = []
        def transport(request):
            requests.append(json.loads(request.content))
            chunk = {'id':'test', 'object':'chat.completion.chunk', 'created':0,
                     'model':model, 'choices':[{'index':0, 'delta':{'content':content},
                                               'finish_reason':'stop'}]}
            return httpx.Response(200, headers={'content-type':'text/event-stream'},
                text='data: ' + json.dumps(chunk) + '\n\ndata: [DONE]\n\n')
        client = create_openai_client(api_key='synthetic', base_url='https://openrouter.ai/api/v1',
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(transport)))
        with mock.patch.object(provider_module, 'cfg', types.SimpleNamespace(
            openrouter_api_key='synthetic', openrouter_private_routing=True
        )), mock.patch.object(provider_module, 'create_openai_client', return_value=client):
            provider = provider_module.OpenAICompatibleProvider('openrouter')
            try:
                answer = ''.join([part async for part in provider.stream_response(
                    'test', [], [], 'test', model=model)])
            finally:
                await client.close()
        return answer, requests[0]

    async def test_empty_response_is_an_actionable_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'returned no answer text'):
            await self.run_response('meta/muse-spark-1.2-contributor', '')

    async def test_muse_allowance_preserves_strict_routing(self):
        answer, request = await self.run_response('meta/muse-spark-1.2-contributor', 'hello')
        self.assertEqual(answer, 'hello')
        self.assertEqual(request['max_tokens'], 4096)
        self.assertEqual(request['provider'], {'allow_fallbacks':False,'zdr':True,'data_collection':'deny'})
        _, other = await self.run_response('another/model', 'hello')
        self.assertEqual(other['max_tokens'], 1024)


if __name__ == '__main__':
    unittest.main()
