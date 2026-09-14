"""OpenRouter speech transport/playback contracts; no network or sound device."""
import asyncio
import json
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx

from audio.tts import openrouter_provider as tts
from audio.tts.factory import create_tts_provider
from audio.tts.voice_catalog import default_voice_id, reviewed_voices
from privacy_controls import PRIVACY_NOTICE_VERSION


class OpenRouterTTSTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config=types.SimpleNamespace(openrouter_api_key='test-openrouter-only',
            openrouter_private_routing=False,cloud_tts_consent=True,
            privacy_consent_version=PRIVACY_NOTICE_VERSION,
            tts_provider=lambda:'openrouter',get_tts_voice=lambda provider:tts.OPENROUTER_TTS_VOICE)
        self.patch_cfg=patch.object(tts,'cfg',self.config);self.patch_cfg.start();self.addCleanup(self.patch_cfg.stop)
        self.play=AsyncMock();self.stop=Mock();self.requests=[];self.client_options=[]
        self.patch_play=patch.object(tts,'play_mp3_async',self.play);self.patch_play.start();self.addCleanup(self.patch_play.stop)
        self.patch_stop=patch.object(tts,'stop_audio',self.stop);self.patch_stop.start();self.addCleanup(self.patch_stop.stop)
        self.handler=lambda request:httpx.Response(200,headers={'content-type':'audio/mpeg'},content=b'ID3synthetic')
        original=httpx.AsyncClient
        def client(**kwargs):
            self.client_options.append(kwargs)
            async def route(request):
                self.requests.append(request)
                result=self.handler(request)
                return await result if asyncio.iscoroutine(result) else result
            return original(transport=httpx.MockTransport(route),**kwargs)
        self.patch_client=patch.object(tts.httpx,'AsyncClient',client);self.patch_client.start();self.addCleanup(self.patch_client.stop)
        self.provider=tts.OpenRouterTTSProvider()

    async def test_exact_endpoint_model_voice_auth_and_shared_playback(self):
        await self.provider.speak('The answer is sixteen.')
        request=self.requests[0];body=json.loads(request.content)
        self.assertEqual(str(request.url),tts.OPENROUTER_TTS_ENDPOINT)
        self.assertEqual(request.headers['authorization'],'Bearer test-openrouter-only')
        self.assertEqual(body,{'model':'microsoft/mai-voice-2','input':'The answer is sixteen.',
            'voice':tts.OPENROUTER_TTS_VOICE,'response_format':'mp3','provider':{'allow_fallbacks':False}})
        self.assertFalse(self.client_options[0]['trust_env']);self.assertFalse(self.client_options[0]['follow_redirects'])
        self.play.assert_awaited_once_with(b'ID3synthetic')

    async def test_private_routing_is_not_silently_weakened(self):
        self.config.openrouter_private_routing=True
        await tts.OpenRouterTTSProvider().speak('Synthetic test')
        self.assertEqual(json.loads(self.requests[0].content)['provider'],
            {'allow_fallbacks':False,'zdr':True,'data_collection':'deny'})

    async def test_permission_or_key_revocation_blocks_request(self):
        self.config.cloud_tts_consent=False
        with self.assertRaises(PermissionError):await self.provider.speak('Synthetic')
        self.assertEqual(self.requests,[])
        self.config.cloud_tts_consent=True;self.config.openrouter_api_key='changed'
        with self.assertRaises(RuntimeError):await self.provider.speak('Synthetic')
        self.assertEqual(self.requests,[])

    async def test_settings_change_after_response_prevents_playback(self):
        def revoke(request):
            self.config.openrouter_private_routing=True
            return httpx.Response(200,headers={'content-type':'audio/mpeg'},content=b'ID3synthetic')
        self.handler=revoke
        with self.assertRaises(RuntimeError):await self.provider.speak('Synthetic')
        self.play.assert_not_called()

    async def test_http_error_body_never_leaks_or_plays(self):
        self.handler=lambda request:httpx.Response(401,json={'error':'sensitive provider body'})
        with self.assertRaisesRegex(RuntimeError,'^OpenRouter speech could not be completed.$'):
            await self.provider.speak('Synthetic')
        self.play.assert_not_called()

    async def test_wrong_content_type_empty_and_oversize_rejected(self):
        for response in (httpx.Response(200,headers={'content-type':'application/json'},content=b'{}'),
                httpx.Response(200,headers={'content-type':'audio/mpeg'},content=b''),
                httpx.Response(200,headers={'content-type':'audio/mpeg'},content=b'a'*17)):
            with self.subTest(response=response):
                self.handler=lambda request:response
                with patch.object(tts,'MAX_AUDIO_BYTES',16),self.assertRaises(RuntimeError):
                    await self.provider.speak('Synthetic')
        self.play.assert_not_called()

    async def test_stop_during_network_cancels_without_playback(self):
        started=asyncio.Event();finished=asyncio.Event()
        async def pending(request):
            started.set()
            try:await asyncio.sleep(20)
            finally:finished.set()
        self.handler=pending
        task=asyncio.create_task(self.provider.speak('Synthetic'))
        await asyncio.wait_for(started.wait(),1);self.provider.stop()
        with self.assertRaises(asyncio.CancelledError):await asyncio.wait_for(task,1)
        self.assertTrue(finished.is_set());self.play.assert_not_called()

    async def test_permission_revocation_stops_active_playback(self):
        started=asyncio.Event()
        async def playing(audio):
            started.set();await asyncio.sleep(20)
        self.play.side_effect=playing
        task=asyncio.create_task(self.provider.speak('Synthetic'))
        await asyncio.wait_for(started.wait(),1);self.config.cloud_tts_consent=False
        with self.assertRaises(PermissionError):await asyncio.wait_for(task,1)
        self.stop.assert_called()

    async def test_task_cancellation_stops_active_playback(self):
        started=asyncio.Event()
        async def playing(audio):
            started.set();await asyncio.sleep(20)
        self.play.side_effect=playing
        task=asyncio.create_task(self.provider.speak('Synthetic'))
        await asyncio.wait_for(started.wait(),1);task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.stop.assert_called()

    async def test_long_answer_uses_bounded_sequential_chunks(self):
        text=('This is a synthetic sentence. '*90).strip()
        await self.provider.speak(text)
        chunks=[json.loads(request.content)['input'] for request in self.requests]
        self.assertGreater(len(chunks),1)
        self.assertTrue(all(len(chunk)<=tts.MAX_TTS_CHUNK for chunk in chunks))
        self.assertEqual(' '.join(chunks),text)
        self.assertEqual(self.play.await_count,len(chunks))

    async def test_total_deadline_cancels_pending_synthesis(self):
        async def pending(request):await asyncio.sleep(20)
        self.handler=pending
        with patch.object(tts,'MAX_SPEAK_SECONDS',0.01),self.assertRaises(RuntimeError):
            await self.provider.speak('Synthetic')
        self.play.assert_not_called()

    async def test_blank_and_oversize_text_make_no_requests(self):
        await self.provider.speak('  ')
        with self.assertRaises(ValueError):await self.provider.speak('a'*(tts.MAX_TTS_TEXT+1))
        self.assertEqual(self.requests,[])

    async def test_factory_and_reviewed_catalog_route_openrouter(self):
        provider=create_tts_provider('openrouter',default_voice_id('openrouter'))
        self.assertIsInstance(provider,tts.OpenRouterTTSProvider)
        self.assertEqual(len(reviewed_voices('openrouter')),4)
        with self.assertRaises(ValueError):create_tts_provider('openrouter','alloy')

if __name__=='__main__':unittest.main()
