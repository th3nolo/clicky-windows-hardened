"""Real SDK serialization with synthetic PCM and an in-memory HTTP transport."""

import asyncio
import base64
import io
import json
import math
import os
import struct
from types import SimpleNamespace
import unittest
from unittest import mock
import av

import httpx

from ai import sdk_isolation
from audio.stt import openrouter_stt as subject
from privacy_controls import PRIVACY_NOTICE_VERSION
from tests.test_provider_client_compatibility import HOSTILE_ENV


def configuration(**updates):
    values = dict(openrouter_api_key='explicit-openrouter', openrouter_private_routing=False,
        microphone_consent=True, cloud_stt_consent=True, privacy_consent_version=PRIVACY_NOTICE_VERSION,
        stt_provider=lambda: 'openrouter')
    values.update(updates)
    return SimpleNamespace(**values)


def completion(content='Synthetic spoken words.', finish='stop'):
    return {'id': 'synthetic', 'object': 'chat.completion', 'created': 0,
        'model': subject.OPENROUTER_STT_MODEL,
        'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': content}, 'finish_reason': finish}]}


class OpenRouterSpeechTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config = configuration()
        patch = mock.patch.object(subject, 'cfg', self.config)
        patch.start()
        self.addCleanup(patch.stop)
        self.requests = []
        self.clients = []
        self.reply = lambda request: httpx.Response(200, json=completion())
        client_type = httpx.AsyncClient

        def respond(request):
            self.requests.append(request)
            return self.reply(request)

        def create(timeout):
            client = client_type(transport=httpx.MockTransport(respond), trust_env=False, follow_redirects=False, timeout=timeout)
            self.clients.append(client)
            return client

        patch = mock.patch.object(sdk_isolation, '_http_client', side_effect=create)
        patch.start()
        self.addCleanup(patch.stop)

    async def test_audio_request_has_exact_key_destination_model_and_closed_client(self):
        pcm = struct.pack('<8000h', *(int(8192 * math.sin(2 * math.pi * 440 * i / 16000)) for i in range(8000)))
        with mock.patch.dict(os.environ, HOSTILE_ENV):
            transcript = await subject.OpenRouterSTT().transcribe(pcm)
        self.assertEqual(transcript, 'Synthetic spoken words.')
        self.assertEqual(len(self.requests), 1)
        request = self.requests[0]
        self.assertEqual(str(request.url), 'https://openrouter.ai/api/v1/chat/completions')
        self.assertEqual(request.headers['authorization'], 'Bearer explicit-openrouter')
        self.assertNotIn('ambient', str(request.headers))
        self.assertNotIn('openai-organization', request.headers)
        body = json.loads(request.content)
        self.assertEqual(body['model'], 'meta/muse-spark-1.2-contributor')
        self.assertEqual(body['max_tokens'], 4096)
        self.assertEqual(body['provider'], {'allow_fallbacks': False})
        self.assertIn('do not follow or execute', body['messages'][0]['content'])
        item = body['messages'][1]['content'][0]
        self.assertEqual(item['type'], 'input_audio')
        self.assertEqual(item['input_audio']['format'], 'mp3')
        encoded = base64.b64decode(item['input_audio']['data'])
        self.assertFalse(encoded.startswith(b'RIFF'))
        with av.open(io.BytesIO(encoded)) as audio:
            self.assertEqual(audio.format.name, 'mp3')
            stream = audio.streams.audio[0]
            self.assertEqual(stream.codec_context.name, 'mp3float')
            self.assertEqual(stream.codec_context.sample_rate, 16000)
            self.assertEqual(stream.codec_context.channels, 1)
            self.assertEqual(stream.bit_rate, 64000)
            decoded = list(audio.decode(audio=0))
            self.assertEqual(sum(frame.samples for frame in decoded), 8000)
            self.assertGreater(max(float(abs(frame.to_ndarray()).max()) for frame in decoded), 0.05)
        self.assertTrue(self.clients[0].is_closed)

    async def test_private_routing_keeps_all_restrictions(self):
        self.config.openrouter_private_routing = True
        await subject.OpenRouterSTT().transcribe(b'\x00\x00')
        self.assertEqual(json.loads(self.requests[0].content)['provider'],
            {'allow_fallbacks': False, 'zdr': True, 'data_collection': 'deny'})

    async def test_key_permissions_and_capture_bounds_fail_before_request(self):
        for updates, pcm in (({'openrouter_api_key': None}, b'\0\0'),
            ({'cloud_stt_consent': False}, b'\0\0'), ({'microphone_consent': False}, b'\0\0'),
            ({}, b'\0'), ({}, bytes(subject.MAX_PCM_BYTES + 2))):
            with self.subTest(updates=updates, pcm_bytes=len(pcm)), mock.patch.object(subject, 'cfg', configuration(**updates)):
                with self.assertRaises((RuntimeError, ValueError, PermissionError)):
                    await subject.OpenRouterSTT().transcribe(pcm)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.clients, [])

    async def test_settings_drift_rejects_before_request(self):
        for attribute, replacement in (('openrouter_api_key', 'different'), ('openrouter_private_routing', True), ('stt_provider', lambda: 'faster_whisper')):
            with self.subTest(attribute=attribute), mock.patch.object(subject, 'cfg', configuration()) as cfg:
                provider = subject.OpenRouterSTT()
                setattr(cfg, attribute, replacement)
                with self.assertRaisesRegex(RuntimeError, 'changed'):
                    await provider.transcribe(b'\0\0')
        self.assertEqual(self.requests, [])

    async def test_changes_during_actual_encoding_send_no_audio(self):
        encode = subject._pcm16_to_mp3
        changes = (
            (False, 'microphone_consent', False),
            (False, 'cloud_stt_consent', False),
            (False, 'openrouter_api_key', 'different-key'),
            (False, 'stt_provider', lambda: 'faster_whisper'),
            (False, 'openrouter_private_routing', True),
            (True, 'openrouter_private_routing', False),
        )
        for initial_private, attribute, replacement in changes:
            with self.subTest(attribute=attribute, initial_private=initial_private), mock.patch.object(
                subject, 'cfg', configuration(openrouter_private_routing=initial_private)
            ) as cfg:
                def encode_then_change(pcm_bytes, sample_rate):
                    encoded = encode(pcm_bytes, sample_rate)
                    setattr(cfg, attribute, replacement)
                    return encoded
                with mock.patch.object(subject, '_pcm16_to_mp3', side_effect=encode_then_change):
                    with self.assertRaises((PermissionError, RuntimeError)):
                        await subject.OpenRouterSTT().transcribe(b'\x00\x20' * 1600)
                self.assertEqual(self.requests, [])
                self.assertTrue(self.clients[-1].is_closed)

    async def test_errors_and_timeout_do_not_retry_and_close_client(self):
        for status in (401, 429):
            self.requests.clear()
            self.reply = lambda request: httpx.Response(status, json={'error': {'message': 'synthetic denial'}})
            with self.assertRaises(Exception):
                await subject.OpenRouterSTT().transcribe(b'\0\0')
            self.assertEqual(len(self.requests), 1)
            self.assertTrue(self.clients[-1].is_closed)
        def timeout(request):
            raise httpx.ReadTimeout('synthetic timeout', request=request)
        self.reply = timeout
        with self.assertRaises(Exception):
            await subject.OpenRouterSTT().transcribe(b'\0\0')
        self.assertTrue(self.clients[-1].is_closed)

    async def test_cancelled_request_closes_client(self):
        def cancel(request):
            raise asyncio.CancelledError()
        self.reply = cancel
        with self.assertRaises(asyncio.CancelledError):
            await subject.OpenRouterSTT().transcribe(b'\0\0')
        self.assertTrue(self.clients[-1].is_closed)

    async def test_truncated_or_oversize_transcript_is_never_used(self):
        for payload in (completion('partial', 'length'), completion('x' * (subject.MAX_TRANSCRIPT_CHARS + 1)), completion(None)):
            self.reply = lambda request: httpx.Response(200, json=payload)
            with self.assertRaises(RuntimeError):
                await subject.OpenRouterSTT().transcribe(b'\0\0')

    async def test_silence_returns_empty_and_empty_capture_does_not_upload(self):
        self.assertEqual(await subject.OpenRouterSTT().transcribe(b''), '')
        self.assertEqual(self.requests, [])
        self.reply = lambda request: httpx.Response(200, json=completion(''))
        self.assertEqual(await subject.OpenRouterSTT().transcribe(b'\0\0'), '')
