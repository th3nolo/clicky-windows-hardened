"""Bounded OpenRouter speech synthesis using the shared cancellable player."""
from __future__ import annotations
import asyncio
import re
import threading
import httpx
from audio.playback import play_mp3_async, stop_audio
from audio.tts.base_tts import BaseTTS
from audio.tts.voice_catalog import reviewed_voice
from config import cfg
from privacy_controls import cloud_tts_allowed

OPENROUTER_TTS_MODEL = 'microsoft/mai-voice-2'
OPENROUTER_TTS_ENDPOINT = 'https://openrouter.ai/api/v1/audio/speech'
OPENROUTER_TTS_VOICE = 'en-US-Harper:MAI-Voice-2'
MAX_TTS_TEXT = 16000
MAX_TTS_CHUNK = 1000
MAX_SPEAK_SECONDS = 600
MAX_AUDIO_BYTES = 8 * 1024 * 1024


class OpenRouterTTSProvider(BaseTTS):
    """One explicitly selected model and voice; no credential/provider fallback."""
    def __init__(self, voice: str = OPENROUTER_TTS_VOICE):
        self._voice = reviewed_voice('openrouter', voice).voice_id
        self._key = getattr(cfg, 'openrouter_api_key', None)
        self._private = getattr(cfg, 'openrouter_private_routing', False) is True
        self._selected_provider = cfg.tts_provider()
        self._selected_voice = cfg.get_tts_voice('openrouter')
        self._stopped = threading.Event()
        self._speaking = False
        self._playing = False

    def _require_current_settings(self):
        if self._stopped.is_set():
            raise asyncio.CancelledError()
        if not cloud_tts_allowed(cfg):
            raise PermissionError('Cloud text-to-speech permission is required.')
        if (getattr(cfg, 'openrouter_api_key', None) != self._key or
                (getattr(cfg, 'openrouter_private_routing', False) is True) != self._private or
                cfg.tts_provider() != self._selected_provider or
                cfg.get_tts_voice('openrouter') != self._selected_voice):
            raise RuntimeError('Speech settings changed; start a new speech request.')
        if not isinstance(self._key, str) or not self._key.strip():
            raise RuntimeError('OpenRouter speech credentials are required.')

    def stop(self):
        """Existing companion cancellation path calls this across threads."""
        self._stopped.set()
        if self._playing:
            stop_audio()

    async def _synthesize_and_play(self, text):
        self._require_current_settings()
        routing = {'allow_fallbacks': False}
        if self._private:
            routing.update(zdr=True, data_collection='deny')
        payload = {'model': OPENROUTER_TTS_MODEL, 'input': text,
            'voice': self._voice, 'response_format': 'mp3', 'provider': routing}
        audio = bytearray()
        async with asyncio.timeout(90), httpx.AsyncClient(trust_env=False, follow_redirects=False,
                timeout=httpx.Timeout(60.0, connect=15.0)) as client:
            self._require_current_settings()
            async with client.stream('POST', OPENROUTER_TTS_ENDPOINT,
                    headers={'Authorization': 'Bearer ' + self._key}, json=payload) as response:
                if response.status_code != 200:
                    raise RuntimeError('OpenRouter speech synthesis failed.')
                if response.headers.get('content-type', '').split(';', 1)[0].strip().lower() != 'audio/mpeg':
                    raise RuntimeError('OpenRouter returned an unsupported speech format.')
                async for chunk in response.aiter_bytes():
                    self._require_current_settings()
                    if len(audio) + len(chunk) > MAX_AUDIO_BYTES:
                        raise RuntimeError('OpenRouter speech output exceeded its size limit.')
                    audio.extend(chunk)
        if not audio:
            raise RuntimeError('OpenRouter returned empty speech audio.')
        self._require_current_settings()
        self._playing = True
        try:
            await play_mp3_async(bytes(audio))
        finally:
            self._playing = False

    async def _speak_chunks(self, text):
        remaining = text.strip()
        async with asyncio.timeout(MAX_SPEAK_SECONDS):
            while remaining:
                end = min(len(remaining), MAX_TTS_CHUNK)
                if end < len(remaining):
                    boundaries = [match.end() for match in re.finditer(r'[.!?\u3002\uff01\uff1f]\s+', remaining[:end])]
                    if boundaries:
                        end = boundaries[-1]
                    else:
                        space = remaining.rfind(' ', 0, end)
                        if space > 0:
                            end = space
                chunk = remaining[:end].strip()
                remaining = remaining[end:].lstrip()
                self._require_current_settings()
                if chunk:
                    await self._synthesize_and_play(chunk)

    async def speak(self, text: str) -> None:
        if not isinstance(text, str) or len(text) > MAX_TTS_TEXT:
            raise ValueError('Speech text must be at most 16000 characters.')
        if not text.strip():
            return
        if self._speaking:
            raise RuntimeError('A speech request is already active.')
        self._speaking = True
        self._stopped.clear()
        operation = None
        try:
            self._require_current_settings()
            operation = asyncio.create_task(self._speak_chunks(text))
            while not operation.done():
                await asyncio.wait({operation}, timeout=0.05)
                self._require_current_settings()
            await operation
        except asyncio.CancelledError:
            self.stop()
            raise
        except PermissionError:
            self.stop()
            raise
        except Exception:
            self.stop()
            raise RuntimeError('OpenRouter speech could not be completed.') from None
        finally:
            if operation is not None:
                if not operation.done():
                    operation.cancel()
                await asyncio.gather(operation, return_exceptions=True)
            self._speaking = False
