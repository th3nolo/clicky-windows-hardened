from ai.sdk_isolation import create_openai_client

from audio.tts.base_tts import BaseTTS
from audio.playback import play_mp3_async
from audio.openai_credentials import openai_speech_api_key
from audio.tts.voice_catalog import reviewed_voice
from config import cfg


class OpenAITTSProvider(BaseTTS):
    """OpenAI TTS — high quality, $15/1M chars."""

    def __init__(self, voice: str = "alloy"):
        self._client = create_openai_client(
            api_key=openai_speech_api_key(
                speech_key=getattr(cfg, "openai_speech_api_key", None),
                chat_key=cfg.openai_api_key,
                chat_base_url=getattr(cfg, "openai_base_url", ""),
            ),
            base_url="https://api.openai.com/v1",
            timeout=600.0,
            max_retries=2,
        )
        self._voice = reviewed_voice("openai", voice).voice_id

    async def speak(self, text: str) -> None:
        if not text.strip():
            return

        response = await self._client.audio.speech.create(
            model="tts-1",
            voice=self._voice,
            input=text,
            response_format="mp3",
        )

        await play_mp3_async(response.content)
