import io
from collections.abc import Sequence

from ai.sdk_isolation import create_openai_client

from audio.stt.base_stt import BaseSTT
from audio.capture import pcm16_to_wav
from audio.openai_credentials import openai_speech_api_key
from audio.stt.vocabulary import approved_vocabulary
from config import cfg


class OpenAISTT(BaseSTT):
    """OpenAI Whisper API — upload-based, high accuracy."""

    def __init__(self, vocabulary: Sequence[str] = ()) -> None:
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
        self._vocabulary = approved_vocabulary(vocabulary)

    async def transcribe(self, pcm_bytes: bytes, sample_rate: int = 16000) -> str:
        wav_bytes = pcm16_to_wav(pcm_bytes, sample_rate)
        audio_file = io.BytesIO(wav_bytes)
        audio_file.name = "audio.wav"
        result = await self._client.audio.transcriptions.create(
            model="whisper-1",
            file=audio_file,
            response_format="text",
            prompt=", ".join(self._vocabulary),
        )
        return result.strip() if isinstance(result, str) else result.text.strip()
