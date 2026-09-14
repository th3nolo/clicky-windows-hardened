import io
from collections.abc import Sequence

from audio.stt.base_stt import BaseSTT
from audio.capture import pcm16_to_wav
from audio.openai_client import create_openai_speech_client
from audio.stt.vocabulary import approved_vocabulary
from config import cfg


class OpenAISTT(BaseSTT):
    """OpenAI Whisper API — upload-based, high accuracy."""

    def __init__(self, vocabulary: Sequence[str] = ()) -> None:
        self._client = create_openai_speech_client(cfg)
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
