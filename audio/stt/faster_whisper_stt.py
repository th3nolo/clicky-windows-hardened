import asyncio

from audio.capture import pcm16_to_wav, trim_silence
from audio.stt.base_stt import BaseSTT
from audio.stt.local_models import LocalModelUnavailable, resolve_faster_whisper_model
from config import cfg

_model_cache = None


def load_local_faster_whisper_model(model_spec: str, expected_sha256: str):
    """Load only a complete model already present on local storage."""
    model_path = resolve_faster_whisper_model(model_spec, expected_sha256)
    try:
        from faster_whisper import WhisperModel

        return WhisperModel(
            str(model_path),
            device="cpu",
            compute_type="int8",
            local_files_only=True,
        )
    except LocalModelUnavailable:
        raise
    except Exception as exc:
        raise LocalModelUnavailable(
            f"Could not load the verified local faster-whisper model at "
            f"{model_path}: {exc}"
        ) from exc


def _get_model():
    global _model_cache
    if _model_cache is None:
        _model_cache = load_local_faster_whisper_model(
            cfg.whisper_model, cfg.whisper_model_sha256
        )
    return _model_cache


class FasterWhisperSTT(BaseSTT):
    """Offline speech-to-text using an already-provisioned local model."""

    async def transcribe(self, pcm_bytes: bytes, sample_rate: int = 16000) -> str:
        pcm_bytes = trim_silence(pcm_bytes)
        wav_bytes = pcm16_to_wav(pcm_bytes, sample_rate)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run, wav_bytes)

    def _run(self, wav_bytes: bytes) -> str:
        import os
        import tempfile

        model = _get_model()
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as wav_file:
            wav_file.write(wav_bytes)
            wav_path = wav_file.name
        try:
            language = cfg.whisper_language or None
            segments, _ = model.transcribe(
                wav_path,
                beam_size=5,
                language=language,
            )
            return " ".join(segment.text.strip() for segment in segments).strip()
        finally:
            os.unlink(wav_path)
