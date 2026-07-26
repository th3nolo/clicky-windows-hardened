"""Offline whisper.cpp speech-to-text using a pre-provisioned local model.

The hardened Windows build never asks pywhispercpp to download a model. Set
WHISPERCPP_MODEL to a verified GGML/GGUF file, or place exactly one matching
model in a supported local cache directory before starting Clicky.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import wave
from pathlib import Path
from typing import Optional

from audio.capture import pcm16_to_wav, trim_silence
from audio.stt.base_stt import BaseSTT
from audio.stt.local_models import resolve_whisper_cpp_model
from config import cfg


DEFAULT_MODEL = os.getenv("WHISPERCPP_MODEL", "") or cfg.whisper_model or "base"


class WhisperCppSTT(BaseSTT):
    """Local STT via whisper.cpp using an existing model file only."""

    def __init__(self, model: Optional[str] = None):
        try:
            from pywhispercpp.model import Model  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "whisper.cpp support is not installed. The hardened build will "
                "not install it automatically; provision a reviewed pywhispercpp "
                "package and local model, or select another STT provider."
            ) from exc

        self._Model = Model
        self._model_path = resolve_whisper_cpp_model(
            model or DEFAULT_MODEL, cfg.whispercpp_model_sha256
        )
        self._model = None

    def _load(self):
        if self._model is None:
            try:
                cores = max(1, (os.cpu_count() or 4) - 1)
            except Exception:
                cores = 4
            self._model = self._Model(
                str(self._model_path),
                n_threads=cores,
                print_realtime=False,
                print_progress=False,
            )
        return self._model

    async def transcribe(self, pcm_bytes: bytes) -> str:
        """Convert raw 16-bit mono PCM at 16 kHz to text."""
        if not pcm_bytes:
            return ""
        pcm_bytes = trim_silence(pcm_bytes)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_transcribe, pcm_bytes)

    def _sync_transcribe(self, pcm_bytes: bytes) -> str:
        wav_bytes = pcm16_to_wav(pcm_bytes)
        pcm_bytes = wav_bytes[44:]

        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_file:
            temp_path = temp_file.name
        try:
            with wave.open(temp_path, "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(16000)
                wav_file.writeframes(pcm_bytes)
            model = self._load()
            language = cfg.whisper_language or ""
            segments = model.transcribe(temp_path, language=language)
            return " ".join(segment.text.strip() for segment in segments).strip()
        finally:
            try:
                Path(temp_path).unlink()
            except Exception:
                pass
