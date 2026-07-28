"""Permissioned, bounded preview of one reviewed cloud TTS voice."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from audio.tts.factory import create_tts_provider
from audio.tts.voice_catalog import ReviewedVoice, reviewed_voice


VOICE_PREVIEW_TEXT = "This is Clicky's fixed voice preview."
VOICE_PREVIEW_TIMEOUT_SECONDS = 12.0


async def speak_voice_preview(
    provider: str,
    voice_id: str,
    *,
    cloud_tts_permission: bool,
    provider_factory: Callable[[str, str], object] = create_tts_provider,
    timeout_seconds: float = VOICE_PREVIEW_TIMEOUT_SECONDS,
) -> ReviewedVoice:
    """Speak fixed synthetic text through exactly one reviewed provider.

    No response text, user text, fallback provider, or local status voice enters
    this path. Cancellation propagates to the manager-owned playback stop.
    """

    if cloud_tts_permission is not True:
        raise PermissionError(
            "Cloud text-to-speech permission is required for voice preview."
        )
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < float(timeout_seconds) <= VOICE_PREVIEW_TIMEOUT_SECONDS
    ):
        raise ValueError("Voice preview timeout is invalid")
    voice = reviewed_voice(provider, voice_id)
    speaker = provider_factory(provider, voice.voice_id)
    speak = getattr(speaker, "speak", None)
    if not callable(speak):
        raise TypeError("TTS preview provider is invalid")
    await asyncio.wait_for(
        speak(VOICE_PREVIEW_TEXT),
        timeout=float(timeout_seconds),
    )
    return voice


__all__ = [
    "VOICE_PREVIEW_TEXT",
    "VOICE_PREVIEW_TIMEOUT_SECONDS",
    "speak_voice_preview",
]
