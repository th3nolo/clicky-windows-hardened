"""Construct one explicitly selected, reviewed TTS provider."""

from __future__ import annotations

from audio.tts.voice_catalog import reviewed_voice


def create_tts_provider(provider: str, voice_id: str):
    """Build exactly ``provider`` with one catalog-approved voice ID."""

    voice = reviewed_voice(provider, voice_id)
    if provider == "elevenlabs":
        from audio.tts.elevenlabs_provider import ElevenLabsProvider

        return ElevenLabsProvider(voice_id=voice.voice_id)
    if provider == "openai":
        from audio.tts.openai_tts_provider import OpenAITTSProvider

        return OpenAITTSProvider(voice=voice.voice_id)
    if provider == "edge_tts":
        from audio.tts.edge_tts_provider import EdgeTTSProvider

        return EdgeTTSProvider(voice=voice.voice_id)
    raise ValueError("Unsupported TTS provider")


__all__ = ["create_tts_provider"]
