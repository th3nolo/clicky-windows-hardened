"""Fixed, reviewed voice identities for the supported cloud TTS providers.

Voice selection is a transport setting. It is intentionally separate from
writing-style profiles, LLM instructions, and model personas.
"""

from __future__ import annotations

from dataclasses import dataclass


EDGE_TTS_PROVIDER = "edge_tts"
OPENAI_TTS_PROVIDER = "openai"
ELEVENLABS_TTS_PROVIDER = "elevenlabs"
TTS_PROVIDERS = (
    EDGE_TTS_PROVIDER,
    OPENAI_TTS_PROVIDER,
    ELEVENLABS_TTS_PROVIDER,
)


@dataclass(frozen=True)
class ReviewedVoice:
    """One non-editable provider voice exposed by the Windows UI."""

    provider: str
    voice_id: str
    label: str
    destination: str


_DESTINATIONS = {
    EDGE_TTS_PROVIDER: "speech.platform.bing.com",
    OPENAI_TTS_PROVIDER: "api.openai.com",
    ELEVENLABS_TTS_PROVIDER: "api.elevenlabs.io",
}
_PROVIDER_LABELS = {
    EDGE_TTS_PROVIDER: "Microsoft Edge TTS",
    OPENAI_TTS_PROVIDER: "OpenAI TTS",
    ELEVENLABS_TTS_PROVIDER: "ElevenLabs",
}


def _voice(provider: str, voice_id: str, label: str) -> ReviewedVoice:
    return ReviewedVoice(
        provider=provider,
        voice_id=voice_id,
        label=label,
        destination=_DESTINATIONS[provider],
    )


# Edge IDs are a deliberately fixed subset of the reviewed Microsoft voice
# catalog, not the arbitrary result of a local file or user-supplied endpoint.
_EDGE_VOICES = (
    _voice(EDGE_TTS_PROVIDER, "en-US-AvaNeural", "Ava — English (US)"),
    _voice(EDGE_TTS_PROVIDER, "en-US-AriaNeural", "Aria — English (US)"),
    _voice(EDGE_TTS_PROVIDER, "en-US-GuyNeural", "Guy — English (US)"),
    _voice(EDGE_TTS_PROVIDER, "en-US-JennyNeural", "Jenny — English (US)"),
    _voice(EDGE_TTS_PROVIDER, "hi-IN-MadhurNeural", "Madhur — Hindi"),
    _voice(EDGE_TTS_PROVIDER, "es-MX-DaliaNeural", "Dalia — Spanish"),
    _voice(EDGE_TTS_PROVIDER, "fr-FR-DeniseNeural", "Denise — French"),
    _voice(EDGE_TTS_PROVIDER, "de-DE-KatjaNeural", "Katja — German"),
    _voice(EDGE_TTS_PROVIDER, "it-IT-ElsaNeural", "Elsa — Italian"),
    _voice(
        EDGE_TTS_PROVIDER,
        "pt-BR-FranciscaNeural",
        "Francisca — Portuguese",
    ),
    _voice(EDGE_TTS_PROVIDER, "ja-JP-NanamiNeural", "Nanami — Japanese"),
    _voice(EDGE_TTS_PROVIDER, "zh-CN-XiaoxiaoNeural", "Xiaoxiao — Chinese"),
    _voice(EDGE_TTS_PROVIDER, "ko-KR-SunHiNeural", "SunHi — Korean"),
    _voice(EDGE_TTS_PROVIDER, "ru-RU-SvetlanaNeural", "Svetlana — Russian"),
    _voice(EDGE_TTS_PROVIDER, "ar-EG-SalmaNeural", "Salma — Arabic"),
    _voice(EDGE_TTS_PROVIDER, "ta-IN-PallaviNeural", "Pallavi — Tamil"),
    _voice(EDGE_TTS_PROVIDER, "te-IN-ShrutiNeural", "Shruti — Telugu"),
    _voice(EDGE_TTS_PROVIDER, "bn-IN-TanishaaNeural", "Tanishaa — Bengali"),
    _voice(EDGE_TTS_PROVIDER, "ur-PK-UzmaNeural", "Uzma — Urdu"),
)

# These built-in IDs are reviewed for the repository's fixed tts-1 request.
# Custom voice objects are intentionally outside this first picker.
_OPENAI_VOICES = tuple(
    _voice(OPENAI_TTS_PROVIDER, voice_id, voice_id.title())
    for voice_id in (
        "alloy",
        "ash",
        "ballad",
        "coral",
        "echo",
        "fable",
        "nova",
        "onyx",
        "sage",
        "shimmer",
    )
)

# The current provider has one previously reviewed built-in identity. Adding
# account-specific ElevenLabs voices requires a separate bounded listing flow.
_ELEVENLABS_VOICES = (
    _voice(
        ELEVENLABS_TTS_PROVIDER,
        "EXAVITQu4vr4xnSDxMaL",
        "Sarah — ElevenLabs premade",
    ),
)

_VOICES = {
    EDGE_TTS_PROVIDER: _EDGE_VOICES,
    OPENAI_TTS_PROVIDER: _OPENAI_VOICES,
    ELEVENLABS_TTS_PROVIDER: _ELEVENLABS_VOICES,
}
_DEFAULTS = {
    EDGE_TTS_PROVIDER: "en-US-AvaNeural",
    OPENAI_TTS_PROVIDER: "alloy",
    ELEVENLABS_TTS_PROVIDER: "EXAVITQu4vr4xnSDxMaL",
}


def provider_label(provider: str) -> str:
    try:
        return _PROVIDER_LABELS[provider]
    except KeyError as exc:
        raise ValueError("Unsupported TTS provider") from exc


def provider_destination(provider: str) -> str:
    try:
        return _DESTINATIONS[provider]
    except KeyError as exc:
        raise ValueError("Unsupported TTS provider") from exc


def reviewed_voices(provider: str) -> tuple[ReviewedVoice, ...]:
    try:
        return _VOICES[provider]
    except KeyError as exc:
        raise ValueError("Unsupported TTS provider") from exc


def reviewed_voice(provider: str, voice_id: str) -> ReviewedVoice:
    if not isinstance(voice_id, str):
        raise TypeError("TTS voice ID must be text")
    for voice in reviewed_voices(provider):
        if voice.voice_id == voice_id:
            return voice
    raise ValueError("TTS voice is not in the reviewed provider catalog")


def default_voice_id(provider: str) -> str:
    try:
        return _DEFAULTS[provider]
    except KeyError as exc:
        raise ValueError("Unsupported TTS provider") from exc


def selected_voice(provider: str, candidate: str) -> ReviewedVoice:
    """Resolve a persisted selection, failing safely to the reviewed default."""

    try:
        return reviewed_voice(provider, candidate)
    except (TypeError, ValueError):
        return reviewed_voice(provider, default_voice_id(provider))


__all__ = [
    "EDGE_TTS_PROVIDER",
    "ELEVENLABS_TTS_PROVIDER",
    "OPENAI_TTS_PROVIDER",
    "ReviewedVoice",
    "TTS_PROVIDERS",
    "default_voice_id",
    "provider_destination",
    "provider_label",
    "reviewed_voice",
    "reviewed_voices",
    "selected_voice",
]
