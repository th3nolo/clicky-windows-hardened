"""Read-only speech-input readiness and destination descriptions."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util

from audio.stt.local_models import (
    LocalModelUnavailable,
    resolve_faster_whisper_model,
    resolve_whisper_cpp_model,
)
from privacy_controls import (
    cloud_stt_allowed,
    microphone_allowed,
)


@dataclass(frozen=True, slots=True)
class STTReadiness:
    provider: str
    label: str
    mode: str
    destination: str
    ready: bool
    detail: str


STT_PROVIDER_DETAILS = {
    "deepgram": (
        "Deepgram Nova-2",
        "live streaming",
        "wss://api.deepgram.com/v1/listen",
    ),
    "deepgram_batch": (
        "Deepgram Nova-2",
        "cloud batch",
        "https://api.deepgram.com/v1/listen",
    ),
    "openai": (
        "OpenAI Whisper",
        "cloud batch",
        "https://api.openai.com/v1/audio/transcriptions",
    ),
    "whisper_cpp": (
        "whisper.cpp",
        "local batch",
        "This Windows device only",
    ),
    "faster_whisper": (
        "faster-whisper",
        "local batch",
        "This Windows device only",
    ),
}
LOCAL_FALLBACK_PROVIDERS = ("whisper_cpp", "faster_whisper")


def provider_label(provider: str) -> str:
    details = STT_PROVIDER_DETAILS.get(provider)
    return details[0] if details is not None else provider


def fallback_label(provider: str) -> str:
    if not provider:
        return "Off — show the selected provider error"
    return f"{provider_label(provider)} — local batch only"


def _cloud_readiness(config, provider: str) -> STTReadiness:
    label, mode, destination = STT_PROVIDER_DETAILS[provider]
    key_present = (
        bool(config.deepgram_api_key)
        if provider.startswith("deepgram")
        else bool(config.openai_api_key)
    )
    if not key_present:
        key_name = (
            "DEEPGRAM_API_KEY"
            if provider.startswith("deepgram")
            else "OPENAI_API_KEY"
        )
        detail = f"Not ready: {key_name} is absent from this process."
        ready = False
    elif not microphone_allowed(config):
        detail = "Not ready: microphone permission is off."
        ready = False
    elif not cloud_stt_allowed(config):
        detail = "Not ready: cloud speech-to-text permission is off."
        ready = False
    else:
        detail = (
            "Configured and consented. No provider request was made by this "
            "readiness check."
        )
        ready = True
    return STTReadiness(
        provider,
        label,
        mode,
        destination,
        ready,
        detail,
    )


def _local_readiness(config, provider: str) -> STTReadiness:
    label, mode, destination = STT_PROVIDER_DETAILS[provider]
    try:
        if provider == "whisper_cpp":
            if importlib.util.find_spec("pywhispercpp") is None:
                raise LocalModelUnavailable(
                    "The reviewed pywhispercpp package is unavailable."
                )
            resolve_whisper_cpp_model(
                config.whisper_model,
                config.whispercpp_model_sha256,
            )
        else:
            if importlib.util.find_spec("faster_whisper") is None:
                raise LocalModelUnavailable(
                    "The reviewed faster-whisper package is unavailable."
                )
            resolve_faster_whisper_model(
                config.whisper_model,
                config.whisper_model_sha256,
            )
    except (LocalModelUnavailable, ImportError, OSError) as exc:
        ready = False
        detail = f"Not ready: {exc}"
    else:
        ready = microphone_allowed(config)
        detail = (
            "Verified local model is ready."
            if ready
            else "Model verified, but microphone permission is off."
        )
    return STTReadiness(
        provider,
        label,
        mode,
        destination,
        ready,
        detail,
    )


def collect_stt_readiness(config) -> tuple[STTReadiness, ...]:
    """Inspect credentials, consent, packages, and local model identity.

    This function never opens a microphone or network connection and never
    downloads, installs, starts, or loads a model.
    """

    results = []
    for provider in STT_PROVIDER_DETAILS:
        if provider in LOCAL_FALLBACK_PROVIDERS:
            results.append(_local_readiness(config, provider))
        else:
            results.append(_cloud_readiness(config, provider))
    return tuple(results)
