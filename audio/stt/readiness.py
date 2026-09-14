"""Read-only speech-input readiness and destination descriptions."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util

from audio.openai_credentials import openai_speech_api_key
from audio.stt.local_models import (
    LocalModelUnavailable,
    resolve_faster_whisper_model,
    resolve_whisper_cpp_model,
    validate_sha256,
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
    "openrouter": (
        "OpenRouter Muse Spark 1.2",
        "cloud batch",
        "https://openrouter.ai/api/v1/chat/completions",
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


def local_stt_setup_issue(config, provider: str) -> str:
    """Check cheap local prerequisites before capture, without hashing a model.

    An empty result only permits capture; the provider must still resolve and
    verify the complete model when loading it. Full readiness stays an explicit
    diagnostic so large model files are not hashed on each hotkey press.
    """
    if provider not in LOCAL_FALLBACK_PROVIDERS:
        return ""
    package, digest_attribute, digest_variable = (
        ("pywhispercpp", "whispercpp_model_sha256", "WHISPERCPP_MODEL_SHA256")
        if provider == "whisper_cpp" else
        ("faster_whisper", "whisper_model_sha256", "WHISPER_MODEL_SHA256")
    )
    try:
        if importlib.util.find_spec(package) is None:
            return f"The {provider_label(provider)} speech package is unavailable."
        validate_sha256(getattr(config, digest_attribute, ""), digest_variable)
    except LocalModelUnavailable as exc:
        return f"{provider_label(provider)} needs a verified local speech model. {exc}"
    except (ImportError, ValueError, OSError):
        return f"The {provider_label(provider)} speech package is unavailable."
    return ""


def _cloud_readiness(config, provider: str) -> STTReadiness:
    label, mode, destination = STT_PROVIDER_DETAILS[provider]
    key_error = "DEEPGRAM_API_KEY is absent from this process."
    if provider.startswith("deepgram"):
        key_present = bool(config.deepgram_api_key)
    elif provider == "openrouter":
        key_present = bool(getattr(config, "openrouter_api_key", None))
        key_error = "OPENROUTER_API_KEY is absent from this process."
    else:
        try:
            openai_speech_api_key(
                speech_key=getattr(config, "openai_speech_api_key", None),
                chat_key=config.openai_api_key,
                chat_base_url=getattr(config, "openai_base_url", ""),
            )
            key_present = True
        except RuntimeError as exc:
            key_present = False
            key_error = str(exc)
    if not key_present:
        detail = f"Not ready: {key_error}"
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
    if provider == "openrouter":
        detail += (
            " Model: meta/muse-spark-1.2-contributor. Audio is sent to OpenRouter "
            "and its selected model provider; the contributor model may use "
            "inputs for training. Private routing remains enforced when enabled "
            "and can make this model unavailable. The configured policy is not "
            "relaxed automatically."
        )
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
