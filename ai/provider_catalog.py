"""Reviewed provider identities, endpoints, and user-facing metadata.

Credentials and executable locations are deliberately not stored here. Cloud
secrets remain process-environment inputs owned by :mod:`config`, while
read-only response-provider CLIs must already be installed and discoverable on
PATH.
"""

from __future__ import annotations

from dataclasses import dataclass


MUSE_VIDEO_MODELS = frozenset({
    "meta/muse-spark-1.2-contributor",
    "meta/muse-spark-1.3-contributor",
})


def supports_video(provider: str, model: str | None) -> bool:
    # These identities accept our video request format; this is not an audio
    # comprehension guarantee. See video_model_notices for known limitations.
    # Keep identities dependency-free for model discovery and the stdlib CI job.
    return provider == "openrouter" and model in MUSE_VIDEO_MODELS


def video_model_notices(provider: str, model: str | None) -> tuple[str, ...]:
    """Exact-model disclosures checked against OpenRouter on 2026-09-13."""
    if not supports_video(provider, model):
        return ()
    notices = (
        "This Contributor model may use your prompts and responses to improve "
        "Meta's products.",
    )
    if model == "meta/muse-spark-1.3-contributor":
        notices += (
            "Muse 1.3 audio understanding is currently limited; answers may "
            "miss or misunderstand what you say.",
        )
    return notices


@dataclass(frozen=True, slots=True)
class OpenAICompatibleSpec:
    provider_id: str
    label: str
    base_url: str
    credential_attribute: str


OPENAI_COMPATIBLE_SPECS: dict[str, OpenAICompatibleSpec] = {
    "openrouter": OpenAICompatibleSpec(
        provider_id="openrouter",
        label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        credential_attribute="openrouter_api_key",
    ),
    "kimi_code": OpenAICompatibleSpec(
        provider_id="kimi_code",
        label="Kimi Code",
        base_url="https://api.kimi.com/coding/v1",
        credential_attribute="kimi_code_api_key",
    ),
    "minimax_plan": OpenAICompatibleSpec(
        provider_id="minimax_plan",
        label="MiniMax Token Plan",
        base_url="https://api.minimax.io/v1",
        credential_attribute="minimax_api_key",
    ),
    "deepseek": OpenAICompatibleSpec(
        provider_id="deepseek",
        label="DeepSeek",
        base_url="https://api.deepseek.com",
        credential_attribute="deepseek_api_key",
    ),
    "qwen": OpenAICompatibleSpec(
        provider_id="qwen",
        label="Qwen",
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        credential_attribute="dashscope_api_key",
    ),
}

AGENT_PROVIDER_EXECUTABLES = {
    "codex_agent": "codex",
    "qwen_code_agent": "qwen",
}

PROVIDER_LABELS = {
    "claude": "Claude",
    "openai": "OpenAI",
    "gemini": "Gemini",
    "copilot": "GitHub Copilot",
    "ollama": "Ollama",
    "lmstudio": "LM Studio",
    "codex_agent": "Codex — read-only response provider",
    "qwen_code_agent": "Qwen Code — read-only response provider",
    **{
        provider_id: spec.label
        for provider_id, spec in OPENAI_COMPATIBLE_SPECS.items()
    },
}

REGISTRY_MODEL_PROVIDERS = frozenset({
    "claude",
    "openai",
    "gemini",
    *OPENAI_COMPATIBLE_SPECS,
    *AGENT_PROVIDER_EXECUTABLES,
})
REFRESHABLE_MODEL_PROVIDERS = frozenset({
    "claude",
    "openai",
    "gemini",
    *OPENAI_COMPATIBLE_SPECS,
})
AGENT_PROVIDERS = frozenset(AGENT_PROVIDER_EXECUTABLES)
ALL_PROVIDER_IDS = frozenset({
    "claude",
    "openai",
    "gemini",
    "copilot",
    "ollama",
    "lmstudio",
    *OPENAI_COMPATIBLE_SPECS,
    *AGENT_PROVIDER_EXECUTABLES,
})


def provider_label(provider_id: str) -> str:
    return PROVIDER_LABELS.get(provider_id, provider_id)
