"""Reviewed provider identities, endpoints, and user-facing metadata.

Credentials and executable locations are deliberately not stored here. Cloud
secrets remain process-environment inputs owned by :mod:`config`, while
read-only response-provider CLIs must already be installed and discoverable on
PATH.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OpenAICompatibleSpec:
    provider_id: str
    label: str
    base_url: str
    credential_attribute: str


OPENAI_COMPATIBLE_SPECS: dict[str, OpenAICompatibleSpec] = {
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
