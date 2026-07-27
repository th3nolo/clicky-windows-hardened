"""Focused construction boundary for LLM and coding-agent providers."""

from __future__ import annotations

from ai.base_provider import BaseLLMProvider
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS


def create_llm_provider(provider_id: str) -> BaseLLMProvider:
    if provider_id in OPENAI_COMPATIBLE_SPECS:
        from ai.openai_compatible_provider import OpenAICompatibleProvider

        return OpenAICompatibleProvider(provider_id)
    if provider_id == "claude":
        from ai.claude_provider import ClaudeProvider

        return ClaudeProvider()
    if provider_id == "openai":
        from ai.openai_provider import OpenAIProvider

        return OpenAIProvider()
    if provider_id == "gemini":
        from ai.gemini_provider import GeminiProvider

        return GeminiProvider()
    if provider_id == "copilot":
        from ai.github_copilot_provider import GitHubCopilotProvider

        return GitHubCopilotProvider()
    if provider_id == "lmstudio":
        from ai.lmstudio_provider import LMStudioProvider

        return LMStudioProvider()
    if provider_id in {"codex_agent", "qwen_code_agent"}:
        from ai.agent_cli_provider import AgentCLIProvider

        return AgentCLIProvider(provider_id)
    if provider_id == "ollama":
        from ai import ollama_bootstrap
        from ai.ollama_provider import OllamaProvider

        ollama_bootstrap.require_configured_model_identities()
        return OllamaProvider()
    raise ValueError(f"Unknown LLM provider: {provider_id}")
