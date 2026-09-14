"""Keep OpenAI speech credentials separate from a custom chat router."""

from ai.provider_endpoints import is_custom_openai_endpoint


def openai_speech_api_key(
    *, speech_key: str | None, chat_key: str | None, chat_base_url: str,
) -> str:
    if speech_key:
        return speech_key
    if is_custom_openai_endpoint(chat_base_url):
        raise RuntimeError(
            "OpenAI speech requires OPENAI_SPEECH_API_KEY when chat uses a "
            "custom endpoint. The chat router credential was not sent."
        )
    if not chat_key:
        raise RuntimeError("OpenAI speech requires OPENAI_SPEECH_API_KEY or OPENAI_API_KEY.")
    return chat_key
