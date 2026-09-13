"""Keep OpenAI speech credentials separate from a custom chat router."""


def openai_speech_api_key(
    *, speech_key: str | None, chat_key: str | None, chat_base_url: str,
) -> str:
    if speech_key:
        return speech_key
    if chat_base_url and chat_base_url.rstrip("/") != "https://api.openai.com/v1":
        raise RuntimeError(
            "OpenAI speech requires OPENAI_SPEECH_API_KEY when chat uses a "
            "custom endpoint. The chat router credential was not sent."
        )
    if not chat_key:
        raise RuntimeError("OpenAI speech requires OPENAI_SPEECH_API_KEY or OPENAI_API_KEY.")
    return chat_key
